from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import time
from collections import defaultdict
from datetime import datetime, timedelta
import random
import os
import urllib.parse
import jwt
import hashlib
import base64
from functools import wraps
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ==================== CONFIGURATION ====================
CONFIG = {
    'DAILY_LIMIT': 100,
    'MAX_CONCURRENT': 30,
    'ACCOUNT_BATCH_SIZE': 100,
    'TOKEN_REFRESH_HOURS': 23,
    'REQUEST_TIMEOUT': 8,
    'RETRY_ATTEMPTS': 3,
    'USER_AGENT': "Dalvik/2.1.0 (Linux; U; Android 11; SM-G998B Build/RP1A.200720.012)",
    'RELEASE_VERSION': "OB55"
}

# ==================== CACHE MANAGER ====================
class CacheManager:
    """Advanced caching system with TTL and automatic cleanup"""
    
    def __init__(self, cleanup_interval=300):
        self._data = {}
        self._ttl = {}
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()
    
    def set(self, key, value, ttl_seconds=3600):
        """Store data with TTL"""
        self._data[key] = value
        self._ttl[key] = time.time() + ttl_seconds
        self._auto_cleanup()
    
    def get(self, key):
        """Retrieve data if not expired"""
        if key in self._data:
            if time.time() < self._ttl.get(key, 0):
                return self._data[key]
            else:
                self._delete(key)
        return None
    
    def _delete(self, key):
        """Delete a specific key"""
        if key in self._data:
            del self._data[key]
        if key in self._ttl:
            del self._ttl[key]
    
    def _auto_cleanup(self):
        """Automatic cleanup of expired items"""
        current_time = time.time()
        if current_time - self._last_cleanup >= self._cleanup_interval:
            expired_keys = [k for k, v in self._ttl.items() if current_time >= v]
            for key in expired_keys:
                self._delete(key)
            self._last_cleanup = current_time
    
    def clear(self):
        """Clear all cached data"""
        self._data.clear()
        self._ttl.clear()
        logger.info("🗑️ Cache cleared successfully")

# ==================== INITIALIZE CACHES ====================
token_cache = CacheManager()
liked_tracker = CacheManager(ttl_seconds=86400)  # 24 hours
rate_limiter = defaultdict(lambda: {'count': 0, 'reset_time': time.time()})

# ==================== VALIDATION & ENCRYPTION ====================
VALID_SERVERS = ["IND", "BR", "US", "SAC", "NA", "BD", "RU"]
SECRET_KEY = b'Yg&tc%DEuh6%Zc^8'
INIT_VECTOR = b'6oyZDr22E3ychjM%'

def encrypt_data(plaintext):
    """Encrypt data using AES-CBC"""
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, INIT_VECTOR)
    padded = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded)).decode('utf-8')

def decrypt_data(ciphertext):
    """Decrypt data using AES-CBC"""
    try:
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, INIT_VECTOR)
        decrypted = cipher.decrypt(bytes.fromhex(ciphertext))
        return decrypted
    except:
        return None

# ==================== ACCOUNT MANAGEMENT ====================
def load_accounts(server_name):
    """
    Load accounts from server-specific file with enhanced error handling
    and automatic fallback mechanism
    """
    server_map = {
        "IND": "accounts_ind.txt",
        "BR": "accounts_br.txt",
        "US": "accounts_br.txt",
        "SAC": "accounts_br.txt",
        "NA": "accounts_br.txt",
        "BD": "accounts_bd.txt",
        "RU": "accounts_bd.txt"
    }
    
    filename = server_map.get(server_name, "accounts_bd.txt")
    
    # Try multiple fallback files
    fallback_files = [filename, "accounts_ind.txt", "accounts_bd.txt"]
    accounts = []
    
    for file_path in fallback_files:
        if not os.path.exists(file_path):
            continue
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Support multiple formats: uid:pass or uid:pass:extra
                    parts = line.split(':', 1)
                    if len(parts) >= 2:
                        uid = parts[0].strip()
                        password = parts[1].strip()
                        if uid and password:
                            accounts.append({
                                'uid': uid,
                                'password': password,
                                'server': server_name,
                                'status': 'active',
                                'last_used': 0
                            })
            
            if accounts:
                logger.info(f"✅ Loaded {len(accounts)} accounts from {file_path} for {server_name}")
                break
                
        except Exception as e:
            logger.error(f"❌ Error loading {file_path}: {str(e)}")
            continue
    
    return accounts

# ==================== TOKEN MANAGEMENT ====================
async def generate_jwt_token(uid, password):
    """Generate JWT token with retry mechanism"""
    for attempt in range(CONFIG['RETRY_ATTEMPTS']):
        try:
            encoded_password = urllib.parse.quote(password)
            url = f"https://ff-jwt-gen-api.lovable.app/api/public/token?uid={uid}&password={encoded_password}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=CONFIG['REQUEST_TIMEOUT']) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if isinstance(data, dict):
                            token = data.get('jwt_token') or data.get('token')
                            if token:
                                return token
            await asyncio.sleep(0.5 * (attempt + 1))
        except Exception as e:
            logger.warning(f"Token generation attempt {attempt+1} failed for {uid}: {str(e)}")
            continue
    
    return None

async def get_valid_token(uid, password):
    """Get valid token from cache or generate new one"""
    # Check cache
    cached_token = token_cache.get(uid)
    if cached_token:
        try:
            # Verify token expiration
            payload = jwt.decode(cached_token, options={"verify_signature": False})
            exp = payload.get('exp', 0)
            if exp > time.time() + 1800:  # More than 30 minutes remaining
                return cached_token
        except:
            pass
    
    # Generate new token
    token = await generate_jwt_token(uid, password)
    if token:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp = payload.get('exp', time.time() + 86400)
            token_cache.set(uid, token, ttl_seconds=exp - time.time())
        except:
            token_cache.set(uid, token, ttl_seconds=86400)
        
        return token
    
    return None

# ==================== PROTOBUF HELPERS ====================
def create_like_packet(user_id, region):
    """Create like protobuf message"""
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

def create_uid_packet(user_id):
    """Create UID protobuf message"""
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(user_id)
    message.teamXdarks = 1
    return message.SerializeToString()

def decode_player_info(binary_data):
    """Decode player info from binary data"""
    try:
        info = like_count_pb2.Info()
        info.ParseFromString(binary_data)
        return info
    except:
        return None

# ==================== NETWORK REQUESTS ====================
async def send_like_request(encrypted_uid, token, url):
    """Send like request with retry logic"""
    for attempt in range(CONFIG['RETRY_ATTEMPTS']):
        try:
            edata = bytes.fromhex(encrypted_uid)
            headers = {
                'User-Agent': CONFIG['USER_AGENT'],
                'Authorization': f"Bearer {token}",
                'Content-Type': "application/x-www-form-urlencoded",
                'X-GA': "v1 1",
                'ReleaseVersion': CONFIG['RELEASE_VERSION']
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=edata, headers=headers, timeout=CONFIG['REQUEST_TIMEOUT']) as response:
                    if response.status == 200:
                        return 200
                    elif response.status == 429:  # Rate limited
                        await asyncio.sleep(2)
                        continue
                    else:
                        return response.status
        except asyncio.TimeoutError:
            if attempt < CONFIG['RETRY_ATTEMPTS'] - 1:
                await asyncio.sleep(1)
                continue
            return 408
        except:
            if attempt < CONFIG['RETRY_ATTEMPTS'] - 1:
                await asyncio.sleep(1)
                continue
            return 500
    
    return 500

def get_player_info(encrypted_uid, server_name, token):
    """Get player information from server"""
    server_urls = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "BD": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "RU": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
    }
    
    url = server_urls.get(server_name, server_urls["BD"])
    edata = bytes.fromhex(encrypted_uid)
    
    headers = {
        'User-Agent': CONFIG['USER_AGENT'],
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-GA': "v1 1",
        'ReleaseVersion': CONFIG['RELEASE_VERSION']
    }
    
    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=CONFIG['REQUEST_TIMEOUT'])
        if response.status_code == 200:
            return decode_player_info(response.content)
        return None
    except:
        return None

# ==================== LIKE PROCESSING ====================
async def process_account_like(target_uid, encrypted_uid, account, url, semaphore):
    """Process a single account's like request"""
    async with semaphore:
        liked_key = f"{target_uid}:{account['uid']}"
        
        # Check if already liked
        if liked_tracker.get(liked_key):
            return {'status': 304, 'uid': account['uid']}  # Already liked
        
        # Get valid token
        token = await get_valid_token(account['uid'], account['password'])
        if not token:
            return {'status': 401, 'uid': account['uid']}  # Auth failed
        
        # Send like
        status = await send_like_request(encrypted_uid, token, url)
        
        # Update tracker if successful
        if status == 200:
            liked_tracker.set(liked_key, True, ttl_seconds=86400)
            account['last_used'] = time.time()
        
        return {'status': status, 'uid': account['uid']}

async def batch_process_likes(target_uid, server_name, like_url):
    """Process likes in batches with smart account selection"""
    accounts = load_accounts(server_name)
    if not accounts:
        logger.error(f"No accounts found for {server_name}")
        return {'success': 0, 'failed': 0, 'skipped': 0, 'total': 0}
    
    # Filter accounts that haven't liked this UID
    eligible_accounts = []
    for acc in accounts:
        liked_key = f"{target_uid}:{acc['uid']}"
        if not liked_tracker.get(liked_key):
            eligible_accounts.append(acc)
    
    logger.info(f"📊 Total accounts: {len(accounts)}, Eligible: {len(eligible_accounts)}")
    
    if not eligible_accounts:
        return {
            'success': 0,
            'failed': 0,
            'skipped': len(accounts),
            'total': len(accounts)
        }
    
    # Shuffle for better distribution
    random.shuffle(eligible_accounts)
    
    # Process in batches
    batch_size = CONFIG['ACCOUNT_BATCH_SIZE']
    semaphore = asyncio.Semaphore(CONFIG['MAX_CONCURRENT'])
    
    results = []
    for i in range(0, min(len(eligible_accounts), 2000), batch_size):
        batch = eligible_accounts[i:i+batch_size]
        tasks = [
            process_account_like(target_uid, encrypted_uid, acc, like_url, semaphore)
            for acc in batch
        ]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if isinstance(result, Exception):
                results.append({'status': 500, 'uid': 'unknown'})
            else:
                results.append(result)
        
        # Avoid rate limiting
        await asyncio.sleep(0.5)
    
    # Count results
    successful = sum(1 for r in results if r['status'] == 200)
    failed = sum(1 for r in results if r['status'] not in [200, 304])
    skipped = sum(1 for r in results if r['status'] == 304)
    
    return {
        'success': successful,
        'failed': failed,
        'skipped': skipped,
        'total': len(accounts)
    }

# ==================== RATE LIMITING ====================
def check_rate_limit(client_ip):
    """Check and update rate limit for client"""
    current_time = time.time()
    daily_reset = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    
    if client_ip not in rate_limiter:
        rate_limiter[client_ip] = {'count': 0, 'reset_time': daily_reset}
    
    user_data = rate_limiter[client_ip]
    
    # Reset if new day
    if current_time > user_data['reset_time']:
        user_data['count'] = 0
        user_data['reset_time'] = daily_reset + 86400
    
    if user_data['count'] >= CONFIG['DAILY_LIMIT']:
        return False, CONFIG['DAILY_LIMIT'] - user_data['count']
    
    user_data['count'] += 1
    return True, CONFIG['DAILY_LIMIT'] - user_data['count']

# ==================== FLASK ENDPOINTS ====================
def require_auth(f):
    """Decorator for API key authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.args.get('key')
        if key != "ZIBON":
            return jsonify({
                'error': 'Invalid or missing API key',
                'status': 403
            }), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/api/like', methods=['GET'])
@require_auth
def handle_like_request():
    """Main endpoint for sending likes"""
    try:
        # Get parameters
        uid = request.args.get('uid')
        server_name = request.args.get('server_name', '').upper()
        client_ip = request.remote_addr
        
        # Validate parameters
        if not uid or not server_name:
            return jsonify({
                'error': 'UID and server_name are required',
                'status': 400
            }), 400
        
        if server_name not in VALID_SERVERS:
            return jsonify({
                'error': f'Invalid server. Use: {", ".join(VALID_SERVERS)}',
                'status': 400
            }), 400
        
        # Rate limiting
        is_allowed, remaining = check_rate_limit(client_ip)
        if not is_allowed:
            return jsonify({
                'error': 'Daily limit reached',
                'status': 429,
                'remaining': f'({remaining}/{CONFIG["DAILY_LIMIT"]})'
            }), 429
        
        # Get token for verification
        accounts = load_accounts(server_name)
        if not accounts:
            return jsonify({
                'error': 'No accounts available for this server',
                'status': 500
            }), 500
        
        # Try to get valid token
        auth_token = None
        for account in accounts[:10]:
            auth_token = asyncio.run(get_valid_token(account['uid'], account['password']))
            if auth_token:
                break
        
        if not auth_token:
            return jsonify({
                'error': 'Authentication failed - no valid tokens',
                'status': 500
            }), 500
        
        # Get player info before likes
        encrypted_uid = encrypt_data(create_uid_packet(uid))
        before_info = get_player_info(encrypted_uid, server_name, auth_token)
        
        if not before_info:
            return jsonify({
                'error': 'Invalid UID or server',
                'status': 404
            }), 200
        
        try:
            before_data = json.loads(MessageToJson(before_info))
            before_likes = int(before_data.get('AccountInfo', {}).get('Likes', 0))
            player_name = before_data.get('AccountInfo', {}).get('PlayerNickname', 'Unknown')
        except:
            before_likes = 0
            player_name = 'Unknown'
        
        # Determine like URL
        like_urls = {
            "IND": "https://client.ind.freefiremobile.com/LikeProfile",
            "BR": "https://client.us.freefiremobile.com/LikeProfile",
            "US": "https://client.us.freefiremobile.com/LikeProfile",
            "SAC": "https://client.us.freefiremobile.com/LikeProfile",
            "NA": "https://client.us.freefiremobile.com/LikeProfile",
            "BD": "https://clientbp.ggpolarbear.com/LikeProfile",
            "RU": "https://clientbp.ggpolarbear.com/LikeProfile"
        }
        like_url = like_urls.get(server_name, like_urls["BD"])
        
        # Process likes
        like_packet = create_like_packet(uid, server_name)
        encrypted_packet = encrypt_data(like_packet)
        
        result = asyncio.run(batch_process_likes(uid, server_name, like_url))
        
        # Get player info after likes
        after_info = get_player_info(encrypted_uid, server_name, auth_token)
        after_likes = before_likes
        
        if after_info:
            try:
                after_data = json.loads(MessageToJson(after_info))
                after_likes = int(after_data.get('AccountInfo', {}).get('Likes', before_likes))
            except:
                pass
        
        likes_given = after_likes - before_likes
        
        return jsonify({
            'status': 1 if likes_given > 0 else 2,
            'uid': uid,
            'player_name': player_name,
            'likes_before': before_likes,
            'likes_after': after_likes,
            'likes_added': likes_given,
            'accounts_used': result['success'],
            'accounts_failed': result['failed'],
            'accounts_skipped': result['skipped'],
            'total_accounts': result['total'],
            'remaining': f'({remaining}/{CONFIG["DAILY_LIMIT"]})',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in like request: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 500
        }), 500

@app.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    """Get statistics about the system"""
    total_accounts = 0
    server_stats = {}
    
    for server in VALID_SERVERS:
        accounts = load_accounts(server)
        server_stats[server] = len(accounts)
        total_accounts += len(accounts)
    
    return jsonify({
        'total_accounts': total_accounts,
        'servers': server_stats,
        'cache_size': len(token_cache._data),
        'liked_tracked': len(liked_tracker._data),
        'rate_limit': CONFIG['DAILY_LIMIT'],
        'active_ips': len(rate_limiter)
    })

@app.route('/api/clear-cache', methods=['POST'])
def clear_cache():
    """Clear all caches (requires admin key)"""
    admin_key = request.args.get('admin_key')
    if admin_key != "ADMIN_2024":
        return jsonify({'error': 'Unauthorized'}), 403
    
    token_cache.clear()
    liked_tracker.clear()
    logger.info("🧹 All caches cleared by admin")
    
    return jsonify({
        'message': 'All caches cleared successfully',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

# ==================== ERROR HANDLING ====================
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found', 'status': 404}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error', 'status': 500}), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║         🚀 FREE FIRE LIKE BOT - ADVANCED v2.0          ║
    ╚══════════════════════════════════════════════════════════╝
    
    📁 Account Files Required:
       • accounts_ind.txt  - India Server
       • accounts_br.txt   - Brazil/US/SAC/NA Servers
       • accounts_bd.txt   - Bangladesh/RU Servers
    
    📊 Features:
       ✅ Smart token caching
       ✅ Rate limiting per IP
       ✅ Automatic account rotation
       ✅ Duplicate like prevention
       ✅ Batch processing
       ✅ Retry mechanism
       ✅ Detailed logging
    
    🌐 Endpoints:
       GET  /api/like?uid=xxx&server_name=xxx&key=ZIBON
       GET  /api/stats?key=ZIBON
       POST /api/clear-cache?admin_key=ADMIN_2024
       GET  /api/health
    
    ⚙️  Configuration:
       Daily Limit: {CONFIG['DAILY_LIMIT']}
       Max Concurrent: {CONFIG['MAX_CONCURRENT']}
       Batch Size: {CONFIG['ACCOUNT_BATCH_SIZE']}
    
    🚀 Server Starting...
    """)
    
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=False,
        use_reloader=False,
        threaded=True
    )
