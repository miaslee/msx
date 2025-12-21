
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
import lib2
import json
import asyncio
from datetime import datetime, timedelta
import pytz
import os
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
CORS(app)

cache = TTLCache(maxsize=100000, ttl=3600)
max_workers = min(10000, (os.cpu_count() or 1) * 1000)
executor = ThreadPoolExecutor(max_workers=max_workers)

def cached_endpoint(ttl=3600):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = (request.path, tuple(request.args.items()))
            if cache_key in cache:
                return cache[cache_key]
            result = func(*args, **kwargs)
            cache[cache_key] = result
            return result
        return wrapper
    return decorator

def convert_timestamps(data, timestamp_keys):
    """Convert timestamp values to readable format, handling both string keys and numeric keys."""
    if isinstance(data, dict):
        for key, value in data.items():
            # Check if this key should be converted (works for both string and numeric keys)
            key_str = str(key)
            if key_str in timestamp_keys or any(ts_key in key_str for ts_key in timestamp_keys):
                if isinstance(value, (int, str)):
                    try:
                        timestamp = int(value)
                        if timestamp > 0:  # Valid timestamp
                            data[key] = datetime.fromtimestamp(timestamp, pytz.UTC).strftime('%Y-%m-%d %H:%M:%S')
                    except (ValueError, OSError):
                        pass
                elif isinstance(value, dict):
                    # Recursively check nested structures
                    convert_timestamps(value, timestamp_keys)
            else:
                convert_timestamps(value, timestamp_keys)
    elif isinstance(data, list):
        for item in data:
            convert_timestamps(item, timestamp_keys)

async def fetch_all_data(uid, region):
    # Get personal show data (main account info)
    # This endpoint returns comprehensive account information including:
    # - Basic info (level, rank, exp, nickname, etc.)
    # - Profile info (avatar, clothes, skills)
    # - Social info (battle tags, preferences, signature)
    # - Pet info
    # - Clan info
    # - Credit score
    # - Diamond cost
    # - News and history
    personal_show = await lib2.GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
    return {"account_data": personal_show}

def sync_fetch_all_data(uid, region):
    return asyncio.run(fetch_all_data(uid, region))

@app.route('/cloud/accountinfo')
@cached_endpoint()
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')

    if not uid or not region:
        return jsonify({
            "error": "Invalid request",
            "message": "Missing required parameters"
        }), 400

    future = executor.submit(sync_fetch_all_data, uid, region)
    all_data = future.result()

    # Convert timestamps - include common timestamp field names
    timestamp_keys = [
        "lastLoginAt", "createAt", "periodicSummaryEndTime", "periodicSummaryStartTime",
        "last_login_at", "create_at", "update_time", "expire_time", "reward_time",
        "end_time", "unlock_time", "24", "44"  # Also check numeric keys that might be timestamps
    ]
    convert_timestamps(all_data, timestamp_keys)

    return jsonify(all_data), 200

if __name__ == '__main__':
    app.run(port=3000, host='0.0.0.0', debug=True)
