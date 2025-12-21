from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
import lib2
import asyncio
from datetime import datetime
import pytz
import os
from concurrent.futures import ThreadPoolExecutor

# ---------------- APP ----------------
app = Flask(__name__)

# CORS (para pruebas): permite fetch desde cualquier origen.
# Si quieres restringirlo luego, cambia origins="*" por tu dominio, ej: ["https://viewff.com"]
CORS(app, resources={r"/cloud/*": {"origins": "*"}})

# ---------------- CACHE / EXECUTOR ----------------
cache = TTLCache(maxsize=100000, ttl=3600)
max_workers = min(10000, (os.cpu_count() or 1) * 1000)
executor = ThreadPoolExecutor(max_workers=max_workers)

# ---------------- CACHE DECORATOR ----------------
def cached_endpoint(ttl=3600):
    """
    Cachea SOLO datos (dict) y NO cachea objetos Response.
    Esto evita que se pierdan headers (como CORS) cuando respondes desde cache.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Preflight CORS
            if request.method == "OPTIONS":
                return ("", 204)

            # Key estable
            cache_key = (request.path, tuple(sorted(request.args.items())))

            # Si está en cache, devolver JSON nuevo (con headers CORS)
            if cache_key in cache:
                return jsonify(cache[cache_key]), 200

            # Ejecutar función real: debe devolver (dict, status)
            data, status = func(*args, **kwargs)

            # Guardar en cache solo si fue OK
            if status == 200:
                cache[cache_key] = data

            return jsonify(data), status

        return wrapper
    return decorator

# ---------------- TIMESTAMP CONVERSION ----------------
def convert_timestamps(data, timestamp_keys):
    """Convierte timestamps a formato legible en UTC, soportando dict/list recursivo."""
    if isinstance(data, dict):
        for key, value in data.items():
            key_str = str(key)

            should_convert = (key_str in timestamp_keys) or any(ts_key in key_str for ts_key in timestamp_keys)

            if should_convert:
                if isinstance(value, (int, str)):
                    try:
                        ts = int(value)
                        if ts > 0:
                            data[key] = datetime.fromtimestamp(ts, pytz.UTC).strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, OSError):
                        pass
                elif isinstance(value, dict) or isinstance(value, list):
                    convert_timestamps(value, timestamp_keys)
            else:
                convert_timestamps(value, timestamp_keys)

    elif isinstance(data, list):
        for item in data:
            convert_timestamps(item, timestamp_keys)

# ---------------- ASYNC FETCH ----------------
async def fetch_all_data(uid, region):
    personal_show = await lib2.GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
    return {"account_data": personal_show}

def sync_fetch_all_data(uid, region):
    return asyncio.run(fetch_all_data(uid, region))

# ---------------- ROUTE ----------------
@app.route("/cloud/accountinfo", methods=["GET", "OPTIONS"])
@cached_endpoint()
def get_account_info():
    # Preflight CORS (por si acaso; el decorator ya lo cubre)
    if request.method == "OPTIONS":
        return ("", 204)

    region = (request.args.get("region") or "").strip()
    uid = (request.args.get("uid") or "").strip()

    if not uid or not region:
        return {
            "error": "Invalid request",
            "message": "Missing required parameters"
        }, 400

    # Validación uid: solo números 4-15
    import re
    if not re.fullmatch(r"\d{4,15}", uid):
        return {
            "error": "Invalid request",
            "message": "uid must be numeric (4-15 digits)"
        }, 400

    # (Opcional) Validación region: por ahora solo SAC
    if region != "SAC":
        return {
            "error": "Invalid request",
            "message": "Invalid region"
        }, 400

    future = executor.submit(sync_fetch_all_data, uid, region)
    all_data = future.result()

    timestamp_keys = [
        "lastLoginAt", "createAt", "periodicSummaryEndTime", "periodicSummaryStartTime",
        "last_login_at", "create_at", "update_time", "expire_time", "reward_time",
        "end_time", "unlock_time", "24", "44"
    ]
    convert_timestamps(all_data, timestamp_keys)

    return all_data, 200

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(port=80, host="0.0.0.0", debug=True)
