import json
import time
from pathlib import Path

CACHE_PATH = Path(__file__).resolve().parent / "cve_cache.json"
DEFAULT_TTL_SECONDS = 7 * 24 * 3600


def load_cache():
    if not CACHE_PATH.exists():
        return {}
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_cache(cache):
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(
        json.dumps(cache, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def get_cache(key, ttl_seconds=DEFAULT_TTL_SECONDS):
    cache = load_cache()
    item = cache.get(key)
    if not item:
        return None

    cached_at = item.get("cached_at", 0)
    if time.time() - cached_at > ttl_seconds:
        return None

    return item.get("data")


def set_cache(key, data):
    cache = load_cache()
    cache[key] = {
        "cached_at": time.time(),
        "data": data
    }
    save_cache(cache)
