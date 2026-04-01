import json
import os
import time
import requests
from datetime import datetime
from config import MAX_RETRIES, TENABLE_HEADERS, TENABLE_BASE


def log(msg: str) -> None:
    print(f"{datetime.now().isoformat()} | {msg}", flush=True)


# ── HTTP wrapper (Tenable) ────────────────────────────────────────────────────

def tenable_request(method: str, endpoint: str, **kwargs) -> dict:
    """Retry with back-off. Handles 429. Returns parsed JSON."""
    url = f"{TENABLE_BASE}{endpoint}"
    last_exc = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.request(
                method, url,
                headers=TENABLE_HEADERS,
                timeout=120,
                **kwargs
            )
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 30))
                log(f"Rate-limited — waiting {wait}s")
                time.sleep(wait)
                continue
            if not r.ok:
                log(f"API error {r.status_code} {method} {endpoint}: {r.text[:300]}")
            r.raise_for_status()
            return r.json() if r.content else {}
        except Exception as e:
            last_exc = e
            wait = 10 * attempt
            log(f"Request error (attempt {attempt}/{MAX_RETRIES}): {e} — retry in {wait}s")
            time.sleep(wait)

    raise RuntimeError(f"Tenable API failed after {MAX_RETRIES} attempts: {last_exc}")


# ── File helpers ──────────────────────────────────────────────────────────────

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def save_json(path: str, data) -> None:
    ensure_dir(os.path.dirname(path))
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)
