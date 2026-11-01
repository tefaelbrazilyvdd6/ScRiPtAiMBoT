#!/usr/bin/env python3
# api.py — PlatoRelay solver + LootLabs solver, Flask REST API for Render

import time, json, base64, urllib.parse
import requests
import urllib3
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from Crypto.Cipher import AES

# ── stdlib extras needed by LootLabs solver ───────────────────────────────────
import threading
import hashlib
import uuid
import ast
import re
import traceback
import random
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOLVE_TOKEN      = os.environ.get("SOLVE_TOKEN", "changeme-set-this-in-render")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "0x4AAAAAAFuUDflleweTZ8jRZuCffo7siyk")

AUTH_API = "https://auth.platorelay.com/api"
SERVICE  = 3
VERSION  = "8.1.2"
UA       = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 "
    "Mobile/15E148 Safari/604.1"
)
SCREEN         = "390x844"
MIN_TICKET_LEN = 33
MIN_STEP_GAP   = 5.0
STEP_THROTTLE_SLEEP = 2.0

app = Flask(__name__)
CORS(app)


# ─── crypto ────────────────────────────────────────────────────────────────────

def aes_ctr(plain: str, key_bytes, iv_bytes) -> bytes:
    key  = bytearray(key_bytes)
    iv   = bytearray(iv_bytes)
    data = plain.encode()
    out  = bytearray()
    for i in range(0, len(data), 16):
        blk  = AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(iv))
        out += bytes(a ^ b for a, b in zip(data[i : i + 16], blk))
        j = 15
        while True:
            iv[j] = (iv[j] + 1) & 0xFF
            if iv[j] != 0:
                break
            j -= 1
            if j < 0:
                break
    return bytes(out)


def build_meta_stream(ticket: str, now_ms: int = None):
    if len(ticket) < MIN_TICKET_LEN:
        return None, None
    if now_ms is None:
        now_ms = int(time.time() * 1000)

    key_meta,   ctr_meta   = ticket[:16],  ticket[16:32]
    key_stream, ctr_stream = ticket[1:17], ticket[17:33]

    meta_plain = json.dumps(
        {"browserInfo": [{"screen": SCREEN, "ua": UA, "time": now_ms}]},
        separators=(",", ":"),
    )
    stream_plain = json.dumps(
        {"events": [{"event": 1, "data": {"time": now_ms}}]},
        separators=(",", ":"),
    )

    meta   = aes_ctr(meta_plain,   [ord(c) for c in key_meta],   [ord(c) for c in ctr_meta]).hex()
    stream = aes_ctr(stream_plain, [ord(c) for c in key_stream], [ord(c) for c in ctr_stream]).hex()
    return meta, stream


# ─── helpers ───────────────────────────────────────────────────────────────────

def extract_ticket(arg: str) -> str:
    t = arg.strip()
    if t.startswith("http"):
        parsed = urllib.parse.urlparse(t)
        qs = urllib.parse.parse_qs(parsed.query)
        if "d" in qs:
            return qs["d"][0]
    return t


def decode_callback_url(loot_url: str):
    qs     = urllib.parse.parse_qs(urllib.parse.urlparse(loot_url).query)
    r_param = qs.get("r", [""])[0]
    if not r_param:
        return None
    b64     = r_param.replace("-", "+").replace("_", "/")
    padding = (4 - len(b64) % 4) % 4
    try:
        dec = base64.b64decode(b64 + "=" * padding).decode("utf-8")
        if dec.startswith("http"):
            return dec
    except Exception:
        pass
    return None


def extract_ticket_from_callback(cb: str):
    if not cb:
        return None
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(cb).query)
    return qs.get("d", [None])[0]


# ─── core logic ────────────────────────────────────────────────────────────────

_OAUTH_PATTERNS = [
    "accounts.google.com",
    "google.com/o/oauth",
    "discord.com/oauth2",
    "discord.gg/oauth",
    "/oauth",          # generic PlatoRelay oauth gate
]

def _is_oauth_url(url: str) -> bool:
    if not url:
        return False
    low = url.lower()
    return any(p in low for p in _OAUTH_PATTERNS)


def do_step(ticket: str) -> dict:
    meta, stream = build_meta_stream(ticket)
    if meta is None:
        return {"success": False, "error": "ticket too short"}
    url  = (
        f"{AUTH_API}/session/step"
        f"?ticket={urllib.parse.quote(ticket)}&service={SERVICE}"
    )
    body = json.dumps(
        {"captcha": None, "meta": meta, "stream": stream, "resolved": True}
    ).encode()
    r = requests.put(
        url,
        data=body,
        headers={
            "User-Agent":       UA,
            "Content-Type":     "application/json",
            "Accept":           "application/json, text/plain, */*",
            "x-client-name":    "platoboost webclient",
            "x-client-version": VERSION,
        },
        timeout=15,
        verify=False,
    )
    try:
        return r.json()
    except Exception:
        return {"success": False, "raw": r.text[:200]}


def poll_key(ticket: str, tries: int = 10):
    for _ in range(tries):
        url = (
            f"{AUTH_API}/session/status"
            f"?ticket={urllib.parse.quote(ticket)}&service={SERVICE}"
        )
        try:
            r = requests.get(
                url,
                headers={
                    "User-Agent":       UA,
                    "Accept":           "application/json",
                    "x-client-name":    "platoboost webclient",
                    "x-client-version": VERSION,
                },
                timeout=10,
                verify=False,
            )
            d = r.json()
            k = (d.get("data") or {}).get("key", "")
            if k and k != "KEY_NOT_FOUND":
                return k
        except Exception:
            pass
        time.sleep(0.5)
    return None


def solve(raw_link: str):
    ticket = extract_ticket(raw_link)
    if len(ticket) < MIN_TICKET_LEN:
        return None, "ticket too short"

    seen   = set()
    gap_ts = 0.0

    for rnd in range(12):
        if ticket in seen:
            return None, "ticket already used"
        seen.add(ticket)

        if gap_ts:
            elapsed = time.time() - gap_ts
            if elapsed < MIN_STEP_GAP:
                time.sleep(MIN_STEP_GAP - elapsed)

        r      = do_step(ticket)
        gap_ts = time.time()

        if not isinstance(r, dict) or not r.get("success"):
            msg = str(r.get("message") or r.get("error") or "").lower()
            if "too fast" in msg or "slow down" in msg:
                time.sleep(STEP_THROTTLE_SLEEP)
                seen.discard(ticket)
                continue
            time.sleep(1.5)
            continue

        data = r.get("data") or {}
        k    = data.get("key")
        if k and k != "KEY_NOT_FOUND":
            return k, None

        url = data.get("url", "")

        # OAuth gate (Google / Discord account verification required)
        if _is_oauth_url(url):
            return None, "oauth:" + url

        if url == "about:blank" or not url:
            k = poll_key(ticket)
            return (k, None) if k else (None, "polling failed")

        cb = decode_callback_url(url)
        nt = extract_ticket_from_callback(cb) if cb else None

        if nt and len(nt) > 50:
            ticket = nt
        else:
            k = poll_key(ticket)
            return (k, None) if k else (None, "callback decode failed")

    return None, "max rounds reached"


# ─── routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return render_template("index.html", solve_token=SOLVE_TOKEN)


def verify_turnstile(token: str) -> bool:
    try:
        r = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": TURNSTILE_SECRET, "response": token},
            timeout=8,
        )
        return r.json().get("success", False)
    except Exception:
        return False


@app.post("/solve")
def route_solve():
    token = request.headers.get("X-Token", "")
    if token != SOLVE_TOKEN:
        return jsonify({"success": False, "error": "forbidden"}), 403

    body = request.get_json(silent=True) or {}

    captcha_token = body.get("captcha", "")
    if not captcha_token or not verify_turnstile(captcha_token):
        return jsonify({"success": False, "error": "captcha required"}), 403

    link = body.get("link", "").strip()
    if not link:
        link = request.args.get("link", "").strip()
    if not link:
        return jsonify({"success": False, "error": "param 'link' is required"}), 400

    key, err = solve(link)
    if key:
        return jsonify({"success": True, "key": key}), 200

    # OAuth gate — return structured response so frontend can show instructions
    if err and err.startswith("oauth:"):
        oauth_url = err[6:]
        return jsonify({
            "success":   False,
            "oauth":     True,
            "oauth_url": oauth_url,
            "error":     "Account verification required",
        }), 200

    messages = {
        "ticket too short":    "Invalid link — make sure you copied the full URL from the Delta checkpoint page.",
        "ticket already used": "This link has already been used or PlatoRelay is looping it. Go back to Delta and get a fresh checkpoint link.",
        "polling failed":      "Key could not be retrieved. The link may have expired — get a new one from Delta.",
        "callback decode failed": "Checkpoint step failed. Try again with a fresh link from Delta.",
        "max rounds reached":  "Solver timed out after 12 rounds. PlatoRelay may be slow — try again in a few seconds.",
    }
    friendly = messages.get(err, "Something went wrong. Grab a fresh link from Delta and try again.")
    return jsonify({"success": False, "error": friendly}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# ─── LootLabs solver (shadows.py by ajyats, integrated) ───────────────────────
# ═══════════════════════════════════════════════════════════════════════════════
#
# Extra packages needed in requirements.txt:
#   websocket-client
#   beautifulsoup4
#   cryptography
#   brotli          (optional, for brotli-compressed responses)
#
# ═══════════════════════════════════════════════════════════════════════════════

LL_AVAILABLE = False

try:
    from bs4 import BeautifulSoup as _BS4
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    import websocket as _websocket
    import zlib as _zlib
    try:
        import brotli as _brotli
    except ImportError:
        _brotli = None
    LL_AVAILABLE = True
except ImportError as _e:
    print(f"[LootLabs] Optional deps missing, /solve-lootlabs will be unavailable: {_e}")


def _ll_log(level, msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {level}: {msg}")


def _ll_decode_resp(response):
    """Decompress/decode an HTTP response body."""
    content  = response.content
    encoding = response.headers.get("content-encoding", "").lower()
    if "br" in encoding and _brotli is not None:
        content = _brotli.decompress(content)
    elif "gzip" in encoding:
        try:
            content = _zlib.decompress(content, _zlib.MAX_WBITS | 32)
        except Exception:
            pass
    elif "deflate" in encoding:
        try:
            content = _zlib.decompress(content)
        except Exception:
            pass
    return content.decode("utf-8", errors="ignore")


def _ll_cln_url(u):
    return re.sub(r'<.*|".*', "", u)


def _ll_ext_info(response, pattern):
    m = re.search(pattern, response)
    return _ll_cln_url(m.group(1)) if m else None


def _ll_get_cdn_tid(content):
    """Extract CDN domain, TID, and KEY from page HTML."""
    try:
        if not content:
            return None, None, None, {"active": True}
        soup = _BS4(content, "html.parser")
        for script in soup.find_all("script"):
            if script.string and "domain:" in script.string:
                cd     = re.search(r"cd: ([^']*),", script.string)
                domain = re.search(r"domain: '([^']*)'", script.string)
                key    = re.search(r"key: '([^']*)'", script.string)
                if cd and domain and key:
                    return domain.group(1), cd.group(1), key.group(1), {"active": False}
        cdn = _ll_ext_info(content, r"p\['CDN_DOMAIN'\]\s*=\s*'([^']*)'")
        tid = _ll_ext_info(content, r"p\['TID'\]\s*=\s*(\d+)")
        key = _ll_ext_info(content, r"p\['KEY'\]\s*=\s*\"([^\"]*)\"")
        if cdn and tid and key:
            return cdn, tid, key, {"active": True}
        return None, None, None, {"active": True}
    except Exception as e:
        _ll_log("ERROR", f"_ll_get_cdn_tid: {e}")
        return None, None, None, {"active": True}


def _ll_decrypt_data(encoded_data, key_length=5):
    """XOR-decrypt the WebSocket payload."""
    try:
        raw       = base64.b64decode(encoded_data)
        k, enc    = raw[:key_length], raw[key_length:]
        decrypted = bytes(b ^ k[i % key_length] for i, b in enumerate(enc))
        return decrypted.decode("utf-8").strip()
    except Exception as e:
        _ll_log("ERROR", f"_ll_decrypt_data: {e}")
        return encoded_data.strip()


def _ll_transform_uuid(uuid_str):
    uppercase = [c for c in uuid_str if c.isupper()]
    key_str   = "".join(uppercase[:4]) if uppercase else "KEY1"
    xor_res   = bytes(
        uuid_str.encode()[i] ^ key_str.encode()[i % len(key_str)]
        for i in range(len(uuid_str))
    )
    return base64.b64encode(xor_res).decode("utf-8")


def _ll_botd_payload(session_uuid):
    """Build the AES-GCM encrypted BotD payload (bot=False)."""
    transformed = _ll_transform_uuid(session_uuid)
    aes_key     = hashlib.sha256(transformed.encode()).digest()
    iv          = os.urandom(12)
    timestamp   = int(time.time() * 1000)
    botd = {
        "bot": False,
        "timestamp": timestamp,
        "webGLSolution": {
            "uuid": session_uuid,
            "nonce": random.randint(1, 3000),
            "time":  random.randint(100, 5000),
        },
    }
    plaintext  = json.dumps(botd, separators=(",", ":")).encode()
    ciphertext = _AESGCM(aes_key).encrypt(iv, plaintext, None)
    botd["encrypted"] = base64.b64encode(iv + ciphertext).decode()
    return json.dumps(botd, separators=(",", ":"))


def _ll_parse_params(raw_string):
    """Parse the CDN params-only response into a dict."""
    raw_string = raw_string.strip().rstrip(";")
    raw_string = raw_string.replace("false", "False").replace("true", "True").replace("null", "None")
    data = ast.literal_eval(raw_string)
    keys = [
        "tid", "backup_domain", "backup2_domain", "sixteen_type",
        "datacloudfront_domain", "EM_List", "max_tasks", "bl_config",
        "tracking", "websocket_domain", "websocket_backup",
        "websocket_bckup2", "pixel_enabled", "redirect_domain",
        "debug_mode", "debug_level", "RGBA_Payloas", "custom_css",
        "custom_js", "cookie_notice", "theme", "custom_logo",
        "maintenance_mode", "extra_scripts", "extra_styles",
        "extra_fonts", "background_color", "custom_html",
        "security_tend", "tc_domain", "analytics_enabled", "ads_enabled",
    ]
    return {k: data[i] for i, k in enumerate(keys) if i < len(data)}


def _ll_canserbero(session, server, syncer, urid, p_key, tid,
                   session_id, isLLBS, task_id, TLeft, APUrl):
    """Connect to AdMaven WebSocket and retrieve the destination URL."""
    catnumber = task_id
    numbers   = [int(urid[-5:]) % 3] + [i for i in range(3) if i != int(urid[-5:]) % 3]
    _ll_log("INFO", f"Trying WS servers in order: {numbers}")

    # fire-and-forget tracking pings
    try:
        threading.Thread(
            target=lambda: session.post(
                f"https://{numbers[0]}.{server}/st?uid={urid}&cat={catnumber}",
                timeout=5),
            daemon=True,
        ).start()
    except Exception:
        pass
    try:
        if APUrl:
            threading.Thread(
                target=lambda: session.get(f"https:{APUrl}", timeout=5),
                daemon=True,
            ).start()
    except Exception:
        pass

    for nmb in numbers:
        current = f"{nmb}.{server}"
        for attempt in range(1, 3):
            ws = None
            try:
                url = (
                    f"wss://{current}/c"
                    f"?uid={urid}&cat={catnumber}&key={p_key}"
                    f"&session_id={session_id}&is_loot={isLLBS}&tid={tid}"
                )
                headers = {
                    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                                       "Chrome/120.0.0.0 Safari/537.36",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Cache-Control":   "no-cache",
                    "Pragma":          "no-cache",
                }
                cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
                if cookie_str:
                    headers["Cookie"] = cookie_str

                _ll_log("INFO", f"WS connecting: {current} (attempt {attempt})")
                ws = _websocket.create_connection(url, timeout=10, header=headers)
                _ll_log("INFO", f"WS connected: {current}")
                ws.settimeout(10)
                ws.send("0")

                max_wait  = 20
                start     = time.time()
                last_ping = time.time()

                while time.time() - start < max_wait:
                    try:
                        ws.settimeout(1)
                        msg = ws.recv()
                        if isinstance(msg, bytes):
                            msg = msg.decode("utf-8")
                        if isinstance(msg, str) and msg.startswith("r:"):
                            result = _ll_decrypt_data(msg[2:])
                            _ll_log("INFO", f"WS result from {current}: {result[:80]}")
                            ws.close()
                            return result
                    except _websocket.WebSocketTimeoutException:
                        if time.time() - last_ping >= 3:
                            try:
                                ws.send("0")
                                last_ping = time.time()
                            except Exception:
                                break
                    except Exception as e:
                        _ll_log("WARN", f"WS recv error on {current}: {e}")
                        break

                _ll_log("WARN", f"No valid response from {current} after {max_wait}s")

            except _websocket.WebSocketException as e:
                _ll_log("WARN", f"WS exception {current} attempt {attempt}: {e}")
            except Exception as e:
                _ll_log("WARN", f"WS general error {current} attempt {attempt}: {e}")
            finally:
                if ws:
                    try:
                        ws.close()
                    except Exception:
                        pass
            if attempt == 1:
                time.sleep(0.5)

    _ll_log("ERROR", "All WS servers exhausted")
    return None


def _ll_get_dest(url):
    """Core LootLabs bypass logic (from shadows.py by ajyats)."""
    hostname = urllib.parse.urlparse(url).hostname
    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        })

        initial   = session.get(url, timeout=15)
        page_text = _ll_decode_resp(initial)

        # extract session UUID
        m = re.search(r"document\.session\s*=\s*['\"]([^'\"]+)['\"]", page_text)
        if not m:
            return "bypass fail! Session UUID not found"
        sess_uuid = m.group(1)
        _ll_log("INFO", f"Session UUID: {sess_uuid}")

        cdn, tid, key, gis = _ll_get_cdn_tid(page_text)
        if not all([cdn, tid, key]):
            return "bypass fail! CDN/TID/KEY not found"

        isLLBS     = gis.get("active", False)
        isLLBS_str = "1" if isLLBS else "0"

        # fetch CDN params
        params_resp = session.get(
            f"https://{cdn}/?tid={tid}&params_only=1", timeout=15)
        try:
            params = _ll_parse_params(_ll_decode_resp(params_resp))
        except Exception as e:
            return f"bypass fail! params parse error: {e}"

        SYNCER = params.get("tc_domain")
        if not SYNCER:
            return "bypass fail! tc_domain not found"

        # verify session (non-blocking)
        if isLLBS and sess_uuid:
            try:
                threading.Thread(
                    target=lambda: session.post(
                        f"https://{hostname}/verify",
                        json={"session": sess_uuid},
                        timeout=10,
                        headers={"Referer": url},
                    ),
                    daemon=True,
                ).start()
            except Exception:
                pass

        mess_session = str(random.randint(100000000000000000, 999999999999999999))
        botd_data    = _ll_botd_payload(sess_uuid)

        # check for puid (postback)
        qs   = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        Pb   = qs.get("puid", [None])[0]
        iP   = bool(Pb)

        TC_body = {
            "tid": int(tid), "bl": [10], "session": mess_session,
            "max_tasks": 1, "design_id": 139, "cur_url": str(url),
            "doc_ref": "", "num_of_tasks": "", "is_loot": isLLBS,
            "rkey": key,
            "cookie_id": str(random.randint(100000000, 999999999)),
            "botd": botd_data, "botds": sess_uuid, "offer": "0",
            "tier_id": 4, "taboola_user_sync": "", "fid": -1,
            "clid": str(uuid.uuid4()),
            "additional_info": {}, "allow_unlocker": True,
            "desktop_design": 0, "show_unlocker": True,
            "test_unlocker_app": -1, "unlocker_only": 0,
        }
        if iP:
            TC_body["puid"] = iP

        rawr = session.post(
            f"https://{SYNCER}/tc",
            json=TC_body,
            cookies={"ci": str(random.randint(1000000000000000, 9999999999999999))},
            timeout=20,
        )
        _ll_log("INFO", f"/tc status: {rawr.status_code}")

        if rawr.status_code == 428:
            return "bypass fail! 428 — BotD rejected"
        if rawr.status_code != 200:
            return f"bypass fail! /tc status {rawr.status_code}"

        try:
            TCP = rawr.json()
            if isinstance(TCP, list):
                if not TCP:
                    return "bypass fail! Empty /tc response"
                TCP = TCP[0]

            task_id = TCP.get("task_id", 0)
            urid    = TCP.get("urid")
            TLeft   = TCP.get("auto_complete_seconds")
            APUrl   = TCP.get("action_pixel_url", "")

            if not urid:
                return "bypass fail! No urid in /tc response"

            # fire task_clicked event (non-blocking)
            try:
                threading.Thread(
                    target=lambda: requests.get(
                        f"https://enaightdecipie.com/?event=task_clicked"
                        f"&session_id={task_id}&info=1",
                        timeout=5,
                    ),
                    daemon=True,
                ).start()
            except Exception:
                pass

            daserver = params.get("websocket_domain")
            if not daserver:
                return "bypass fail! No websocket_domain"

            result = _ll_canserbero(
                session, daserver, SYNCER, urid, key,
                tid, mess_session, isLLBS_str, task_id, TLeft, APUrl,
            )
            if result:
                return result
            return "bypass fail! WebSocket returned no result"

        except Exception as e:
            _ll_log("ERROR", traceback.format_exc())
            return f"bypass fail! /tc parse error: {e}"

    except Exception as e:
        _ll_log("ERROR", traceback.format_exc())
        return f"bypass fail! {e}"


@app.post("/solve-lootlabs")
def route_solve_lootlabs():
    token = request.headers.get("X-Token", "")
    if token != SOLVE_TOKEN:
        return jsonify({"success": False, "error": "forbidden"}), 403

    body = request.get_json(silent=True) or {}

    captcha_token = body.get("captcha", "")
    if not captcha_token or not verify_turnstile(captcha_token):
        return jsonify({"success": False, "error": "captcha required"}), 403

    if not LL_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "LootLabs solver not available — add websocket-client, beautifulsoup4, cryptography to requirements.txt and redeploy",
        }), 500

    link = body.get("link", "").strip()
    if not link:
        return jsonify({"success": False, "error": "param 'link' is required"}), 400

    result = _ll_get_dest(link)

    if result and not result.startswith("bypass fail!"):
        return jsonify({"success": True, "result": result}), 200

    # map internal errors to friendly messages
    friendly = result or "bypass failed — try a fresh link"
    if "Session UUID not found" in friendly:
        friendly = "Could not load the LootLabs page. The link may be expired — grab a fresh one."
    elif "CDN/TID/KEY not found" in friendly:
        friendly = "Page structure changed or link is invalid. Try a fresh link."
    elif "428" in friendly:
        friendly = "Bot detection triggered (428). The server rejected the request — try again in a few seconds."
    elif "WebSocket returned no result" in friendly:
        friendly = "WebSocket timed out. LootLabs servers may be slow — try again with a fresh link."
    elif "websocket_domain" in friendly:
        friendly = "Could not resolve LootLabs WebSocket server. Link may be expired."

    return jsonify({"success": False, "error": friendly}), 500


# ─── entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
