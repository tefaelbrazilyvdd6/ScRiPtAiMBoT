#!/usr/bin/env python3
# api.py — PlatoRelay solver + LootLabs solver (shadows_v2), Flask REST API

import time, json, base64, urllib.parse, queue, math
import requests
import urllib3
from flask import Flask, request, jsonify, render_template, Response, stream_with_context
from flask_cors import CORS
from Crypto.Cipher import AES

import threading
import hashlib
import uuid
import ast
import re
import traceback
import random
import os
import gzip
import zlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOLVE_TOKEN      = os.environ.get("SOLVE_TOKEN", "changeme-set-this-in-render")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "0x4AAAAAAFuUDflleweTZ8jRZuCffo7siyk")

# ─── Delta / PlatoRelay ────────────────────────────────────────────────────────

AUTH_API = "https://auth.platorelay.com/api"
SERVICE  = 3
VERSION  = "8.1.2"
DELTA_UA = (
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
        {"browserInfo": [{"screen": SCREEN, "ua": DELTA_UA, "time": now_ms}]},
        separators=(",", ":"),
    )
    stream_plain = json.dumps(
        {"events": [{"event": 1, "data": {"time": now_ms}}]},
        separators=(",", ":"),
    )
    meta   = aes_ctr(meta_plain,   [ord(c) for c in key_meta],   [ord(c) for c in ctr_meta]).hex()
    stream = aes_ctr(stream_plain, [ord(c) for c in key_stream], [ord(c) for c in ctr_stream]).hex()
    return meta, stream


def extract_ticket(arg: str) -> str:
    t = arg.strip()
    if t.startswith("http"):
        parsed = urllib.parse.urlparse(t)
        qs = urllib.parse.parse_qs(parsed.query)
        if "d" in qs:
            return qs["d"][0]
    return t


def decode_callback_url(loot_url: str):
    qs      = urllib.parse.parse_qs(urllib.parse.urlparse(loot_url).query)
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


_OAUTH_PATTERNS = [
    "accounts.google.com", "google.com/o/oauth",
    "discord.com/oauth2", "discord.gg/oauth", "/oauth",
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
    url  = f"{AUTH_API}/session/step?ticket={urllib.parse.quote(ticket)}&service={SERVICE}"
    body = json.dumps(
        {"captcha": None, "meta": meta, "stream": stream, "resolved": True}
    ).encode()
    r = requests.put(url, data=body, headers={
        "User-Agent": DELTA_UA, "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "x-client-name": "platoboost webclient", "x-client-version": VERSION,
    }, timeout=15, verify=False)
    try:
        return r.json()
    except Exception:
        return {"success": False, "raw": r.text[:200]}


def poll_key(ticket: str, tries: int = 10):
    for _ in range(tries):
        url = f"{AUTH_API}/session/status?ticket={urllib.parse.quote(ticket)}&service={SERVICE}"
        try:
            r = requests.get(url, headers={
                "User-Agent": DELTA_UA, "Accept": "application/json",
                "x-client-name": "platoboost webclient", "x-client-version": VERSION,
            }, timeout=10, verify=False)
            d = r.json()
            k = (d.get("data") or {}).get("key", "")
            if k and k != "KEY_NOT_FOUND":
                return k
        except Exception:
            pass
        time.sleep(0.5)
    return None


def _check_oauth_redirect(ticket: str) -> str | None:
    """
    After a ticket gets consumed by the server triggering an OAuth flow,
    the status endpoint often holds the OAuth redirect URL.
    Returns the URL if found, else None.
    """
    url = f"{AUTH_API}/session/status?ticket={urllib.parse.quote(ticket)}&service={SERVICE}"
    try:
        r = requests.get(url, headers={
            "User-Agent": DELTA_UA, "Accept": "application/json",
            "x-client-name": "platoboost webclient", "x-client-version": VERSION,
        }, timeout=10, verify=False)
        d = r.json()
        data = d.get("data") or {}
        redirect = data.get("url") or data.get("redirect") or ""
        if redirect and _is_oauth_url(redirect):
            return redirect
    except Exception:
        pass
    return None


def solve_delta(raw_link: str, status_cb=None):
    def emit(msg):
        if status_cb:
            status_cb(msg)

    ticket = extract_ticket(raw_link)
    if len(ticket) < MIN_TICKET_LEN:
        return None, "ticket too short"

    seen   = set()
    gap_ts = 0.0

    for rnd in range(12):
        emit(f"round {rnd+1}/12 — sending step request...")
        if ticket in seen:
            return None, "ticket already used"
        seen.add(ticket)

        if gap_ts:
            elapsed = time.time() - gap_ts
            if elapsed < MIN_STEP_GAP:
                wait = MIN_STEP_GAP - elapsed
                emit(f"rate-limit cooldown ({wait:.1f}s)...")
                time.sleep(wait)

        r      = do_step(ticket)
        gap_ts = time.time()

        if not isinstance(r, dict) or not r.get("success"):
            msg = str(r.get("message") or r.get("error") or "").lower()
            if "too fast" in msg or "slow down" in msg:
                emit("server says slow down, retrying...")
                time.sleep(STEP_THROTTLE_SLEEP)
                seen.discard(ticket)
                continue
            # server says ticket consumed — before giving up, check if the
            # step actually triggered an OAuth redirect on their side
            if "already" in msg or "used" in msg or "expired" in msg:
                emit("ticket may be consumed — checking for OAuth redirect...")
                oauth_url = _check_oauth_redirect(ticket)
                if oauth_url:
                    return None, "oauth:" + oauth_url
                return None, "ticket already used"
            emit(f"step failed ({msg or 'no message'}), retrying...")
            time.sleep(1.5)
            continue

        data = r.get("data") or {}
        k    = data.get("key")
        if k and k != "KEY_NOT_FOUND":
            emit("key found!")
            return k, None

        url = data.get("url", "")
        if _is_oauth_url(url):
            return None, "oauth:" + url
        if url == "about:blank" or not url:
            emit("polling for key...")
            k = poll_key(ticket)
            return (k, None) if k else (None, "polling failed")

        emit("following redirect chain...")
        cb = decode_callback_url(url)
        nt = extract_ticket_from_callback(cb) if cb else None
        if nt and len(nt) > 50:
            emit("got new ticket, continuing...")
            ticket = nt
        else:
            emit("polling for key...")
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


def _stream_worker(fn, q):
    try:
        fn()
    except Exception as e:
        q.put({"type": "done", "success": False, "error": f"Internal error: {e}"})


def _make_sse_response(q, timeout=65):
    def generate():
        while True:
            try:
                item = q.get(timeout=timeout)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("type") == "done":
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'status', 'msg': 'still working...'})}\n\n"
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


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
        return jsonify({"success": False, "error": "param 'link' is required"}), 400
    key, err = solve_delta(link)
    if key:
        return jsonify({"success": True, "key": key}), 200
    if err and err.startswith("oauth:"):
        return jsonify({"success": False, "oauth": True, "oauth_url": err[6:], "error": "Account verification required"}), 200
    messages = {
        "ticket too short": "Invalid link — copy the full URL from Delta.",
        "ticket already used": "Link already used — get a fresh one from Delta.",
        "polling failed": "Key could not be retrieved — link may be expired.",
        "callback decode failed": "Checkpoint step failed — try a fresh link.",
        "max rounds reached": "Solver timed out — try again in a few seconds.",
    }
    return jsonify({"success": False, "error": messages.get(err, "Something went wrong — grab a fresh link.")}), 500


@app.post("/solve-stream")
def route_solve_stream():
    token = request.headers.get("X-Token", "")
    if token != SOLVE_TOKEN:
        return jsonify({"success": False, "error": "forbidden"}), 403
    body = request.get_json(silent=True) or {}
    captcha_token = body.get("captcha", "")
    if not captcha_token or not verify_turnstile(captcha_token):
        return jsonify({"success": False, "error": "captcha required"}), 403
    link = body.get("link", "").strip()
    if not link:
        return jsonify({"success": False, "error": "param 'link' is required"}), 400

    q = queue.Queue()

    def work():
        key, err = solve_delta(link, status_cb=lambda m: q.put({"type": "status", "msg": m}))
        if key:
            q.put({"type": "done", "success": True, "key": key})
        elif err and err.startswith("oauth:"):
            q.put({"type": "done", "success": False, "oauth": True, "oauth_url": err[6:], "error": "Account verification required"})
        else:
            messages = {
                "ticket too short": "Invalid link — copy the full URL from Delta.",
                "ticket already used": "Link already used — get a fresh one.",
                "polling failed": "Key could not be retrieved — link may be expired.",
                "callback decode failed": "Checkpoint step failed — try a fresh link.",
                "max rounds reached": "Solver timed out — try again.",
            }
            q.put({"type": "done", "success": False, "error": messages.get(err, "Something went wrong — grab a fresh link.")})

    threading.Thread(target=_stream_worker, args=(work, q), daemon=True).start()
    return _make_sse_response(q, timeout=50)


# ═══════════════════════════════════════════════════════════════════════════════
# ─── LootLabs solver (shadows_v2 by ajyats) ───────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

LL_AVAILABLE = False
try:
    from bs4 import BeautifulSoup as _BS4
    import websocket as _websocket
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    LL_AVAILABLE = True
except ImportError as _e:
    print(f"[LootLabs] deps missing: {_e}")

LL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
)


def _ll_make_session(hostname):
    origin = f"https://{hostname}"
    s = requests.Session()
    s.headers.update({
        "User-Agent": LL_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Sec-CH-UA": '"Chromium";v="139", "Not:A-Brand";v="24", "Google Chrome";v="139"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Origin": origin,
        "Referer": f"https://{hostname}",
    })
    return s


def _ll_wildcard_search(text, pattern):
    regex = re.escape(pattern).replace(r"\*", "(.*?)")
    m = re.search(regex, text)
    return m.group(1) if m else None


def _ll_decode_resp(response):
    enc = (response.headers.get("Content-Encoding") or "").lower()
    content = response.content
    try:
        if "gzip" in enc:
            return gzip.decompress(content).decode("utf-8")
        if "deflate" in enc:
            return zlib.decompress(content).decode("utf-8")
        return content.decode("utf-8", errors="ignore")
    except Exception:
        return content.decode("utf-8", errors="ignore")


def _ll_cln_url(u):
    return re.sub(r'<.*|".*', "", u)


def _ll_ext_info(response, pattern):
    m = re.search(pattern, response)
    return _ll_cln_url(m.group(1)) if m else None


def _ll_get_cdn_tid(content):
    if not content:
        return None, None, None
    cdn = _ll_ext_info(content, r"p\['CDN_DOMAIN'\]\s*=\s*'([^']*)'")
    tid = _ll_ext_info(content, r"p\['TID'\]\s*=\s*(\d+)")
    key = _ll_ext_info(content, r"p\['KEY'\]\s*=\s*\"([^\"]*)\"")
    if cdn and tid and key:
        return cdn, tid, key
    return None, None, None


def _ll_get_p_vars(content):
    pvars = {}
    for m in re.finditer(r"p\['(\w+)'\]\s*=\s*([^\n;]+)", content):
        k, v = m.group(1), m.group(2).strip().rstrip(";").strip()
        if (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
            v = v[1:-1]
        pvars[k] = v
    return pvars


def _ll_decrypt_data(encoded_data, key_length=5):
    try:
        raw  = base64.b64decode(encoded_data)
        key, blob = raw[:key_length], raw[key_length:]
        return bytes(b ^ key[i % key_length] for i, b in enumerate(blob)).decode("utf-8").strip()
    except Exception:
        return encoded_data.strip()


def _ll_ws_header_list(session):
    ua = session.headers.get("User-Agent", LL_UA)
    headers = [
        f"User-Agent: {ua}",
        "Accept-Language: en-US,en;q=0.9",
        "Cache-Control: no-cache",
        "Pragma: no-cache",
    ]
    cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
    if cookie_str:
        headers.append(f"Cookie: {cookie_str}")
    return headers


def _ll_fire(fn, *args, **kwargs):
    threading.Thread(target=lambda: _ll_silent(fn, *args, **kwargs), daemon=True).start()


def _ll_silent(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception:
        pass


def _ll_get(session, url, **kw):
    if not url:
        return None
    if url.startswith("//"):
        url = "https:" + url
    kw.setdefault("timeout", 6)
    kw.setdefault("allow_redirects", True)
    return session.get(url, **kw)


def _ll_beacon_post(session, url):
    if not url:
        return
    if url.startswith("//"):
        url = "https:" + url
    session.post(url, data=b"", headers={"Content-Type": "text/plain;charset=UTF-8"}, timeout=4)


def _ll_parse_r_payload(message):
    if not isinstance(message, str) or not message.startswith("r:"):
        return None
    payload = "".join(ch for ch in message[2:].strip() if 32 <= ord(ch) <= 126)
    if payload.startswith("http://") or payload.startswith("https://"):
        return payload
    return _ll_decrypt_data(payload)


# ── WebGL PoW (the key fix in v2) ─────────────────────────────────────────────

def _ll_fract(r6, n1):
    n_ = 43758.5453 * math.sin(12.9898 * r6 + 78.233 * n1)
    return n_ - math.floor(n_)


def _ll_solve_webgl_nonce(uuid_str):
    y6 = int(uuid_str.replace("-", "")[:8], 16) / 4294967295.0
    for nonce in range(100000):
        o4 = _ll_fract(y6, nonce)
        o4 = _ll_fract(o4, nonce + 1)
        o4 = _ll_fract(o4, nonce + 2)
        if o4 < 0.001:
            return nonce
    return 99999


def _ll_transform_uuid(uuid_str):
    m = re.findall(r"[A-Z]", uuid_str)
    key_str = "".join(m[:4]) if m else "KEY1"
    uuid_bytes = uuid_str.encode("utf-8")
    key_bytes  = key_str.encode("utf-8")
    xored = bytes(uuid_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(uuid_bytes)))
    return base64.b64encode(xored).decode("ascii")


def _ll_make_botd(session_uuid):
    nonce      = _ll_solve_webgl_nonce(session_uuid)
    solve_time = int(nonce * random.uniform(1.15, 1.4) + random.randint(20, 80))
    botd = {
        "bot": False,
        "timestamp": int(time.time() * 1000),
        "webGLSolution": {
            "uuid": session_uuid,
            "nonce": nonce,
            "time": solve_time,
        },
    }
    aes_key   = hashlib.sha256(_ll_transform_uuid(session_uuid).encode("utf-8")).digest()
    iv        = os.urandom(12)
    plaintext = json.dumps(botd, separators=(",", ":")).encode("utf-8")
    ct        = _AESGCM(aes_key).encrypt(iv, plaintext, None)
    botd["encrypted"] = base64.b64encode(iv + ct).decode("ascii")
    return json.dumps(botd, separators=(",", ":"))


def _ll_get_params(raw_string):
    text = (raw_string or "").strip()
    try:
        data = json.loads("[" + text[1:-2] + "]")
    except Exception:
        if text.endswith(";"):
            text = text[:-1]
        text = text.replace("false", "False").replace("true", "True").replace("null", "None")
        data = ast.literal_eval(text)
    return {
        "websocket_domain": data[9],
        "websocket_backup":  data[10],
        "websocket_bckup2":  data[11],
        "tc_domain":         data[29],
        "allow_unlocker":    data[30],
    }


def _ll_as_bool(v, default=True):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() in ("1", "true")
    return bool(v)


def _ll_canserbero(session, ws_domain, tasks, p_key, tid, ws_session, origin, done, TLeft=45):
    if not tasks:
        return
    urid    = str(tasks[0].get("urid", ""))
    cat     = str(tasks[0].get("task_id", 0))
    try:
        shard = int(urid[-5:]) % 3
    except Exception:
        shard = 0

    ws_url = (
        f"wss://{shard}.{ws_domain}/c?uid={urid}&cat={cat}"
        f"&key={p_key}&session_id={ws_session}&is_loot=1&tid={tid}"
    )
    ws = None
    ping_stop = threading.Event()
    try:
        ws = _websocket.create_connection(
            ws_url, timeout=8,
            header=_ll_ws_header_list(session),
            origin=origin if str(origin).startswith("http") else f"https://{origin}",
        )
        ws.settimeout(0.5)

        def _ping():
            while not ping_stop.wait(10):
                try:
                    ws.send("0")
                except Exception:
                    return
        threading.Thread(target=_ping, daemon=True).start()

        deadline = time.time() + max(int(TLeft or 30), 10)
        while time.time() < deadline and not done.get("result"):
            try:
                message = ws.recv()
            except _websocket.WebSocketTimeoutException:
                continue
            except Exception:
                break
            if isinstance(message, bytes):
                try:
                    message = message.decode("utf-8")
                except Exception:
                    continue
            if message == "Refresh Page":
                break
            result = _ll_parse_r_payload(message)
            if result:
                done["result"] = result
                return
    except Exception:
        pass
    finally:
        ping_stop.set()
        if ws:
            try:
                ws.close()
            except Exception:
                pass


def _ll_get_dest(url, status_cb=None, captcha_token_cb=None):
    """
    captcha_token_cb: callable(cap_url) -> str  (user-supplied turnstile token)
    If not provided and a captcha task is detected, we skip verification
    (which will likely cause WS timeout, same as before).
    """
    def emit(msg):
        if status_cb:
            status_cb(msg)

    hostname = urllib.parse.urlparse(url).hostname
    session  = None
    t0       = time.perf_counter()

    def taken():
        return f"{time.perf_counter() - t0:.2f}s"

    try:
        emit(f"loading LootLabs page ({hostname})...")
        session = _ll_make_session(hostname)
        origin  = f"https://{hostname}"

        initial   = session.get(url, headers={"Origin": origin}, timeout=15)
        sess_uuid = _ll_wildcard_search(initial.text, "<script>document.session = '*'</script>")
        if not sess_uuid:
            return f"bypass fail! Session UUID not found ({taken()})"
        emit(f"session UUID: {sess_uuid[:8]}...")

        _ll_fire(
            session.post,
            f"{origin}/verify",
            data=json.dumps({"session": sess_uuid}, separators=(",", ":")),
            headers={"Content-Type": "text/plain;charset=UTF-8", "Origin": origin},
            timeout=6,
        )

        emit("extracting CDN/TID/KEY...")
        cdn, tid, key = _ll_get_cdn_tid(initial.text)
        if not all([cdn, tid, key]):
            return f"bypass fail! CDN/TID/KEY not found ({taken()})"

        pvars = _ll_get_p_vars(initial.text)

        emit("fetching CDN parameters...")
        content_resp = session.get(
            f"https://{cdn}/?tid={tid}&params_only=1",
            headers={"Origin": origin}, timeout=10,
        )
        params = _ll_get_params(_ll_decode_resp(content_resp))

        SYNCER = params.get("tc_domain") or "nerventualken.com"

        mess_session = str(random.randint(1, 9)) + "".join(
            str(random.randint(0, 9)) for _ in range(16)
        ) + str(random.randint(0, 9))

        try:
            test_unl = int(pvars.get("TEST_UNLOCKER_APP", -1))
        except Exception:
            test_unl = -1
        try:
            unlocker_only = int(pvars.get("UNLOCKER_ONLY", "0"))
        except Exception:
            unlocker_only = 0

        emit("solving WebGL proof-of-work...")
        botd_data = _ll_make_botd(sess_uuid)

        TCData = {
            "tid":              int(tid),
            "bl":               [18, 2, 33, 7, 21, 49],
            "session":          mess_session,
            "max_tasks":        1,
            "design_id":        135,
            "cur_url":          url,
            "doc_ref":          "",
            "tier_id":          "0",
            "num_of_tasks":     "1",
            "is_loot":          True,
            "rkey":             key,
            "cookie_id":        str(random.randint(100000000, 999999999)),
            "botd":             botd_data,
            "botds":            sess_uuid,
            "offer":            pvars.get("OFFER", "0"),
            "ver":              pvars.get("WIDGET_VERSION") or "v1",
            "tasks_timer":      pvars.get("TASKS_TIMER") or "-1",
            "test_unlocker_app": test_unl,
            "allow_unlocker":   _ll_as_bool(params.get("allow_unlocker"), True),
            "show_unlocker":    _ll_as_bool(pvars.get("SHOW_UNLOCKER"), True),
            "desktop_design":   1 if pvars.get("DESKTOP_DESIGN") in ("1", "true") else 0,
            "unlocker_only":    unlocker_only,
            "additional_info":  {},
            "taboola_user_sync": "0",
        }

        emit("posting task config to sync server...")
        saved_headers = dict(session.headers)
        try:
            session.headers.clear()
            session.headers.update({
                "User-Agent":     saved_headers.get("User-Agent", ""),
                "Accept":         "*/*",
                "Accept-Language": saved_headers.get("Accept-Language", "en-US,en;q=0.9"),
                "Content-Type":   "application/json",
                "Origin":         origin,
                "Referer":        f"{origin}/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
            })
            rawr = session.post(f"https://{SYNCER}/tc", json=TCData, timeout=15)
        finally:
            session.headers.clear()
            session.headers.update(saved_headers)

        emit(f"/tc responded: {rawr.status_code}")
        if rawr.status_code != 200:
            return f"bypass fail! TC status {rawr.status_code} ({taken()})"

        TCP      = json.loads(_ll_decode_resp(rawr))
        TCP_list = TCP if isinstance(TCP, list) else [TCP]
        if not TCP_list:
            return f"bypass fail! Empty TC response ({taken()})"
        TCP = TCP_list[0]

        # detect captcha task (task_id 41)
        captcha_task = next(
            (i for i in TCP_list
             if i.get("title") == "Confirm you are human" or str(i.get("task_id")) == "41"),
            None,
        )
        bind    = captcha_task or TCP
        urid    = bind.get("urid")
        task_id = bind.get("task_id", 0)
        if not urid:
            return f"bypass fail! No urid ({taken()})"

        emit(f"got task (urid={str(urid)[-6:]}, id={task_id})")

        ws_session = bind.get("session_id") or "undefined"
        ws_domain  = params.get("websocket_domain") or "onsultingco.com"
        try:
            shard = int(str(urid)[-5:]) % 3
        except Exception:
            shard = 0
        shard_host = f"{shard}.{ws_domain}"

        for idx, item in enumerate(TCP_list):
            _ll_fire(_ll_get, session,
                f"https://enaightdecipie.com/?event=task_clicked"
                f"&session_id={item.get('task_id')}&info={idx + 1}")

        done = {"result": None}
        ws_domains = [ws_domain]
        for _bd in [params.get("websocket_backup"), params.get("websocket_bckup2")]:
            if _bd and _bd not in ws_domains:
                ws_domains.append(_bd)

        # Launch all available WS domains in parallel — first result wins
        emit(f"opening WebSocket connection ({len(ws_domains)} domain(s))...")
        ws_threads = []
        for _wsd in ws_domains:
            _t = threading.Thread(
                target=_ll_canserbero,
                args=(session, _wsd, [bind], key, tid, ws_session, origin, done),
                kwargs={"TLeft": 40},
                daemon=True,
            )
            _t.start()
            ws_threads.append(_t)
        ws_thread = ws_threads[0]  # kept for join below

        _ll_fire(_ll_beacon_post, session, f"https://{shard_host}/st?uid={urid}&cat={task_id}")
        ap = bind.get("action_pixel_url") or TCP.get("action_pixel_url")
        if ap:
            _ll_fire(_ll_get, session, ap)
        _ll_fire(_ll_get, session,
            f"https://{SYNCER}/td?ac=auto_complete&urid={urid}&cat={task_id}&tid={tid}")

        # ── captcha step ──────────────────────────────────────────────────────
        if captcha_task:
            cap_url = captcha_task.get("ad_url") or f"https://{SYNCER}/captcha?urid={urid}"
            if not str(cap_url).startswith("http"):
                cap_url = f"https://{SYNCER}/captcha?urid={urid}"

            if captcha_token_cb:
                emit(f"captcha required — waiting for user ({cap_url})...")
                try:
                    token = captcha_token_cb(cap_url)
                    if token == "iframe_done":
                        # Fallback: user used the legacy iframe path; we don't have a real token.
                        # Fire the tracking pixel and let the WebSocket try — it may still
                        # succeed if the user's browser session happened to verify on LootLabs' side.
                        emit("captcha iframe completed — waiting for WebSocket result...")
                        _ll_fire(_ll_get, session,
                            f"https://{SYNCER}/td?ac=captcha&urid={urid}&=&cat={task_id}&tid={tid}")
                        # Note: without a real token from /captcha/verify the WebSocket
                        # is unlikely to return a result.  The native-Turnstile path
                        # (sitekey sent in captcha_needed) avoids this entirely.
                    elif token:
                        emit("captcha token received, verifying...")
                        vrf = session.post(
                            f"https://{SYNCER}/captcha/verify",
                            json={"urid": str(urid), "token": token},
                            headers={
                                "Origin":       origin,   # must match the LootLabs page, not SYNCER
                                "Referer":      cap_url,
                                "Content-Type": "application/json",
                            },
                            timeout=10,
                        )
                        emit(f"captcha verify: {vrf.status_code}")
                        _ll_fire(_ll_get, session,
                            f"https://{SYNCER}/td?ac=captcha&urid={urid}&=&cat={task_id}&tid={tid}")
                except Exception as e:
                    emit(f"captcha step error: {e}")
            else:
                emit("captcha task detected but no solver provided — result may fail")

        # Wait for first result — poll every 0.2s up to 42s total
        _deadline = time.time() + 42
        while time.time() < _deadline and not done["result"]:
            time.sleep(0.2)

        if done["result"]:
            emit(f"bypassed! ({taken()})")
            return done["result"]

        return f"bypass fail! WebSocket returned no result ({taken()})"

    except Exception as e:
        return f"bypass fail! {e} ({taken()})"
    finally:
        if session:
            try:
                session.close()
            except Exception:
                pass


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
        return jsonify({"success": False, "error": "LootLabs deps missing — add websocket-client, beautifulsoup4, cryptography to requirements.txt"}), 500
    link = body.get("link", "").strip()
    if not link:
        return jsonify({"success": False, "error": "param 'link' is required"}), 400
    result = _ll_get_dest(link)
    if result and not result.startswith("bypass fail!"):
        return jsonify({"success": True, "result": result}), 200
    friendly = _ll_friendly_error(result)
    return jsonify({"success": False, "error": friendly}), 500


@app.post("/solve-lootlabs-stream")
def route_solve_lootlabs_stream():
    token = request.headers.get("X-Token", "")
    if token != SOLVE_TOKEN:
        return jsonify({"success": False, "error": "forbidden"}), 403
    body = request.get_json(silent=True) or {}
    captcha_token = body.get("captcha", "")
    if not captcha_token or not verify_turnstile(captcha_token):
        return jsonify({"success": False, "error": "captcha required"}), 403
    if not LL_AVAILABLE:
        return jsonify({"success": False, "error": "LootLabs deps missing"}), 500
    link = body.get("link", "").strip()
    if not link:
        return jsonify({"success": False, "error": "param 'link' is required"}), 400

    q = queue.Queue()

    # Each stream session gets a unique ID so the frontend can POST the
    # LootLabs captcha token back to the right waiting thread.
    session_id = str(uuid.uuid4())
    captcha_event   = threading.Event()
    captcha_result  = {"token": None}

    # Store the event/result so /ll-captcha-submit can find it
    _ll_captcha_sessions[session_id] = (captcha_event, captcha_result)

    def captcha_token_cb(cap_url):
        """Called by _ll_get_dest when LootLabs needs a captcha solved."""
        # Tell the frontend: show the captcha iframe to the user
        q.put({"type": "captcha_needed", "session_id": session_id, "cap_url": cap_url})
        # Block until the frontend POSTs the solved token (or 90s timeout)
        captcha_event.wait(timeout=90)
        return captcha_result.get("token")

    def work():
        try:
            result = _ll_get_dest(
                link,
                status_cb=lambda m: q.put({"type": "status", "msg": m}),
                captcha_token_cb=captcha_token_cb,
            )
            if result and not result.startswith("bypass fail!"):
                q.put({"type": "done", "success": True, "result": result})
            else:
                q.put({"type": "done", "success": False, "error": _ll_friendly_error(result)})
        finally:
            _ll_captcha_sessions.pop(session_id, None)

    threading.Thread(target=_stream_worker, args=(work, q), daemon=True).start()

    # Pass the session_id to the frontend as the first SSE event
    q.put({"type": "session", "session_id": session_id})

    return _make_sse_response(q, timeout=120)


# Store in-flight LootLabs captcha sessions: session_id -> (Event, result_dict)
_ll_captcha_sessions: dict = {}


@app.post("/ll-captcha-submit")
def route_ll_captcha_submit():
    """Frontend POSTs the user-solved LootLabs captcha token here."""
    token = request.headers.get("X-Token", "")
    if token != SOLVE_TOKEN:
        return jsonify({"success": False, "error": "forbidden"}), 403
    body = request.get_json(silent=True) or {}
    session_id    = body.get("session_id", "")
    captcha_token = body.get("captcha_token", "")
    if not session_id or not captcha_token:
        return jsonify({"success": False, "error": "missing fields"}), 400
    entry = _ll_captcha_sessions.get(session_id)
    if not entry:
        return jsonify({"success": False, "error": "session not found or expired"}), 404
    event, result = entry
    result["token"] = captcha_token
    event.set()
    return jsonify({"success": True}), 200


def _ll_friendly_error(result):
    friendly = result or "bypass failed — try a fresh link"
    if "Session UUID not found" in friendly:
        return "Could not load the LootLabs page — link may be expired."
    if "CDN/TID/KEY not found" in friendly:
        return "Page structure changed or link is invalid — try a fresh link."
    if "428" in friendly:
        return "Bot detection triggered (428) — try again in a few seconds."
    if "WebSocket returned no result" in friendly:
        return "WebSocket timed out — LootLabs servers may be slow, try a fresh link."
    if "websocket_domain" in friendly:
        return "Could not resolve WebSocket server — link may be expired."
    return friendly


# ─── entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
