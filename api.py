#!/usr/bin/env python3
# api.py — PlatoRelay solver, Flask REST API for Render

import time, json, base64, urllib.parse
import requests
import urllib3
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import os
SOLVE_TOKEN    = os.environ.get("SOLVE_TOKEN", "changeme-set-this-in-render")
HCAPTCHA_SECRET = os.environ.get("HCAPTCHA_SECRET", "ES_56bdac6bfd5c4d3ca6efd9bde2551de0")

AUTH_API = "https://auth.platorelay.com/api"
SERVICE = 3
VERSION = "8.1.2"
UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 "
    "Mobile/15E148 Safari/604.1"
)
SCREEN = "390x844"
MIN_TICKET_LEN = 33
MIN_STEP_GAP = 5.0
STEP_THROTTLE_SLEEP = 2.0

app = Flask(__name__)
CORS(app)


# ─── crypto ────────────────────────────────────────────────────────────────────

def aes_ctr(plain: str, key_bytes, iv_bytes) -> bytes:
    key = bytearray(key_bytes)
    iv = bytearray(iv_bytes)
    data = plain.encode()
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(iv))
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
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(t).query)
        if "d" in qs:
            return qs["d"][0]
    return t


def decode_callback_url(loot_url: str):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(loot_url).query)
    r_param = qs.get("r", [""])[0]
    if not r_param:
        return None
    b64 = r_param.replace("-", "+").replace("_", "/")
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

def do_step(ticket: str) -> dict:
    meta, stream = build_meta_stream(ticket)
    if meta is None:
        return {"success": False, "error": "ticket too short"}
    url = (
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
            "User-Agent": UA,
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "x-client-name": "platoboost webclient",
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
                    "User-Agent": UA,
                    "Accept": "application/json",
                    "x-client-name": "platoboost webclient",
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

    seen = set()
    gap_ts = 0.0

    for rnd in range(12):
        if ticket in seen:
            return None, "ticket loop detected"
        seen.add(ticket)

        if gap_ts:
            elapsed = time.time() - gap_ts
            if elapsed < MIN_STEP_GAP:
                time.sleep(MIN_STEP_GAP - elapsed)

        r = do_step(ticket)
        gap_ts = time.time()

        if not isinstance(r, dict) or not r.get("success"):
            msg = str(r.get("message") or r.get("error") or "").lower()
            if "too fast" in msg or "slow down" in msg:
                time.sleep(STEP_THROTTLE_SLEEP)
                continue
            time.sleep(1.5)
            continue

        data = r.get("data") or {}
        k = data.get("key")
        if k and k != "KEY_NOT_FOUND":
            return k, None

        url = data.get("url", "")
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
    return jsonify({"status": "ok"}), 200


def verify_hcaptcha(token: str) -> bool:
    try:
        r = requests.post(
            "https://api.hcaptcha.com/siteverify",
            data={"secret": HCAPTCHA_SECRET, "response": token},
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
    if not captcha_token or not verify_hcaptcha(captcha_token):
        return jsonify({"success": False, "error": "captcha required"}), 403

    link = body.get("link", "").strip()
    if not link:
        link = request.args.get("link", "").strip()
    if not link:
        return jsonify({"success": False, "error": "param 'link' is required"}), 400

    key, err = solve(link)
    if key:
        return jsonify({"success": True, "key": key}), 200

    messages = {
        "ticket too short":      "Invalid link. Make sure you copied the full link from the Delta checkpoint page.",
        "ticket loop detected":  "This link has already been used. Go back to Delta and get a fresh checkpoint link.",
        "polling failed":        "Key could not be retrieved. The link may have expired — get a new one from Delta.",
        "callback decode failed":"Checkpoint step failed. Try again with a fresh link from Delta.",
        "max rounds reached":    "Solver timed out. PlatoRelay may be slow right now — try again in a few seconds.",
    }
    friendly = messages.get(err, "Something went wrong. Grab a fresh link from Delta and try again.")
    return jsonify({"success": False, "error": friendly}), 500


# ─── entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
