#!/usr/bin/env python3
"""
SparkLight 本地 Brave 浏览器 Cookie 实时联动与自动同步守护工具
说明：从本地 macOS Brave 浏览器安全提取当前已登录的抖音完整 Cookie，
采用 Python 标准库 (hashlib.pbkdf2_hmac) 与系统原生 OpenSSL 解密，零第三方 pip 依赖。
"""

import sys
import os
import json
import sqlite3
import subprocess
import shutil
import tempfile
import time
import hashlib
import binascii
import urllib.request

def get_brave_derived_key():
    res = subprocess.run(["security", "find-generic-password", "-w", "-s", "Brave Safe Storage"], capture_output=True, text=True)
    password = res.stdout.strip().encode("utf-8")
    if not password:
        raise ValueError("未能从系统钥匙串获取 Brave Safe Storage 密码")

    # PBKDF2-HMAC-SHA1, 1003 iterations, 16 bytes
    return hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1003, 16)

def decrypt_cookie_value(enc_val, key):
    if not enc_val or len(enc_val) < 3:
        return ""
    if enc_val[:3] in (b"v10", b"v11"):
        enc_val = enc_val[3:]
    if len(enc_val) == 0:
        return ""

    key_hex = binascii.hexlify(key).decode()
    iv_hex = binascii.hexlify(b" " * 16).decode()

    proc = subprocess.run(
        ["openssl", "enc", "-d", "-aes-128-cbc", "-K", key_hex, "-iv", iv_hex],
        input=enc_val,
        capture_output=True
    )
    if proc.returncode != 0:
        return ""

    raw = proc.stdout
    # Modern Chromium on macOS has a 32-byte signature prefix before plaintext
    if len(raw) > 32:
        try:
            return raw[32:].decode("utf-8")
        except Exception:
            pass
    return raw.decode("utf-8", errors="ignore")

def extract_brave_douyin_cookie():
    cookie_db = os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies")
    if not os.path.exists(cookie_db):
        raise FileNotFoundError(f"未找到 Brave 浏览器 Cookie 文件: {cookie_db}")

    key = get_brave_derived_key()

    tmp = tempfile.mktemp(suffix=".db")
    shutil.copy2(cookie_db, tmp)
    con = sqlite3.connect(tmp)
    cur = con.cursor()
    rows = cur.execute("SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%douyin.com%'").fetchall()
    cookies = {}
    for host, name, enc in rows:
        val = decrypt_cookie_value(enc, key)
        if val:
            cookies[name] = val
    os.remove(tmp)

    sessionid = cookies.get("sessionid", "")
    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
    return cookie_str, sessionid, cookies

def sync_to_server(cookie_str, server_url, api_key):
    req = urllib.request.Request(f"{server_url}/api/v1/accounts", headers={"X-API-Key": api_key})
    with urllib.request.urlopen(req) as res:
        accs = json.loads(res.read().decode()).get("data", [])

    if not accs:
        print("[SparkLight] 服务端暂无账号，正在自动创建...")
        payload = json.dumps({"alias": "", "cookie": cookie_str}).encode()
        r = urllib.request.Request(
            f"{server_url}/api/v1/accounts",
            data=payload,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(r) as res:
            data = json.loads(res.read().decode())
            print("[SparkLight] 账号自动创建成功:", data.get("data", {}).get("alias"))
    else:
        acc_id = accs[0]["id"]
        payload = json.dumps({"cookie": cookie_str}).encode()
        r = urllib.request.Request(
            f"{server_url}/api/v1/accounts/{acc_id}/sync-cookie",
            data=payload,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(r) as res:
            data = json.loads(res.read().decode())
            print(f"[SparkLight] 已向账号「{accs[0]['alias']}」同步最新 Cookie: {data.get('message')}")

def main():
    server = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "http://10.96.1.108:11090"
    api_key = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else "sk_11147ff6bc73186fa257755c057c6c036139083d5d86d569"
    watch_mode = "--watch" in sys.argv or "-w" in sys.argv

    print("==================================================")
    print(" SparkLight 浏览器 Cookie 联动同步服务 (纯标准库版)")
    print(f" 目标服务端: {server}")
    print(f" 运行模式: {'持续监听 (Watch)' if watch_mode else '单次同步 (One-shot)'}")
    print("==================================================")

    cookie_db = os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies")

    last_sid = ""
    last_mtime = 0

    while True:
        try:
            mtime = os.path.getmtime(cookie_db)
            if mtime != last_mtime:
                last_mtime = mtime
                cookie_str, sid, cookies = extract_brave_douyin_cookie()
                if sid and sid != last_sid:
                    last_sid = sid
                    print(f"[{time.strftime('%H:%M:%S')}] 检测到 Brave 浏览器新登录会话 (sessionid={sid[:10]}...)")
                    sync_to_server(cookie_str, server, api_key)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] 检测异常: {e}")

        if not watch_mode:
            break
        time.sleep(2)

if __name__ == "__main__":
    main()
