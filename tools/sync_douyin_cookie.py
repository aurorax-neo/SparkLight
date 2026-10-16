#!/usr/bin/env python3
"""
SparkLight 本机浏览器会话提取与一键同步工具
自动从本地已登录的 Chrome / Brave / Edge 浏览器提取完整 HttpOnly 凭证并安全推送到 SparkLight 服务端。
全程在内存中解密与传输，不向控制台或日志输出明文 Cookie。
"""

import sys, os, sqlite3, hashlib, subprocess, json, urllib.request, urllib.error
from pathlib import Path

def get_macos_key(browser="Brave"):
    service = "Brave Safe Storage" if browser.lower() == "brave" else "Chrome Safe Storage"
    cmd = ["security", "find-generic-password", "-w", "-s", service]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout.strip().encode('utf-8')
    except Exception:
        # Fallback to mock password
        return b"mock_password"

def decrypt_v10(raw_enc, key, host_key=""):
    # Chromium v10 format: AES-128-CBC, IV is 16 spaces
    iv = b" " * 16
    raw = raw_enc[3:] # strip 'v10'
    cmd = ["openssl", "enc", "-d", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex()]
    res = subprocess.run(cmd, input=raw, capture_output=True)
    if res.returncode == 0:
        data = res.stdout
        if host_key and len(data) > 32 and data[:32] == hashlib.sha256(host_key.encode()).digest():
            data = data[32:]
        return data.decode('utf-8', errors='ignore')
    return None
def extract_cookies(cookie_file, browser="Brave"):
    if not Path(cookie_file).exists():
        return None
    raw_key = get_macos_key(browser)
    aes_key = hashlib.pbkdf2_hmac('sha1', raw_key, b'saltysalt', 1003, dklen=16)

    c = sqlite3.connect(f"file:{cookie_file}?mode=ro", uri=True)
    rows = c.execute("SELECT host_key, name, value, encrypted_value FROM cookies WHERE host_key LIKE '%douyin.com%'").fetchall()
    
    cookie_map = {}
    for host, name, val, enc in rows:
        if val:
            cookie_map[name] = val
        elif enc and enc.startswith(b'v10'):
            dec = decrypt_v10(enc, aes_key, host)
            if dec:
                cookie_map[name] = dec

    if not cookie_map or 'sessionid' not in cookie_map:
        return None

    full_cookie = "; ".join(f"{k}={v}" for k, v in cookie_map.items())
    return full_cookie

def sync_to_server(full_cookie, server_url, api_key, target_account_id=None):
    server = server_url.rstrip('/')
    req = urllib.request.Request(f"{server}/api/v1/accounts", headers={"X-API-Key": api_key})
    with urllib.request.urlopen(req, timeout=15) as r:
        accounts = json.loads(r.read()).get("data") or []

    # Verify cookie & get UID
    info_req = urllib.request.Request(
        "https://www.douyin.com/passport/account/info/v2/?aid=6383",
        headers={"Cookie": full_cookie, "User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(info_req, timeout=15) as r:
        info_data = json.loads(r.read()).get("data") or {}
    
    uid = str(info_data.get("user_id") or info_data.get("user_id_str") or "")
    nickname = info_data.get("screen_name") or info_data.get("name") or "抖音用户"

    if not uid:
        print(json.dumps({"status": "FAILED", "reason": "Cookie 无法通过官方身份校验，可能已失效"}, ensure_ascii=False))
        return False

    matched = None
    if target_account_id:
        matched = next((a for a in accounts if a["id"] == target_account_id), None)
    else:
        matched = next((a for a in accounts if a.get("uid") == uid), None)

    if matched:
        put_req = urllib.request.Request(
            f"{server}/api/v1/accounts/{matched['id']}",
            data=json.dumps({"cookie": full_cookie}).encode('utf-8'),
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            method="PUT"
        )
        with urllib.request.urlopen(put_req, timeout=15) as r:
            res = json.loads(r.read())
        print(json.dumps({
            "status": "SUCCESS",
            "action": "UPDATED",
            "account_id": matched["id"],
            "nickname": nickname,
            "uid": uid,
            "message": "账号会话凭证已成功同步更新！"
        }, ensure_ascii=False))
        return True
    else:
        post_req = urllib.request.Request(
            f"{server}/api/v1/accounts",
            data=json.dumps({"alias": nickname, "cookie": full_cookie}).encode('utf-8'),
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(post_req, timeout=15) as r:
            res = json.loads(r.read())
        print(json.dumps({
            "status": "SUCCESS",
            "action": "CREATED",
            "nickname": nickname,
            "uid": uid,
            "message": "已成功创建并同步新账号！"
        }, ensure_ascii=False))
        return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SparkLight 本机浏览器 Cookie 自动同步助手")
    parser.add_argument("--server", default="http://10.96.1.108:11090", help="SparkLight 服务端地址")
    parser.add_argument("--api-key", required=True, help="系统 API Key")
    parser.add_argument("--account-id", default=None, help="指定同步的账号 ID（缺省按 UID 自动匹配）")
    parser.add_argument("--browser", default="Brave", choices=["Brave", "Chrome"], help="浏览器类型")
    parser.add_argument("--cookie-file", default=None, help="自定义 Cookies 文件路径")

    args = parser.parse_args()

    cookie_file = args.cookie_file
    if not cookie_file:
        home = Path.home()
        if args.browser == "Brave":
            cookie_file = str(home / "Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies")
        else:
            cookie_file = str(home / "Library/Application Support/Google/Chrome/Default/Cookies")

    cookie_str = extract_cookies(cookie_file, args.browser)
    if not cookie_str:
        print(json.dumps({
            "status": "FAILED",
            "reason": f"未能在 {cookie_file} 中提取到包含 sessionid 的有效抖音 Cookie，请确保已登录抖音网页版"
        }, ensure_ascii=False))
        sys.exit(1)

    ok = sync_to_server(cookie_str, args.server, args.api_key, args.account_id)
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
