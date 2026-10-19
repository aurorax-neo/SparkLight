#!/usr/bin/env python3
"""校验线上账号 _bd_ticket_crypt_cookie 与已保存 Guard 材料是否自洽。

官方公式（已在真实浏览器数据上验证）：
    _bd_ticket_crypt_cookie = MD5(JSON.stringify({
        publicKey: <客户端 EC 公钥 SPKI PEM>,
        cert:      <bd_ticket_guard_server_data.client_cert>,
        serverData:<bd_ticket_guard_server_data 原始字符串>,
    }))
"""
import base64
import copy
import hashlib
import json
import struct
import sqlite3
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DATA_DIR = '/opt/docker/sparklight/data'


def _rotl32(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def _quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = _rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = _rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = _rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = _rotl32(x[b] ^ x[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = list(struct.unpack('<8I', key))
    n = list(struct.unpack('<4I', nonce16))
    x = constants + k + n
    for _ in range(10):
        _quarter_round(x, 0, 4, 8, 12)
        _quarter_round(x, 1, 5, 9, 13)
        _quarter_round(x, 2, 6, 10, 14)
        _quarter_round(x, 3, 7, 11, 15)
        _quarter_round(x, 0, 5, 10, 15)
        _quarter_round(x, 1, 6, 11, 12)
        _quarter_round(x, 2, 7, 8, 13)
        _quarter_round(x, 3, 4, 9, 14)
    return struct.pack('<8I', *(x[0:4] + x[12:16]))


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    nonce = ciphertext[:24]
    subkey = hchacha20(key, nonce[:16])
    return ChaCha20Poly1305(subkey).decrypt(b'\x00\x00\x00\x00' + nonce[16:24], ciphertext[24:], b'')


def parse_cookie(cookie: str) -> dict:
    out = {}
    for item in cookie.split(';'):
        item = item.strip()
        if '=' in item:
            k, v = item.split('=', 1)
            out[k.strip()] = v.strip()
    return out


def public_key_base64(secret_hex: str) -> str:
    scalar = int(secret_hex, 16)
    priv = ec.derive_private_key(scalar, ec.SECP256R1())
    raw = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return base64.b64encode(raw).decode()


def spki_pem(pub_b64: str) -> str:
    raw = base64.b64decode(pub_b64)
    # P-256 SPKI 固定 26 字节头部，缺失它会导致 MD5 与官方不一致
    spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + raw
    return '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(spki).decode() + '\n-----END PUBLIC KEY-----'


def compute(pub_b64: str, client_cert: str, server_data_raw: str) -> str:
    # 必须严格按官方字段顺序 publicKey -> cert -> serverData
    payload = json.dumps(
        {
            'publicKey': spki_pem(pub_b64),
            'cert': client_cert,
            'serverData': server_data_raw,
        },
        separators=(',', ':'),
    )
    return hashlib.md5(payload.encode()).hexdigest()


def client_cert_public_key(cert: str) -> str:
    return base64.b64encode(base64.b64decode(cert.split('.', 1)[1])).decode()


def main() -> int:
    key = bytes.fromhex(open(f'{DATA_DIR}/.master-key').read().strip())
    conn = sqlite3.connect(f'{DATA_DIR}/sparklight.db')
    rows = conn.execute(
        'SELECT id, alias, uid, encrypted_cookie, status FROM accounts'
    ).fetchall()
    exit_code = 0
    for aid, alias, uid, enc_cookie, status in rows:
        cookie = parse_cookie(decrypt(key, enc_cookie).decode('utf-8', 'ignore'))
        actual = cookie.get('_bd_ticket_crypt_cookie')
        ctx_row = conn.execute(
            'SELECT encrypted_context FROM account_web_contexts WHERE account_id=?', (aid,)
        ).fetchone()
        print('=' * 68)
        print(f'{alias} | uid={uid} | status={status}')
        if not ctx_row:
            print('  web context: NONE')
            continue
        ctx = json.loads(decrypt(key, ctx_row[0]))
        server_data_raw = ctx.get('guard_server_data')
        secret_hex = ctx.get('guard_secret_hex')
        if not server_data_raw or not secret_hex:
            print('  guard material: NONE')
            continue
        sd = json.loads(server_data_raw)
        cert = sd.get('client_cert', '')
        derived_pub = public_key_base64(secret_hex)
        bound_pub = client_cert_public_key(cert) if cert.startswith('pub.') else ''
        expected = compute(derived_pub, cert, server_data_raw)
        expected_from_cert = compute(bound_pub, cert, server_data_raw)
        print(f'  cookie hash : {actual}')
        print(f'  rehash(key) : {expected}')
        print(f'  rehash(cert): {expected_from_cert}')
        print(f'  key==cert   : {derived_pub == bound_pub}')
        print(f'  ALIGNED     : {actual == expected}')
        if actual != expected:
            exit_code = 1
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
