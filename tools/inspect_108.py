import struct, sqlite3, json, time, sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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
    out_words = x[0:4] + x[12:16]
    return struct.pack('<8I', *out_words)

def xchacha20poly1305_decrypt(key: bytes, ciphertext: bytes, aad: bytes = b'') -> bytes:
    nonce = ciphertext[:24]
    ct_tag = ciphertext[24:]
    subkey = hchacha20(key, nonce[:16])
    ietf_nonce = b'\x00\x00\x00\x00' + nonce[16:24]
    cipher = ChaCha20Poly1305(subkey)
    return cipher.decrypt(ietf_nonce, ct_tag, aad)

def main():
    key_hex = open('/opt/docker/sparklight/data/.master-key', 'r').read().strip()
    key = bytes.fromhex(key_hex)
    conn = sqlite3.connect('/opt/docker/sparklight/data/sparklight.db')
    c = conn.cursor()
    now = int(time.time())
    print(f'=== Current UNIX timestamp: {now} ===')

    accounts = c.execute('SELECT id, alias, uid, nickname, encrypted_cookie, status, updated_at FROM accounts').fetchall()
    for aid, alias, uid, nick, enc_cookie, status, updated_at in accounts:
        print('\n' + '=' * 60)
        print(f'Account ID: {aid}')
        print(f'Alias: {alias} | Nickname: {nick} | UID: {uid}')
        print(f'Status: {status} | Updated: {updated_at}')
        
        cookie_str = xchacha20poly1305_decrypt(key, enc_cookie).decode('utf-8', errors='ignore')
        cookie_dict = dict(item.strip().split('=', 1) for item in cookie_str.split(';') if '=' in item.strip())
        print(f'Cookie total items: {len(cookie_dict)}')
        for k in ['sessionid', 'sessionid_ss', 'sid_guard', 'uid_tt', 'passport_assist_user', 'passport_auth_mix_state', 'passport_csrf_token', 'passport_mfa_token', 'd_ticket', '_bd_ticket_crypt_cookie', 'bd_ticket_guard_client_web_domain', 'bd_ticket_guard_generate_ticket_time', 'bd_ticket_guard_regenerate_keys_time', 'x-web-secsdk-uid', 'x_tt_token', '__security_server_data_status', 'login_time']:
            val = cookie_dict.get(k)
            if val:
                if len(val) > 24:
                    print(f'  {k}: {val[:12]}...{val[-6:]} (len {len(val)})')
                else:
                    print(f'  {k}: {val}')
            else:
                print(f'  {k}: [NOT PRESENT]')
        
        ctx_row = c.execute('SELECT encrypted_context FROM account_web_contexts WHERE account_id=?', (aid,)).fetchone()
        if ctx_row:
            ctx_data = json.loads(xchacha20poly1305_decrypt(key, ctx_row[0]))
            print('Web Context:')
            print(f'  UID in ctx: {ctx_data.get("uid")}')
            print(f'  guard_secret_hex present: {bool(ctx_data.get("guard_secret_hex"))}')
            print(f'  guard_acquired_at: {ctx_data.get("guard_acquired_at")} (age: {now - ctx_data.get("guard_acquired_at", 0)}s)')
            print(f'  identity_acquired_at: {ctx_data.get("identity_acquired_at")} (age: {now - ctx_data.get("identity_acquired_at", 0)}s)')
            gsd = ctx_data.get('guard_server_data')
            if gsd:
                try:
                    sd = json.loads(gsd)
                    exp = sd.get('expire_time', 0)
                    rem = exp - now
                    print(f'  guard_server_data: expire_time={exp} (remaining={rem}s, {rem/3600:.2f}h), ticket_len={len(sd.get("ticket", ""))}')
                except:
                    print(f'  guard_server_data (raw): {gsd[:40]}...')
            else:
                print('  guard_server_data: NONE')
            print(f'  dtrait_pk1_pem present: {bool(ctx_data.get("dtrait_pk1_pem"))}')
        else:
            print('Web Context: NONE')

if __name__ == '__main__':
    main()
