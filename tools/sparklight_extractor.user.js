// ==UserScript==
// @name         SparkLight 抖音凭证一键全自动提取助手
// @namespace    https://sparklight.local/
// @version      2.2.4
// @description  一键全自动提取抖音完整登录凭证（包含 HttpOnly Cookie 与 Guard 签名私钥/票据），100% 纯本地复制，免除手动抓包
// @author       SparkLight
// @match        https://*.douyin.com/*
// @grant        GM_cookie
// @grant        GM.cookie
// @grant        GM_setClipboard
// @run-at       document-idle
// ==/UserScript==

(function () {
  'use strict';

  // 1. 轻量解析 PKCS8 P-256 私钥 PEM 为 32 字节 Scalar Hex
  function pemToScalarHex(pem) {
    if (!pem || typeof pem !== 'string') return '';
    try {
      const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      const binary = atob(b64);
      const der = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) der[i] = binary.charCodeAt(i);
      for (let i = 0; i < der.length - 33; i++) {
        if (der[i] === 0x04 && der[i + 1] === 0x20) {
          let hex = '';
          for (let j = i + 2; j < i + 34; j++) {
            hex += der[j].toString(16).padStart(2, '0');
          }
          return hex;
        }
      }
    } catch (_) {}
    return '';
  }

  // 1.2 解析 PKCS8/SPKI EC 公钥 PEM 为 65 字节 SEC1 未压缩公钥 Base64
  function pemToRawPubBase64(pem) {
    if (!pem || typeof pem !== 'string') return '';
    try {
      const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      const binary = atob(b64);
      if (binary.length < 65) return '';
      const raw = binary.slice(binary.length - 65);
      if (raw.charCodeAt(0) !== 0x04) return '';
      return btoa(raw);
    } catch (_) {}
    return '';
  }

  // 1.1 从 IndexedDB secure-store 兜底读取 Guard 凭证
  async function readSecureStoreFromIndexedDB() {
    return new Promise((resolve) => {
      try {
        const req = indexedDB.open('secure-store');
        req.onerror = () => resolve([]);
        req.onsuccess = (e) => {
          const db = e.target.result;
          if (!db.objectStoreNames.contains('cryptvalues')) return resolve([]);
          const tx = db.transaction('cryptvalues', 'readonly');
          const store = tx.objectStore('cryptvalues');
          const getAll = store.getAll();
          getAll.onsuccess = () => resolve(getAll.result || []);
          getAll.onerror = () => resolve([]);
        };
      } catch (_) {
        resolve([]);
      }
    });
  }

  // 2. 页面浮动轻提示 Toast
  function showToast(message, isSuccess = true, duration = 3000) {
    const existing = document.getElementById('sl-extractor-toast');
    if (existing) existing.remove();
    const toast = document.createElement('div');
    toast.id = 'sl-extractor-toast';
    toast.style.cssText = `
      position: fixed; top: 24px; left: 50%; transform: translateX(-50%);
      background: ${isSuccess ? '#059669' : '#b91c1c'}; color: #fff;
      padding: 12px 24px; border-radius: 9999px; font-size: 13px; font-weight: 600;
      box-shadow: 0 12px 36px rgba(0,0,0,0.35); z-index: 2147483647;
      pointer-events: none; transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      opacity: 0; display: flex; align-items: center; gap: 8px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      text-align: center; max-width: 90vw;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    requestAnimationFrame(() => {
      toast.style.opacity = '1';
      toast.style.transform = 'translateX(-50%) translateY(4px)';
    });
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(-50%) translateY(-8px)';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  // 3. 多重策略提取全量 Cookies（深度捕获 HttpOnly 的 sessionid）
  async function fetchAllCookies() {
    const cookieMap = {};

    const tryGmCookie = (details) => new Promise((resolve) => {
      let resolved = false;
      const done = (list) => {
        if (!resolved) {
          resolved = true;
          resolve(Array.isArray(list) ? list : []);
        }
      };
      setTimeout(() => done([]), 800); // 800ms 防挂起

      try {
        if (typeof GM_cookie !== 'undefined' && GM_cookie.list) {
          GM_cookie.list(details, (res, err) => {
            if (!err && res) done(res);
            else done([]);
          });
        } else if (typeof GM !== 'undefined' && GM.cookie && GM.cookie.list) {
          GM.cookie.list(details).then(done).catch(() => done([]));
        } else {
          done([]);
        }
      } catch (_) {
        done([]);
      }
    });

    // 广覆盖检索匹配
    const attempts = await Promise.all([
      tryGmCookie({ url: 'https://www.douyin.com/' }),
      tryGmCookie({ url: window.location.href }),
      tryGmCookie({ domain: 'douyin.com' }),
      tryGmCookie({ domain: '.douyin.com' }),
      tryGmCookie({ domain: 'www.douyin.com' }),
    ]);

    for (const list of attempts) {
      for (const item of list) {
        if (item && item.name && item.value) {
          cookieMap[item.name] = item.value;
        }
      }
    }

    // 合并 document.cookie
    if (document.cookie) {
      document.cookie.split(';').forEach((p) => {
        const idx = p.indexOf('=');
        if (idx > -1) {
          const k = p.slice(0, idx).trim();
          const v = p.slice(idx + 1).trim();
          if (k && !cookieMap[k]) cookieMap[k] = v;
        }
      });
    }

    return cookieMap;
  }

  // 4. 解析 cURL 字符串中的 Cookie
  function parseCurlCookie(text) {
    if (!text || typeof text !== 'string') return null;
    const trimmed = text.trim();
    if (trimmed.includes('-H ') || trimmed.includes('-b ') || trimmed.includes('--cookie')) {
      const m = trimmed.match(/-b\s+['"]([^'"]+)['"]/i) || trimmed.match(/-H\s+['"]cookie:\s*([^'"]+)['"]/i);
      if (m) return m[1].trim();
    }
    return null;
  }

  // 5. 核心全量提取与写入剪贴板
  async function performExtraction() {
    const cookieMap = await fetchAllCookies();
    let hasSession = !!(cookieMap['sessionid'] || cookieMap['sessionid_ss'] || cookieMap['sid_tt']);

    // 兜底：如果扩展限制未直接获取 sessionid，尝试检查剪贴板是否已有纯文本凭证
    if (!hasSession && navigator.clipboard && navigator.clipboard.readText) {
      try {
        const clip = await navigator.clipboard.readText();
        const curlCookie = parseCurlCookie(clip);
        if (curlCookie && (curlCookie.includes('sessionid=') || curlCookie.includes('sid_tt='))) {
          curlCookie.split(';').forEach((p) => {
            const idx = p.indexOf('=');
            if (idx > -1) {
              const k = p.slice(0, idx).trim();
              const v = p.slice(idx + 1).trim();
              if (k) cookieMap[k] = v;
            }
          });
          hasSession = true;
        }
      } catch (_) {}
    }

    const fullCookieStr = Object.entries(cookieMap).map(([k, v]) => `${k}=${v}`).join('; ');

    // 采集 Guard 密钥与票据材料（合并 localStorage 与 IndexedDB，严格选取 create_time 最新的有效材料）
    const candidateKeys = [];
    const candidateTickets = [];

    const parseTicketCandidate = (raw) => {
      if (!raw) return null;
      try {
        let p = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (p && typeof p === 'object' && p.data) {
          p = typeof p.data === 'string' ? JSON.parse(p.data) : p.data;
        }
        if (p && typeof p === 'object' && p.ticket && p.ts_sign && p.client_cert) {
          const pubB64 = p.client_cert.startsWith('pub.') ? p.client_cert.slice(4) : p.client_cert;
          return {
            ticket: p.ticket,
            ts_sign: p.ts_sign,
            client_cert: p.client_cert,
            pubB64: pubB64,
            log_id: p.log_id || '',
            create_time: Number(p.create_time) || 0,
          };
        }
      } catch (_) {}
      return null;
    };

    const parseKeyCandidate = (raw) => {
      if (!raw) return null;
      try {
        let p = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (p && typeof p === 'object' && p.data) {
          p = typeof p.data === 'string' ? JSON.parse(p.data) : p.data;
        }
        if (p && typeof p === 'object' && p.ec_privateKey) {
          const hex = pemToScalarHex(p.ec_privateKey);
          const pubB64 = pemToRawPubBase64(p.ec_publicKey);
          if (hex) {
            return {
              privHex: hex,
              pubPem: p.ec_publicKey || '',
              pubB64: pubB64,
            };
          }
        }
      } catch (_) {}
      return null;
    };

    // 0. 尝试通过当前页面的 securitySDK 获取最新的密钥与票据状态
    const win = typeof unsafeWindow !== 'undefined' ? unsafeWindow : (typeof window !== 'undefined' ? window : null);
    if (win && win.securitySDK) {
      try {
        if (typeof win.securitySDK.getBdTicketGuardHeader === 'function') {
          await win.securitySDK.getBdTicketGuardHeader({ path: '/v1/message/send' }).catch(() => null);
        }
        if (win.securitySDK.cryptoSDK && typeof win.securitySDK.cryptoSDK.getKeysInfo === 'function') {
          for (const certType of ['web_protect', 'cookie', 'login', 'default']) {
            const info = await win.securitySDK.cryptoSDK.getKeysInfo({ certType }).catch(() => null);
            if (info && info.crypt) {
              const k = parseKeyCandidate(info.crypt);
              if (k) {
                if (info.b64PubKey && !k.pubB64) k.pubB64 = info.b64PubKey;
                candidateKeys.push(k);
              }
            }
            if (info && info.sign && info.sign.ticket) {
              const t = parseTicketCandidate(info.sign);
              if (t) candidateTickets.push(t);
            }
          }
        }
      } catch (_) {}
    }

    // 1. 扫描 localStorage
    try {
      const cryptRaw = localStorage.getItem('security-sdk/s_sdk_crypt_sdk');
      const k = parseKeyCandidate(cryptRaw);
      if (k) candidateKeys.push(k);

      const signProtect = localStorage.getItem('security-sdk/s_sdk_sign_data_key/web_protect');
      const tProtect = parseTicketCandidate(signProtect);
      if (tProtect) candidateTickets.push(tProtect);

      const signLogin = localStorage.getItem('security-sdk/s_sdk_sign_data_key/login');
      const tLogin = parseTicketCandidate(signLogin);
      if (tLogin) candidateTickets.push(tLogin);
    } catch (_) {}

    // 1.1 扫描 Cookie 中的 server_data
    if (cookieMap['bd_ticket_guard_server_data']) {
      try {
        const decoded = decodeURIComponent(cookieMap['bd_ticket_guard_server_data']);
        const t = parseTicketCandidate(decoded);
        if (t) candidateTickets.push(t);
      } catch (_) {}
    }

    // 2. 扫描 IndexedDB secure-store (cryptvalues)
    try {
      const idbItems = await readSecureStoreFromIndexedDB();
      for (const item of idbItems) {
        const k = parseKeyCandidate(item);
        if (k) candidateKeys.push(k);
        const t = parseTicketCandidate(item);
        if (t) candidateTickets.push(t);
      }
    } catch (_) {}

    // 去重
    const uniqueKeys = [];
    const seenPriv = new Set();
    for (const k of candidateKeys) {
      if (k && k.privHex && !seenPriv.has(k.privHex)) {
        seenPriv.add(k.privHex);
        uniqueKeys.push(k);
      }
    }

    const uniqueTickets = [];
    const seenTickets = new Set();
    for (const t of candidateTickets) {
      if (t && t.ticket && !seenTickets.has(t.ticket)) {
        seenTickets.add(t.ticket);
        uniqueTickets.push(t);
      }
    }

    // 严格按公钥绑定匹配 (Key, Ticket) 组合，杜绝私钥与票据公钥不匹配
    uniqueTickets.sort((a, b) => b.create_time - a.create_time);
    let matchedPair = null;
    for (const t of uniqueTickets) {
      const matchKey = uniqueKeys.find((k) => k.pubB64 && k.pubB64 === t.pubB64);
      if (matchKey) {
        matchedPair = { key: matchKey, ticket: t };
        break;
      }
    }

    let guardPrivHex = '';
    let guardServerData = '';

    if (matchedPair) {
      guardPrivHex = matchedPair.key.privHex;
      guardServerData = JSON.stringify({
        ticket: matchedPair.ticket.ticket,
        ts_sign: matchedPair.ticket.ts_sign,
        client_cert: matchedPair.ticket.client_cert,
        log_id: matchedPair.ticket.log_id || '',
        create_time: matchedPair.ticket.create_time || 0,
      });
    } else if (uniqueKeys.length > 0) {
      // 存在私钥但未找到匹配的已下发票据（如浏览器自动轮换密钥），提取私钥但留空票据，由服务端发送时按规范协商
      guardPrivHex = uniqueKeys[0].privHex;
    }

    // 采集当前登录用户的标识与昵称
    let userInfo = { uid: '', nickname: '' };
    try {
      const res = await fetch('https://www.douyin.com/aweme/v1/web/user/profile/self/?aid=6383');
      const json = await res.json();
      if (json.user) {
        userInfo.uid = String(json.user.uid || '');
        userInfo.nickname = json.user.nickname || '';
      }
    } catch (_) {}

    if (!userInfo.nickname) {
      try {
        const res = await fetch('https://www.douyin.com/passport/account/info/v2/?aid=6383');
        const json = await res.json();
        if (json.data) {
          userInfo.uid = userInfo.uid || String(json.data.user_id || json.data.user_id_str || '');
          userInfo.nickname = json.data.screen_name || json.data.name || '';
        }
      } catch (_) {}
    }

    if (!hasSession) {
      showToast('⚠️ 未能读取 HttpOnly 凭证(sessionid)！请在油猴/ScriptCat扩展设置中开启 Cookie 访问权限，然后刷新抖音页面重试', false, 6000);
      return false;
    }

    // 组装全量凭证结构
    const payload = {
      type: 'sparklight_credential',
      version: '2.2.4',
      extracted_at: new Date().toISOString(),
      uid: userInfo.uid,
      nickname: userInfo.nickname,
      cookie: fullCookieStr,
      guard_private_key: guardPrivHex,
      guard_server_data: guardServerData,
    };

    const textToCopy = JSON.stringify(payload, null, 2);

    if (typeof GM_setClipboard !== 'undefined') {
      GM_setClipboard(textToCopy);
    } else if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(textToCopy);
    } else {
      prompt('请按 Cmd+C (或 Ctrl+C) 复制凭证：', textToCopy);
    }

    if (matchedPair) {
      showToast(`✅ 已成功复制「${userInfo.nickname || '抖音账号'}」全量凭证（已绑定 Guard 签名公钥 ${matchedPair.key.pubB64.slice(0, 8)}...）！请前往 SparkLight 控制台直接粘贴。`);
    } else if (guardPrivHex) {
      showToast(`⚠️ 已提取私钥，但安全票据尚未与当前公钥配对。建议在抖音网页点击对话或发送消息刷新票据后再提取！`, false, 5000);
    } else {
      showToast(`✅ 已成功复制「${userInfo.nickname || '抖音账号'}」Cookie 凭证！请前往 SparkLight 控制台直接粘贴。`);
    }
    return true;
  }

  // 6. 挂载页面右下角极简常驻胶囊按钮
  function mountCapsule() {
    if (document.getElementById('sl-extractor-capsule')) return;

    const btn = document.createElement('div');
    btn.id = 'sl-extractor-capsule';
    btn.innerHTML = '⚡ 复制 SparkLight 全量凭证';
    btn.style.cssText = `
      position: fixed; bottom: 32px; right: 32px; z-index: 2147483646;
      background: linear-gradient(135deg, #f97316 0%, #ea580c 100%);
      color: #fff; border: 1px solid rgba(255,255,255,0.25);
      border-radius: 9999px; padding: 10px 22px; font-size: 13px; font-weight: 600;
      cursor: pointer; box-shadow: 0 8px 24px -4px rgba(234, 88, 12, 0.45);
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      user-select: none; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      backdrop-filter: blur(8px);
    `;

    btn.onmouseenter = () => {
      btn.style.transform = 'translateY(-3px) scale(1.02)';
      btn.style.boxShadow = '0 12px 28px -4px rgba(234, 88, 12, 0.65)';
    };
    btn.onmouseleave = () => {
      btn.style.transform = 'translateY(0) scale(1)';
      btn.style.boxShadow = '0 8px 24px -4px rgba(234, 88, 12, 0.45)';
    };

    btn.onclick = async () => {
      const original = btn.innerHTML;
      btn.innerHTML = '⏳ 正在全量提取...';
      btn.style.pointerEvents = 'none';
      try {
        const ok = await performExtraction();
        btn.innerHTML = ok ? '✅ 复制成功！' : '⚠️ 缺少关键凭证';
      } catch (e) {
        showToast('提取异常: ' + e.message, false);
        btn.innerHTML = '⚠️ 提取异常';
      } finally {
        setTimeout(() => {
          btn.innerHTML = original;
          btn.style.pointerEvents = 'auto';
        }, 2500);
      }
    };

    document.body.appendChild(btn);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountCapsule);
  } else {
    mountCapsule();
  }
})();
