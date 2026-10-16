// ==UserScript==
// @name         SparkLight 抖音凭证一键全自动提取助手
// @namespace    https://sparklight.local/
// @version      2.2.1
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

    // 采集 Guard 密钥与票据材料
    let guardPrivHex = '';
    let guardServerData = '';

    try {
      const cryptRaw = localStorage.getItem('security-sdk/s_sdk_crypt_sdk');
      if (cryptRaw) {
        const cryptObj = JSON.parse(JSON.parse(cryptRaw).data || '{}');
        if (cryptObj.ec_privateKey) {
          guardPrivHex = pemToScalarHex(cryptObj.ec_privateKey);
        }
      }
    } catch (_) {}

    try {
      // 优先从活跃的 web_protect 获取最新票据，若不存在再回退到 login
      const signProtect = localStorage.getItem('security-sdk/s_sdk_sign_data_key/web_protect');
      const signLogin = localStorage.getItem('security-sdk/s_sdk_sign_data_key/login');

      const parseTicketObj = (raw) => {
        if (!raw) return null;
        try {
          let p = JSON.parse(raw);
          if (p && typeof p === 'object' && p.data) {
            p = typeof p.data === 'string' ? JSON.parse(p.data) : p.data;
          } else if (typeof p === 'string') {
            p = JSON.parse(p);
          }
          if (p && typeof p === 'object' && p.ticket && p.ts_sign && p.client_cert) {
            return p;
          }
        } catch (_) {}
        return null;
      };

      const protectTicket = parseTicketObj(signProtect);
      const loginTicket = parseTicketObj(signLogin);
      let chosenObj = protectTicket;
      if (!chosenObj || (loginTicket && (loginTicket.create_time || 0) > (chosenObj.create_time || 0))) {
        chosenObj = loginTicket || chosenObj;
      }

      if (chosenObj) {
        guardServerData = JSON.stringify({
          ticket: chosenObj.ticket,
          ts_sign: chosenObj.ts_sign,
          client_cert: chosenObj.client_cert,
          log_id: chosenObj.log_id || '',
          create_time: chosenObj.create_time || 0
        });
      }
    } catch (_) {}

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
      version: '2.2.0',
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

    showToast(`✅ 已成功复制「${userInfo.nickname || '抖音账号'}」全量凭证（含 Cookie 与 Guard 私钥）！请前往 SparkLight 控制台直接粘贴。`);
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
