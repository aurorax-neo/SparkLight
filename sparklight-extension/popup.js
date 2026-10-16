'use strict';

let detectedUser = null;
let currentFullCookie = '';

const serverUrlInput = document.getElementById('server-url');
const apiKeyInput = document.getElementById('api-key');
const syncBtn = document.getElementById('sync-btn');
const statusMsg = document.getElementById('status-msg');
const statusBadge = document.getElementById('status-badge');
const userNameEl = document.getElementById('user-name');
const userUidEl = document.getElementById('user-uid');
const userAvatar = document.getElementById('user-avatar');
const avatarPlaceholder = document.getElementById('avatar-placeholder');

// Load stored settings
chrome.storage.local.get(['sparkUrl', 'sparkApiKey'], (res) => {
  if (res.sparkUrl) serverUrlInput.value = res.sparkUrl;
  if (res.sparkApiKey) apiKeyInput.value = res.sparkApiKey;
});

serverUrlInput.addEventListener('change', () => {
  chrome.storage.local.set({ sparkUrl: serverUrlInput.value.trim() });
});
apiKeyInput.addEventListener('change', () => {
  chrome.storage.local.set({ sparkApiKey: apiKeyInput.value.trim() });
});

function showStatus(text, type) {
  statusMsg.style.display = 'block';
  statusMsg.innerText = text;
  if (type === 'success') {
    statusMsg.style.background = 'rgba(34, 197, 94, 0.2)';
    statusMsg.style.color = '#86efac';
    statusMsg.style.border = '1px solid rgba(34, 197, 94, 0.4)';
  } else if (type === 'error') {
    statusMsg.style.background = 'rgba(239, 68, 68, 0.2)';
    statusMsg.style.color = '#fca5a5';
    statusMsg.style.border = '1px solid rgba(239, 68, 68, 0.4)';
  } else {
    statusMsg.style.background = 'rgba(249, 115, 22, 0.2)';
    statusMsg.style.color = '#fdba74';
    statusMsg.style.border = '1px solid rgba(249, 115, 22, 0.4)';
  }
}

// 1. Read all cookies including HttpOnly
async function extractDouyinCookies() {
  const cookies = await chrome.cookies.getAll({ domain: 'douyin.com' });
  const map = new Map();
  for (const c of cookies) {
    if (c.name && c.value) {
      map.set(c.name, c.value);
    }
  }

  const parts = [];
  for (const [k, v] of map.entries()) {
    parts.push(`${k}=${v}`);
  }
  currentFullCookie = parts.join('; ');
  return { map, fullCookie: currentFullCookie };
}

// 2. Fetch User Profile
async function fetchUserInfo(cookieStr) {
  try {
    const res = await fetch('https://www.douyin.com/passport/account/info/v2/?aid=6383', {
      headers: {
        'Accept': 'application/json',
      },
      credentials: 'include'
    });
    if (!res.ok) return null;
    const json = await res.json();
    if (json.data && (json.data.user_id || json.data.user_id_str)) {
      return {
        uid: String(json.data.user_id || json.data.user_id_str),
        nickname: json.data.screen_name || json.data.name || '抖音用户',
        avatar_url: json.data.avatar_url || '',
        sec_uid: json.data.sec_user_id || '',
      };
    }
  } catch (e) {
    console.warn('Fetch user info error:', e);
  }
  return null;
}

// 3. Init on load
async function init() {
  const { map } = await extractDouyinCookies();
  const hasSession = map.has('sessionid');

  if (!hasSession) {
    statusBadge.className = 'badge badge-error';
    statusBadge.innerText = '未登录';
    userNameEl.innerText = '未检测到登录 Cookie';
    userUidEl.innerText = '请在当前浏览器打开 douyin.com 登录账号';
    syncBtn.disabled = true;
    return;
  }

  const user = await fetchUserInfo();
  if (user) {
    detectedUser = user;
    userNameEl.innerText = user.nickname;
    userUidEl.innerText = `UID: ${user.uid}`;
    if (user.avatar_url) {
      userAvatar.src = user.avatar_url;
      userAvatar.style.display = 'block';
      avatarPlaceholder.style.display = 'none';
    }
    statusBadge.className = 'badge badge-success';
    statusBadge.innerText = '已就绪';
    syncBtn.disabled = false;
  } else {
    userNameEl.innerText = '已读取会话凭证';
    userUidEl.innerText = 'sessionid 已就绪';
    statusBadge.className = 'badge badge-success';
    statusBadge.innerText = '已就绪';
    syncBtn.disabled = false;
  }
}

// 4. Sync action
syncBtn.addEventListener('click', async () => {
  const server = serverUrlInput.value.trim().replace(/\/+$/, '');
  const key = apiKeyInput.value.trim();

  if (!server) {
    showStatus('请输入 SparkLight 服务地址', 'error');
    return;
  }
  if (!key) {
    showStatus('请输入 API 授权密钥', 'error');
    return;
  }
  if (!currentFullCookie) {
    showStatus('未读取到有效 Cookie', 'error');
    return;
  }

  syncBtn.disabled = true;
  showStatus('正在连接 SparkLight 服务端...', 'info');

  try {
    chrome.storage.local.set({ sparkUrl: server, sparkApiKey: key });

    // Fetch existing accounts to find match
    const listRes = await fetch(`${server}/api/v1/accounts`, {
      headers: { 'X-API-Key': key }
    });
    if (!listRes.ok) throw new Error(`服务端鉴权失败 (HTTP ${listRes.status})`);
    const listJson = await listRes.json();
    const accounts = listJson.data || [];

    let matched = null;
    if (detectedUser) {
      matched = accounts.find(a => a.uid === detectedUser.uid || (detectedUser.sec_uid && a.sec_uid === detectedUser.sec_uid));
    }

    if (matched) {
      // Update existing account
      const updateRes = await fetch(`${server}/api/v1/accounts/${matched.id}`, {
        method: 'PUT',
        headers: {
          'X-API-Key': key,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ cookie: currentFullCookie })
      });
      const updateData = await updateRes.json();
      if (!updateRes.ok) throw new Error(updateData.message || '更新失败');
      showStatus(`同步成功！已更新账号「${matched.nickname || matched.alias}」凭证`, 'success');
    } else {
      // Create new account
      const alias = detectedUser ? detectedUser.nickname : '抖音账号';
      const createRes = await fetch(`${server}/api/v1/accounts`, {
        method: 'POST',
        headers: {
          'X-API-Key': key,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          alias,
          cookie: currentFullCookie
        })
      });
      const createData = await createRes.json();
      if (!createRes.ok) throw new Error(createData.message || '创建失败');
      showStatus(`同步成功！已成功添加账号「${alias}」`, 'success');
    }
  } catch (err) {
    showStatus(`同步失败: ${err.message}`, 'error');
  } finally {
    syncBtn.disabled = false;
  }
});

init();
