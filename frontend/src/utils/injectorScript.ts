/**
 * SparkLight - 抖音全自动凭证提取助手脚本模板（纯本地复制版）
 */
const INJECTOR_TEMPLATE: string = `/**
 * SparkLight - 抖音凭证一键全自动提取助手（纯控制台版）
 * 
 * 【使用方法】
 * 1. 在电脑浏览器登录抖音网页版 (https://www.douyin.com/user/self)
 * 2. 按 F12 (Mac: Cmd + Option + I) 打开开发者工具，切到 Console (控制台)
 * 3. 粘贴本脚本按回车运行，脚本将全自动提取完整凭证（含 Cookie 与 Guard 密钥）并复制到剪贴板！
 * 4. 返回 SparkLight 控制台直接粘贴即可导入。
 * 
 * 声明：100% 纯本地运行，零外部网络请求，仅做剪贴板复制。
 */

(async function () {
  'use strict';

  function pemToScalarHex(pem) {
    if (!pem || typeof pem !== 'string') return '';
    try {
      const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\\s+/g, '');
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

  console.log('%c[SparkLight]%c 正在提取抖音账号会话与 Guard 安全凭证...', 'color:#ea580c;font-weight:bold;', 'color:unset;');

  // 1. 采集 Cookie
  const cookieStr = document.cookie || '';

  // 2. 采集 Guard 密钥与票据
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
    const signLogin = localStorage.getItem('security-sdk/s_sdk_sign_data_key/login');
    const signProtect = localStorage.getItem('security-sdk/s_sdk_sign_data_key/web_protect');
    const chosen = signLogin || signProtect;
    if (chosen) {
      const parsed = JSON.parse(chosen);
      guardServerData = typeof parsed === 'string' ? parsed : JSON.stringify(parsed);
    }
  } catch (_) {}

  // 3. 探测用户身份
  let userInfo = { uid: '', nickname: '' };
  try {
    const res = await fetch('https://www.douyin.com/aweme/v1/web/user/profile/self/?aid=6383');
    const json = await res.json();
    if (json.user) {
      userInfo.uid = String(json.user.uid || '');
      userInfo.nickname = json.user.nickname || '';
    }
  } catch (_) {}

  const payload = {
    type: 'sparklight_credential',
    version: '2.0.0',
    extracted_at: new Date().toISOString(),
    uid: userInfo.uid,
    nickname: userInfo.nickname,
    cookie: cookieStr,
    guard_private_key: guardPrivHex,
    guard_server_data: guardServerData,
  };

  const textToCopy = JSON.stringify(payload, null, 2);

  let copySuccess = false;
  if (typeof copy === 'function') {
    try {
      copy(textToCopy);
      copySuccess = true;
    } catch (_) {}
  }

  if (!copySuccess && navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(textToCopy);
      copySuccess = true;
    } catch (_) {}
  }

  if (copySuccess) {
    console.log('%c[SparkLight] ✅ 全量凭证已成功复制到剪贴板！', 'color:#059669;font-weight:bold;font-size:14px;');
    console.log(\`账号: \${userInfo.nickname || '抖音账号'} (UID: \${userInfo.uid || '未知'})\`);
    console.log('请直接前往 SparkLight 控制台粘贴即可导入！');
  } else {
    console.log('%c[SparkLight] ⚠️ 未能直接写入剪贴板，请手动复制下方生成的凭证对象：', 'color:#d97706;font-weight:bold;');
    console.log(textToCopy);
  }
})();
`;

export function buildInjectorScript(_sparkUrl: string = '', _apiKey: string = '', _accountId: string = ''): string {
  return INJECTOR_TEMPLATE;
}
