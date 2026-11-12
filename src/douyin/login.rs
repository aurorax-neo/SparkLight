//! 抖音 App 二维码登录。
//!
//! 登录只在 Rust 进程内完成：服务端直连官方 Passport 接口，使用账号独占的原生设备参数
//! 和独立 Cookie Jar。这里不启动浏览器、不读取用户日常浏览器资料，也不接受手工粘贴 Cookie。

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use reqwest::{
    Client, Method,
    cookie::{CookieStore, Jar},
    header,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

use super::{
    client::{DouyinClient, merge_cookies},
    im_auth::sid_guard_expiry,
    types::DouyinUserProfile,
};

pub const LOGIN_SESSION_TTL_SECS: i64 = 60;
const LOGIN_CHALLENGE_TTL_SECS: i64 = 10 * 60;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
// 1049 归因（2026-10-29）：该错误由手机端抖音判定，文案是“应用版本过低或
// 经非官方渠道下载”。抖音正式版在 2026-10-20 已更新到 40.8.0，扫码登录对
// 发起端版本有下限；此前用 38.7.0 身份复现 1049。客户端身份统一对齐 40.8.0。
const APP_VERSION_CODE: &str = "400801";
const APP_PACKAGE_VERSION_CODE: &str = "400801";
const APP_VERSION_NAME: &str = "40.8.0";
const APP_UPDATE_VERSION_CODE: &str = "40809900";
const APP_VERSION_CODE_INT: i64 = 400801;
const APP_UPDATE_VERSION_CODE_INT: i64 = 40809900;
const APP_PACKAGE_VERSION_CODE_INT: i64 = 400801;
const APP_CHANNEL: &str = "update";
const PASSPORT_SDK_VERSION: &str = "60760";
const QR_GET_SERVICE: &str = "https://aweme.snssdk.com";
const QR_CHECK_SERVICE: &str = "https://aweme.snssdk.com";
// 108 实测：source 是登录发起的准入开关之一。空值会让 get_qrcode 返回 de=11
// “此功能不支持当前app”，只有 source=pad 能出二维码。设备形状与 source 保持
// 一致：source=pad 时必须配 Pixel Tablet 平板画像，混合形状会被确认环节拒绝。
const QR_SOURCE: &str = "pad";
const DEVICE_BRAND: &str = "Xiaomi";
const DEVICE_TYPE: &str = "23127PN0CC";
/// 原生手机端机型展示名（真机 Build.MODEL 的人类可读形式）。
const DEVICE_DISPLAY_MODEL: &str = "Xiaomi 14";
const DEVICE_MANUFACTURER: &str = "Xiaomi";
const DEVICE_OS_VERSION: &str = "14";
const DEVICE_RESOLUTION: &str = "1200*2670";
const IS_ANDROID_PAD: &str = "0";
const MAX_LOGIN_REDIRECTS: usize = 8;
const MAX_BARE_BUSY_POLLS: u32 = 6;
const DEVICE_REGISTER_URL: &str = "https://log.snssdk.com/service/2/device_register/";
/// 官方登记接口会限流，这里允许少量带退避的重试。QR 登录已回到 Oct-22
/// 可登录版，不依赖登记号；登记结果仅用于导入会话的续期探针。
const DEVICE_REGISTER_ATTEMPTS: u32 = 3;
const DEVICE_DISPLAY_NAME: &str = "抖音";
/// 官方 APK 签名证书 DER 的 MD5。RegistrationHeaderHelper 用签名证书字节算 MD5 上报 sig_hash，
/// 服务端据此区分官方渠道与改造包；缺失时登录类 Passport 接口按“非官方渠道”拒绝（4044/1049）。
const APK_SIG_HASH: &str = "aea615ab910015038f73c47e45d21466";

#[derive(Clone, Serialize, Deserialize)]
pub struct NativeDevice {
    pub device_id: String,
    pub install_id: String,
    pub openudid: String,
    pub cdid: String,
    pub aid: String,
    pub app_name: String,
    pub app_version: String,
    pub version_code: String,
    pub device_platform: String,
    pub channel: String,
    pub package: String,
    pub user_agent: String,
    /// 官方 device_register 下发的设备令牌。DeviceRegisterManager 把它作为 `x-tt-dt`
    /// 头附在每一个 Passport 请求上；缺失时服务端按“来源设备无法识别”拒绝扫码确认。
    #[serde(default)]
    pub device_token: Option<String>,
}

impl NativeDevice {
    pub fn derive(account_id: &str) -> Self {
        let seed = if std::env::var("SPARK_PROBE_RANDOM_DEVICE").is_ok() {
            format!("sparklight-native-device:v3:rand:{}", uuid::Uuid::new_v4())
        } else {
            format!("sparklight-native-device:v3:{APP_VERSION_CODE}:{APP_CHANNEL}:{account_id}")
        };
        let digest = Sha256::digest(seed.as_bytes());
        let cdid_digest = Sha256::digest(digest);
        let mut first = [0_u8; 8];
        first.copy_from_slice(&digest[..8]);
        let mut second = [0_u8; 8];
        second.copy_from_slice(&digest[8..16]);
        let device_id = u64::from_be_bytes(first).max(1).to_string();
        let install_id = u64::from_be_bytes(second).max(1).to_string();
        let openudid = hex::encode(&digest[16..24]);
        let cdid = hex::encode(&cdid_digest[..16]);
        Self {
            device_id,
            install_id,
            openudid,
            cdid,
            aid: "1128".to_string(),
            app_name: "aweme".to_string(),
            app_version: APP_VERSION_NAME.to_string(),
            version_code: APP_VERSION_CODE.to_string(),
            device_platform: "android".to_string(),
            channel: APP_CHANNEL.to_string(),
            package: "com.ss.android.ugc.aweme".to_string(),
            user_agent: format!(
                "com.ss.android.ugc.aweme/{APP_PACKAGE_VERSION_CODE} (Linux; U; Android {DEVICE_OS_VERSION}; zh_CN; {DEVICE_DISPLAY_MODEL}; Build/UKQ1.231003.002)"
            ),
            device_token: None,
        }
    }

    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("device_id", self.device_id.as_str()),
            ("install_id", self.install_id.as_str()),
            ("openudid", self.openudid.as_str()),
            ("cdid", self.cdid.as_str()),
            ("aid", self.aid.as_str()),
            ("app_name", self.app_name.as_str()),
            ("version_code", self.version_code.as_str()),
            ("user_agent", self.user_agent.as_str()),
        ] {
            ensure!(!value.trim().is_empty(), "原生设备字段 {name} 为空");
        }
        ensure!(self.device_id.len() <= 64, "原生 device_id 超长");
        ensure!(self.install_id.len() <= 64, "原生 install_id 超长");
        ensure!(self.user_agent.len() <= 1024, "原生 User-Agent 超长");
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NativeSessionRecord {
    pub device: NativeDevice,
    pub cookie: String,
    pub uid: String,
    pub sec_uid: String,
    pub nickname: String,
    pub avatar_url: String,
    #[serde(default)]
    pub mobile: String,
    #[serde(default)]
    pub session_key: Option<String>,
    #[serde(default)]
    pub d_ticket: Option<String>,
    #[serde(default)]
    pub x_tt_token: Option<String>,
    #[serde(default)]
    pub token_encrypted: Option<String>,
    #[serde(default)]
    pub ts_sign: Option<String>,
    #[serde(default)]
    pub attest_ts_sign: Option<String>,
    #[serde(default)]
    pub mfa_token: Option<String>,
    #[serde(default)]
    pub guard_key_hex: Option<String>,
    #[serde(default)]
    pub guard_server_data: Option<String>,
    #[serde(default)]
    pub dtrait_pk1_pem: Option<String>,
    #[serde(default)]
    pub dtrait_version: Option<String>,
    #[serde(default)]
    pub logged_in_at: i64,
    pub last_verified_at: Option<i64>,
    pub last_beat_at: Option<i64>,
}

impl NativeSessionRecord {
    pub fn profile(&self) -> DouyinUserProfile {
        DouyinUserProfile {
            uid: self.uid.clone(),
            sec_uid: self.sec_uid.clone(),
            nickname: self.nickname.clone(),
            avatar_url: self.avatar_url.clone(),
        }
    }

    pub fn sid_expiry(&self) -> Option<i64> {
        sid_guard_expiry(&self.cookie)
    }

    pub fn validate(&self) -> Result<()> {
        self.device.validate()?;
        ensure!(
            self.uid.parse::<u64>().ok().is_some_and(|uid| uid > 0),
            "原生登录 UID 无效"
        );
        ensure!(!self.cookie.trim().is_empty(), "原生登录 Cookie 为空");
        ensure!(!self.sec_uid.trim().is_empty(), "原生登录缺少 sec_user_id");
        ensure!(
            self.cookie.len() <= 64 * 1024,
            "原生登录 Cookie 超出安全上限"
        );
        Ok(())
    }
}

impl std::fmt::Debug for NativeSessionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSessionRecord")
            .field("device_id", &self.device.device_id)
            .field("uid", &self.uid)
            .field("logged_in_at", &self.logged_in_at)
            .field("last_verified_at", &self.last_verified_at)
            .field("last_beat_at", &self.last_beat_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct LoginSession {
    pub id: String,
    pub account_id: String,
    pub alias: String,
    pub qrcode: String,
    pub expires_at: i64,
    token: String,
    device: NativeDevice,
    jar: Arc<Jar>,
    client: Client,
    verification: Arc<Mutex<Option<LoginVerification>>>,
    scan_profile: Arc<Mutex<Option<ScanProfile>>>,
    seen_scan: Arc<AtomicBool>,
    busy_polls: Arc<AtomicU32>,
}

impl LoginSession {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.session_expires_at()
    }

    pub fn qr_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    pub fn session_expires_at(&self) -> i64 {
        self.verification_snapshot()
            .map_or(self.expires_at, |verification| verification.expires_at)
    }

    pub fn has_verification(&self) -> bool {
        self.verification_snapshot().is_some()
    }

    pub fn qr_token(&self) -> &str {
        &self.token
    }

    pub async fn shutdown(&mut self) {
        // 纯 Rust 会话没有外部进程；保留该接口便于幂等清理。
        self.clear_verification();
    }

    fn verification_snapshot(&self) -> Option<LoginVerification> {
        self.verification
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn store_verification(&self, verification: LoginVerification) {
        *self
            .verification
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(verification);
    }

    fn update_verification(
        &self,
        update: impl FnOnce(&mut LoginVerification),
    ) -> Option<LoginVerification> {
        let mut guard = self
            .verification
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let verification = guard.as_mut()?;
        update(verification);
        Some(verification.clone())
    }

    fn note_scan(&self, root: &Value, status: &str) {
        let normalized = normalize_qr_status(status);
        let has_scan_info = root
            .get("data")
            .and_then(Value::as_object)
            .is_some_and(|data| data.contains_key("scan_user_info"));
        if normalized == "scanned" || has_scan_info {
            self.seen_scan.store(true, Ordering::Relaxed);
        }
        if let Some(profile) = scan_profile_from_response(root) {
            self.merge_scan_profile(profile);
            self.seen_scan.store(true, Ordering::Relaxed);
        }
    }

    fn merge_scan_profile(&self, incoming: ScanProfile) {
        let mut guard = self
            .scan_profile
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_mut() {
            Some(existing) => {
                if incoming.name.is_some() {
                    existing.name = incoming.name;
                }
                if incoming.avatar_url.is_some() {
                    existing.avatar_url = incoming.avatar_url;
                }
            }
            None => *guard = Some(incoming),
        }
    }

    fn scan_profile_snapshot(&self) -> Option<ScanProfile> {
        self.scan_profile
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn with_scan_profile(&self, mut verification: LoginVerification) -> LoginVerification {
        if let Some(profile) = self.scan_profile_snapshot() {
            if verification.profile_name.is_none() {
                verification.profile_name = profile.name;
            }
            if verification.avatar_url.is_none() {
                verification.avatar_url = profile.avatar_url;
            }
        }
        verification
    }

    fn clear_verification(&self) {
        *self
            .verification
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

#[derive(Debug, Clone)]
pub struct ConfirmedLogin {
    pub record: NativeSessionRecord,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum LoginPoll {
    Pending {
        status: String,
        challenge: Option<LoginChallenge>,
    },
    Confirmed(ConfirmedLogin),
    Terminal {
        status: String,
        message: String,
    },
}

/// 抖音二维码风控挑战。仅在官方返回 `captcha`/`desc_url` 或
/// `verify_ticket` + `auth_ways_data` 时生成；不能从普通错误文本推断。
#[derive(Debug, Clone)]
pub enum LoginChallenge {
    /// App 通过 `/passport/authentication/index/` 承载的二次验证。
    Web {
        url: String,
        decision_config: Option<String>,
    },
    /// App 原生二次验证列表，票据只留在 Rust 进程内。
    TwoStep {
        ways: Vec<LoginVerifyWay>,
        masked_mobile: Option<String>,
        profile_name: Option<String>,
        avatar_url: Option<String>,
        ticket_ready: bool,
        scene_description: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoginChallengeView {
    Web {
        url: String,
    },
    TwoStep {
        ways: Vec<LoginVerifyWay>,
        masked_mobile: Option<String>,
        profile_name: Option<String>,
        avatar_url: Option<String>,
        ticket_ready: bool,
        scene_description: Option<String>,
    },
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LoginVerifyWay {
    pub kind: String,
    pub label: String,
    pub masked_mobile: Option<String>,
    pub supported: bool,
    pub description: Option<String>,
}

impl LoginChallenge {
    pub fn view(&self) -> LoginChallengeView {
        match self {
            Self::Web { url, .. } => LoginChallengeView::Web { url: url.clone() },
            Self::TwoStep {
                ways,
                masked_mobile,
                profile_name,
                avatar_url,
                ticket_ready,
                scene_description,
            } => LoginChallengeView::TwoStep {
                ways: ways.clone(),
                masked_mobile: masked_mobile.clone(),
                profile_name: profile_name.clone(),
                avatar_url: avatar_url.clone(),
                ticket_ready: *ticket_ready,
                scene_description: scene_description.clone(),
            },
        }
    }
}

impl LoginChallengeView {
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::Web { url } => Some(url),
            Self::TwoStep { .. } => None,
        }
    }
}

#[derive(Clone)]
struct LoginVerification {
    verify_ticket: Option<String>,
    ways: Vec<VerificationWay>,
    sms_code_key: Option<String>,
    auth_ticket: Option<String>,
    profile_key: Option<String>,
    profile_name: Option<String>,
    avatar_url: Option<String>,
    scene_description: Option<String>,
    expires_at: i64,
}

#[derive(Clone, Default)]
struct ScanProfile {
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Clone, Default)]
struct VerificationWay {
    public: LoginVerifyWay,
    auth_ticket: Option<String>,
    sms_content: Option<String>,
    channel_mobile: Option<String>,
    scene: Option<String>,
    cert_app_id: Option<String>,
    flow: Option<String>,
    act_type: Option<i64>,
    is_oper_staff_user: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationDelivery {
    pub kind: String,
    pub sms_content: Option<String>,
    pub channel_mobile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qrcode: Option<String>,
}

#[derive(Clone)]
enum PendingWebLoginAction {
    Sms { code: String },
    Password { password: String },
}

#[derive(Clone, Default)]
struct WebSecondVerifyState {
    verify_portrait_id: String,
    encrypt_uid: Option<String>,
    verify_ticket: Option<String>,
    up_verify_ticket: Option<String>,
    auth_ticket: Option<String>,
    sms_code_key: Option<String>,
    common_params: Vec<(String, String)>,
    verify_scene: Option<String>,
    verify_reason: Option<String>,
    biz_params: Vec<(String, String)>,
    replay_headers: Vec<(String, String)>,
    ways: Vec<VerificationWay>,
    push_token: Option<String>,
    qr_token: Option<String>,
    qr_image: Option<String>,
    sec_user_id: Option<String>,
    scene_description: Option<String>,
    pending_action: Option<PendingWebLoginAction>,
}

pub enum PhoneLoginOutcome {
    Confirmed(ConfirmedLogin),
    NeedSecondVerify {
        session: PhoneLoginSession,
        challenge: LoginChallengeView,
        message: String,
    },
}

/// 官方手机版 App 的主登录方式：手机号 + 短信验证码。
///
/// 手机版 App 没有扫码登录入口（`LoginFlowFactory` 里 QR 被 `isPad()` 门控，
/// 只有平板版才有），因此对齐手机版就必须走 `/passport/mobile/send_code/`
/// 与 `/passport/mobile/sms_login/`。
#[derive(Clone)]
pub struct PhoneLoginSession {
    pub id: String,
    pub account_id: String,
    pub alias: String,
    pub expires_at: i64,
    mobile: String,
    web_mobile: String,
    csrf_token: String,
    verify_fp: String,
    guard_key_hex: String,
    dtrait_bytes: Vec<u8>,
    browser_info_enc: String,
    sms_code_key: Option<String>,
    ticket: Option<String>,
    second_verify: Arc<Mutex<Option<WebSecondVerifyState>>>,
    device: NativeDevice,
    jar: Arc<Jar>,
    client: Client,
}

impl PhoneLoginSession {
    pub fn mobile_masked(&self) -> String {
        let value = self.mobile.trim();
        if value.len() < 7 {
            return "***".to_string();
        }
        format!("{}****{}", &value[..3], &value[value.len() - 4..])
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }
}

pub fn normalize_cn_mobile(raw: &str) -> Result<(String, String)> {
    let compact = raw
        .trim()
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .collect::<String>();
    let digits = compact
        .strip_prefix("+86")
        .or_else(|| compact.strip_prefix("0086"))
        .or_else(|| {
            (compact.len() == 13 && compact.starts_with("86")).then(|| &compact[2..])
        })
        .unwrap_or(compact.as_str());
    ensure!(
        digits.len() == 11 && digits.starts_with('1') && digits.bytes().all(|b| b.is_ascii_digit()),
        "请输入有效的 11 位中国大陆手机号"
    );
    Ok((digits.to_string(), format!("+86{digits}")))
}

const WEB_LOGIN_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const WEB_BDMS_SCRIPT: &str = include_str!("sdk/bdms_1.0.1.19_fix.js");
const WEB_ABOGUS_SHIM: &str = include_str!("sdk/abogus_research.js");
const WEB_QR_SVG_SCRIPT: &str = include_str!("sdk/qrcode_svg.js");
const WEB_NEW_AUTHN_SDK_VERSION: &str = "1.0.0.428-web";
const WEB_JS_PRELUDE: &str = r#"
var window=globalThis,self=globalThis,global=globalThis,top=globalThis,JS_SHA256_NO_NODE_JS=true;
var console={log:function(){},warn:function(){},error:function(){}};
var _b64chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
function btoa(input){
  var str=String(input),output="";
  for(var block=0,charCode,i=0,map=_b64chars;str.charAt(i|0)||(map="=",i%1);output+=map.charAt(63&block>>8-i%1*8)){
    charCode=str.charCodeAt(i+=3/4);
    if(charCode>0xff)throw new Error("btoa invalid char");
    block=block<<8|charCode;
  }
  return output;
}
function atob(input){
  var str=String(input).replace(/[=\s]+$/,""),output="";
  for(var bc=0,bs=0,buffer,i=0;buffer=str.charAt(i++);~buffer&&(bs=bc%4?bs*64+buffer:buffer,bc++%4)?output+=String.fromCharCode(255&bs>>(-2*bc&6)):0){
    buffer=_b64chars.indexOf(buffer);
  }
  return output;
}
function TextEncoder(){}
TextEncoder.prototype.encode=function(str){
  str=String(str);
  var out=[];
  for(var i=0;i<str.length;i++){
    var c=str.charCodeAt(i);
    if(c<0x80)out.push(c);
    else if(c<0x800)out.push(0xc0|(c>>6),0x80|(c&0x3f));
    else if(c<0xd800||c>=0xe000)out.push(0xe0|(c>>12),0x80|((c>>6)&0x3f),0x80|(c&0x3f));
    else{i++;c=0x10000+(((c&0x3ff)<<10)|(str.charCodeAt(i)&0x3ff));out.push(0xf0|(c>>18),0x80|((c>>12)&0x3f),0x80|((c>>6)&0x3f),0x80|(c&0x3f));}
  }
  return new Uint8Array(out);
};
function TextDecoder(){}
TextDecoder.prototype.decode=function(bytes){
  if(!bytes)return "";
  var u8=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes),out="";
  for(var i=0;i<u8.length;){
    var c=u8[i++];
    if(c<0x80)out+=String.fromCharCode(c);
    else if((c&0xe0)===0xc0)out+=String.fromCharCode(((c&0x1f)<<6)|(u8[i++]&0x3f));
    else if((c&0xf0)===0xe0)out+=String.fromCharCode(((c&0x0f)<<12)|((u8[i++]&0x3f)<<6)|(u8[i++]&0x3f));
    else{var cp=((c&0x07)<<18)|((u8[i++]&0x3f)<<12)|((u8[i++]&0x3f)<<6)|(u8[i++]&0x3f)-0x10000;out+=String.fromCharCode(0xd800+(cp>>10),0xdc00+(cp&0x3ff));}
  }
  return out;
};
function parseSimpleUrl(raw){
  var s=String(raw||"");
  if(s.indexOf("//")===0)s="https:"+s;
  else if(s.indexOf("/")===0)s="https://www.douyin.com"+s;
  else if(!/^https?:/i.test(s))s="https://www.douyin.com/"+s;
  var m=s.match(/^(https?:)\/\/([^\/?#]+)([^?#]*)(\?[^#]*)?(#.*)?$/i);
  if(!m)return {href:s,protocol:"https:",host:"www.douyin.com",hostname:"www.douyin.com",port:"",pathname:"/",search:"",hash:"",origin:"https://www.douyin.com"};
  var protocol=m[1].toLowerCase(),host=m[2],hostname=host.split(":")[0],port=host.split(":")[1]||"",pathname=m[3]||"/",search=m[4]||"",hash=m[5]||"";
  return {href:s,protocol:protocol,host:host,hostname:hostname,port:port,pathname:pathname,search:search,hash:hash,origin:protocol+"//"+host};
}
function SyncPromise(fn){
  var state=0,val=undefined;
  function resolve(v){
    if(state!==0)return;
    if(v&&(typeof v==="object"||typeof v==="function")&&typeof v.then==="function"){v.then(resolve,reject);return;}
    state=1;val=v;
  }
  function reject(e){if(state===0){state=2;val=e;}}
  try{fn(resolve,reject);}catch(e){reject(e);}
  this._s=state;this._v=val;
}
SyncPromise.prototype.then=function(onFulfilled,onRejected){
  var self=this;
  return new SyncPromise(function(res,rej){
    if(self._s===1){
      if(typeof onFulfilled==="function"){try{res(onFulfilled(self._v));}catch(e){rej(e);}}
      else res(self._v);
    }else if(self._s===2){
      if(typeof onRejected==="function"){try{res(onRejected(self._v));}catch(e){rej(e);}}
      else rej(self._v);
    }
  });
};
SyncPromise.prototype.catch=function(onRejected){return this.then(null,onRejected);};
SyncPromise.resolve=function(v){return new SyncPromise(function(res){res(v);});};
SyncPromise.reject=function(e){return new SyncPromise(function(_,rej){rej(e);});};
SyncPromise.all=function(arr){
  return new SyncPromise(function(res,rej){
    var out=[],rem=arr.length;
    if(rem===0){res(out);return;}
    for(var i=0;i<arr.length;i++)(function(idx){
      SyncPromise.resolve(arr[idx]).then(function(v){out[idx]=v;if(--rem===0)res(out);},rej);
    })(i);
  });
};
"#;

const WEB_FP_JSON: &str = r#"{"fonts":"[\"Arial Unicode MS\",\"Calibri\",\"Century\",\"Century Gothic\",\"Futura Bk BT\",\"Gill Sans\",\"HELV\",\"Helvetica Neue\",\"Lucida Bright\",\"Lucida Sans\",\"Menlo\",\"MS Mincho\",\"MS Outlook\",\"MS Reference Specialty\",\"MS UI Gothic\",\"MT Extra\",\"Marlett\",\"Meiryo UI\",\"Microsoft Uighur\",\"Minion Pro\",\"Monotype Corsiva\",\"PMingLiU\",\"Pristina\",\"SCRIPTINA\",\"Segoe UI Light\",\"Serifa\",\"SimHei\",\"Small Fonts\",\"Staccato222 BT\",\"TRAJAN PRO\",\"Univers CE 55 Medium\",\"Vrinda\",\"ZWAdobeF\"]","fontPreferences":"{\"default\":149.40625,\"apple\":149.40625,\"serif\":149.40625,\"sans\":145.671875,\"mono\":123.2265625,\"min\":9.5859375,\"system\":147.625}","canvas":"{\"winding\":true,\"geometry\":\"5292599e1a367e4d3a7f57ce39543286\",\"text\":\"6d86be4fc98cf1e1a4a24d34f920bd90\"}","osCpu":"","languages":"[[\"zh-CN\"],[\"zh-CN\",\"zh\"]]","colorDepth":"24","deviceMemory":"8","screenResolution":"[1920,1080]","hardwareConcurrency":"8","timezone":"Asia/Shanghai","sessionStorage":"true","localStorage":"true","indexedDB":"true","openDatabase":"false","cpuClass":"","platform":"MacIntel","touchSupport":"{\"maxTouchPoints\":0,\"touchEvent\":false,\"touchStart\":false}","vendor":"Google Inc.","vendorFlavors":"[\"chrome\"]","cookiesEnabled":"true","colorGamut":"p3","invertedColors":"false","forcedColors":"false","monochrome":"0","contrast":"0","reducedMotion":"false","reducedTransparency":"false","hdr":"true","math":"{\"acos\":1.4473569987996832,\"acosh\":709.889355822726,\"acoshPf\":355.31285933834824,\"asin\":0.12343858458708294,\"asinh\":0.881373587019543,\"asinhPf\":0.8813735870195429,\"atanh\":0.5493061443340549,\"atanhPf\":0.5493061443340549,\"atan\":0.4636476090008061,\"sin\":-0.8178819121159085,\"sinh\":1.1752011936438014,\"sinhPf\":1.1752011936438014,\"cos\":-0.8390715290763854,\"cosh\":1.5430806348152437,\"coshPf\":1.5430806348152437,\"tan\":0.9747463484863075,\"tanh\":0.7615941559557649,\"tanhPf\":0.7615941559557649,\"exp\":2.718281828459045,\"expm1\":1.718281828459045,\"expm1Pf\":1.718281828459045,\"log1p\":2.3978952727983707,\"log1pPf\":2.3978952727983707,\"powPI\":1.9275814160560204e-50}","pdfViewerEnabled":"true","architecture":"127","userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36","webglUnmaskedVendor":"Google Inc. (Apple)","webglUnmaskedRenderer":"ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)","webglImageHash":"c675b95be11f21f9982c0178d79b15e5","id":"61ef11ef01c316e7453e90a1719cb201"}"#;

fn challenge_aes256_cbc_base64url_pad4(plain: &[u8], ua: &str) -> String {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let digest = Sha256::digest(ua.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&digest[16..32]);
    let cipher = aes::Aes256::new((&key).into());
    let padding = 16 - (plain.len() % 16);
    let mut buf = plain.to_vec();
    buf.resize(plain.len() + padding, padding as u8);
    let mut prev = iv;
    for chunk in buf.chunks_exact_mut(16) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        let mut block = aes::cipher::Block::<aes::Aes256>::default();
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        prev.copy_from_slice(&block);
    }
    let mut encoded = URL_SAFE_NO_PAD.encode(&buf);
    while encoded.len() % 4 != 0 {
        encoded.push('=');
    }
    encoded
}

fn sign_web_passport_url(url: &str, body: &str) -> Result<String> {
    sign_web_passport_request("POST", url, Some(body))
}

fn render_qr_svg_data_url(text: &str) -> Result<String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let rt = rquickjs::Runtime::new().map_err(|_| anyhow::anyhow!("无法创建二维码渲染引擎"))?;
    rt.set_memory_limit(32 * 1024 * 1024);
    rt.set_max_stack_size(512 * 1024);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    rt.set_interrupt_handler(Some(Box::new(move || std::time::Instant::now() >= deadline)));
    let ctx = rquickjs::Context::full(&rt).map_err(|_| anyhow::anyhow!("无法创建二维码渲染上下文"))?;
    let text_json = serde_json::to_string(text)?;
    let call_code = format!("renderQrSvg({text_json})");
    let svg: String = ctx.with(|ctx| {
        ctx.eval::<(), _>(WEB_JS_PRELUDE)
            .map_err(|_| anyhow::anyhow!("二维码引擎 Prelude 初始化失败"))?;
        ctx.eval::<(), _>(WEB_QR_SVG_SCRIPT)
            .map_err(|_| anyhow::anyhow!("二维码引擎脚本加载失败"))?;
        ctx.eval::<String, _>(call_code.as_str())
            .map_err(|_| anyhow::anyhow!("二维码 SVG 生成失败"))
    })?;
    ensure!(svg.starts_with("<svg"), "生成的二维码不是有效 SVG");
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg.as_bytes())
    ))
}

fn sign_web_passport_request(method: &str, url: &str, body: Option<&str>) -> Result<String> {
    let rt = rquickjs::Runtime::new().map_err(|_| anyhow::anyhow!("无法创建 BDMS JS 引擎"))?;
    rt.set_memory_limit(64 * 1024 * 1024);
    rt.set_max_stack_size(1024 * 1024);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    rt.set_interrupt_handler(Some(Box::new(move || std::time::Instant::now() >= deadline)));
    let ctx = rquickjs::Context::full(&rt).map_err(|_| anyhow::anyhow!("无法创建 BDMS JS 上下文"))?;
    let mut shim = WEB_ABOGUS_SHIM.replace("offline-dependency-probe", WEB_LOGIN_UA);
    shim = shim.replace(
        "var OrigDate=Date;Date=class extends OrigDate{constructor(...args){super(...(args.length?args:[1700000000000]))}static now(){return 1700000000000}};",
        "",
    );
    shim = shim.replace(
        "var url=new URL(location.href);Object.defineProperty(el,'href',{get:()=>url.href,set:v=>url=new URL(v,location.href)});",
        "var url=parseSimpleUrl(location.href);Object.defineProperty(el,'href',{get:()=>url.href,set:v=>url=parseSimpleUrl(v)});",
    );
    let method_json = serde_json::to_string(method)?;
    let url_json = serde_json::to_string(url)?;
    let body_json = match body {
        Some(b) => serde_json::to_string(b)?,
        None => "null".to_string(),
    };
    let call_code =
        format!("var x=new XMLHttpRequest();x.open({method_json},{url_json});x.send({body_json});");
    let call_code_json = serde_json::to_string(&call_code)?;
    let tail = format!(
        "window.bdms.init({{aid:6383,pageId:110624,paths:[\"/passport/\",\"/aweme/\"]}});var s=offlineCase({call_code_json});s&&s[0]&&s[0].url||\"\""
    );
    let signed: String = ctx
        .with(|ctx| {
            ctx.eval::<(), _>(WEB_JS_PRELUDE)
                .map_err(|_| anyhow::anyhow!("BDMS Prelude 初始化失败"))?;
            ctx.eval::<(), _>(shim.as_str())
                .map_err(|_| anyhow::anyhow!("BDMS Shim 初始化失败"))?;
            ctx.eval::<(), _>(WEB_BDMS_SCRIPT)
                .map_err(|_| anyhow::anyhow!("BDMS 主脚本加载失败"))?;
            ctx.eval::<String, _>(tail.as_str())
                .map_err(|_| anyhow::anyhow!("BDMS URL 签名执行失败"))
        })?;
    ensure!(!signed.is_empty() && signed.contains("a_bogus="), "BDMS 未生成有效 a_bogus");
    Ok(signed)
}

fn run_web_challenge_template(
    template: &str,
    ts: i64,
    enc_iv: &str,
) -> Result<(String, Value)> {
    let rev_t: String = Utc::now().timestamp_millis().to_string().chars().rev().collect();
    let default_e_in = serde_json::json!({
        "automa_ele": "false",
        "bit_helper": "false",
        "chrome_extension_script": "[]",
        "console_lied": "false",
        "global_variables": "[]",
        "swt_alt": "false",
        "zn_cap": "false",
        "hok_noti": "false",
        "inj_zfb": "false",
        "t": rev_t,
        "bit_protocol": "false",
    });
    let default_p_in = hex::encode(Sha256::digest(
        format!("userAgent={WEB_LOGIN_UA}&platform=MacIntel").as_bytes(),
    ));
    if template.trim().is_empty() {
        return Ok((default_p_in, default_e_in));
    }
    let patched = template.replace(
        "get 14(){return qt},get 15(){return Wt},get 16(){return It}",
        "get 14(){return function(){return Promise.resolve(globalThis.__FP_OBJ)}},get 15(){return function(){return Promise.resolve(globalThis.__E_IN)}},get 16(){return function(){return Promise.resolve(\"false\")}}",
    );
    let rt = rquickjs::Runtime::new().map_err(|_| anyhow::anyhow!("无法创建 Challenge JS 引擎"))?;
    rt.set_memory_limit(64 * 1024 * 1024);
    rt.set_max_stack_size(1024 * 1024);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    rt.set_interrupt_handler(Some(Box::new(move || std::time::Instant::now() >= deadline)));
    let ctx = rquickjs::Context::full(&rt).map_err(|_| anyhow::anyhow!("无法创建 Challenge JS 上下文"))?;
    let e_in_base = serde_json::json!({
        "automa_ele": "false",
        "bit_helper": "false",
        "chrome_extension_script": "[]",
        "console_lied": "false",
        "global_variables": "[]",
        "swt_alt": "false",
        "zn_cap": "false",
        "hok_noti": "false",
        "inj_zfb": "false",
        "t": rev_t,
    });
    let init_code = format!(
        "globalThis.Promise=SyncPromise;globalThis.__FP_OBJ={WEB_FP_JSON};globalThis.__E_IN={};",
        serde_json::to_string(&e_in_base)?
    );
    let iv_json = serde_json::to_string(enc_iv)?;
    let run_code = format!(
        "var __r=\"\";window.__p_ch.rs({{ts:{ts},iv:{iv_json}}}).then(function(x){{__r=JSON.stringify(x);}});__r"
    );
    let raw_out: String = ctx
        .with(|ctx| {
            ctx.eval::<(), _>(WEB_JS_PRELUDE)
                .map_err(|_| anyhow::anyhow!("Challenge Prelude 初始化失败"))?;
            ctx.eval::<(), _>(init_code.as_str())
                .map_err(|_| anyhow::anyhow!("Challenge 上下文初始化失败"))?;
            ctx.eval::<(), _>(patched.as_str())
                .map_err(|_| anyhow::anyhow!("Challenge 脚本加载失败"))?;
            ctx.eval::<String, _>(run_code.as_str())
                .map_err(|_| anyhow::anyhow!("Challenge 脚本执行失败"))
        })
        .unwrap_or_default();
    if let Ok(parsed) = serde_json::from_str::<Value>(&raw_out) {
        if let Some(p_in) = parsed.get("p_in").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            let e_in = parsed.get("e_in").cloned().unwrap_or(default_e_in);
            return Ok((p_in.to_string(), e_in));
        }
    }
    Ok((default_p_in, default_e_in))
}

fn set_douyin_web_cookie(jar: &Jar, name: &str, value: &str) {
    for base in ["https://www.douyin.com/", "https://douyin.com/"] {
        if let Ok(url) = reqwest::Url::parse(base) {
            jar.add_cookie_str(&format!("{name}={value}; Domain=.douyin.com; Path=/"), &url);
        }
    }
}

fn remove_douyin_web_cookie(jar: &Jar, name: &str) {
    for base in ["https://www.douyin.com/", "https://douyin.com/"] {
        if let Ok(url) = reqwest::Url::parse(base) {
            jar.add_cookie_str(
                &format!("{name}=; Domain=.douyin.com; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
                &url,
            );
            jar.add_cookie_str(
                &format!("{name}=; Domain=douyin.com; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
                &url,
            );
            jar.add_cookie_str(
                &format!("{name}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
                &url,
            );
        }
    }
}

fn store_internal_guard_server_data(jar: &Jar, encoded_value: &str) {
    if let Ok(url) = reqwest::Url::parse("https://guard.sparklight.internal/") {
        jar.add_cookie_str(
            &format!("bd_ticket_guard_server_data={encoded_value}; Domain=guard.sparklight.internal; Path=/"),
            &url,
        );
    }
}

fn load_internal_guard_server_data(jar: &Jar) -> Option<String> {
    let url = reqwest::Url::parse("https://guard.sparklight.internal/").ok()?;
    let header = CookieStore::cookies(jar, &url)?;
    let text = header.to_str().ok()?;
    cookie_value(text, "bd_ticket_guard_server_data")
}

fn parse_dtrait_pem_and_version(dtrait_bytes: &[u8]) -> Option<(String, String)> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let root: Value = serde_json::from_slice(dtrait_bytes).ok()?;
    let data = root.get("data")?.as_object()?;
    let pk1 = data.get("x-tt-session-dtrait-pk1")?.as_str()?.trim();
    let ver = data.get("x-tt-session-dtrait-pk1-version")?.as_str()?.trim();
    if pk1.is_empty() || ver.is_empty() {
        return None;
    }
    let pem_bytes = STANDARD.decode(pk1).ok()?;
    let pem = String::from_utf8(pem_bytes).ok()?;
    Some((pem, ver.to_string()))
}

fn generate_web_verify_fp(seed: &str) -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut ms = Utc::now().timestamp_millis().max(1) as u64;
    let mut ts_base36 = Vec::new();
    while ms > 0 {
        let rem = (ms % 36) as usize;
        ts_base36.push(if rem < 10 {
            b'0' + rem as u8
        } else {
            b'a' + (rem - 10) as u8
        });
        ms /= 36;
    }
    ts_base36.reverse();
    let ts_str = String::from_utf8(ts_base36).unwrap_or_else(|_| "mwbk2s5e".to_string());
    let hash = Sha256::digest(format!("sparklight-verify-fp:{seed}:{}", uuid::Uuid::new_v4()).as_bytes());
    let mut suffix = String::with_capacity(36);
    for i in 0..36 {
        match i {
            8 | 13 | 18 | 23 => suffix.push('_'),
            14 => suffix.push('4'),
            19 => {
                let idx = ((hash[i % hash.len()] & 0x03) | 0x08) as usize;
                suffix.push(CHARS[idx] as char);
            }
            _ => {
                let b = hash[i % hash.len()] ^ hash[(i + 7) % hash.len()];
                suffix.push(CHARS[(b as usize) % CHARS.len()] as char);
            }
        }
    }
    format!("verify_{ts_str}_{suffix}")
}

fn web_dtrait_central_string() -> String {
    use super::pcim_features::{FeatureProtocol, murmur3};
    let mut p = FeatureProtocol::new();
    for (k, v) in [
        ("bool_1", false),
        ("bool_2", false),
        ("bool_3", false),
        ("bool_4", true),
        ("bool_5", true),
        ("bool_6", true),
        ("bool_7", false),
        ("bool_8", true),
        ("bool_9", false),
        ("bool_10", true),
    ] {
        p.add_bool(k, v);
    }
    for (idx, sample) in [
        (1, WEB_LOGIN_UA),
        (2, "MacIntel"),
        (3, "zh-CN"),
        (4, "zh-CN,zh"),
        (5, "Asia/Shanghai"),
        (6, "1920x1080"),
        (7, "1920x1055"),
        (8, "24"),
        (9, "8"),
        (10, "8"),
        (11, "Google Inc."),
        (12, "Google Inc. (Apple)"),
        (13, "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)"),
        (14, "5292599e1a367e4d3a7f57ce39543286"),
        (15, "6d86be4fc98cf1e1a4a24d34f920bd90"),
        (16, "c675b95be11f21f9982c0178d79b15e5"),
        (17, "www.douyin.com"),
        (18, "https://www.douyin.com/"),
    ] {
        p.add_hash(&format!("str_{idx}"), murmur3(sample));
    }
    p.result().0
}

fn make_web_passport_query(
    trace_id: &str,
    verify_fp: &str,
    browser_info_enc: &str,
    extra: &[(&str, &str)],
) -> String {
    let p_ts = Utc::now().timestamp_millis().to_string();
    let p_no_raw = format!(
        "p_bd=1.0.1.19-fix.01&p_ca=4.0.21&p_ts={p_ts}&p_ver=1.1.4-beta.5&p_zt=3.3.10&passport_jssdk_version=3.4.9"
    );
    let p_no = hex::encode(Sha256::digest(p_no_raw.as_bytes()));
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in [
        ("is_from_ttaccountsdk", "1"),
        ("passport_jssdk_type", "normal"),
        ("passport_jssdk_version", "3.4.9"),
        ("account_sdk_source", "web"),
        ("aid", "6383"),
        ("language", "zh"),
        ("account_app_language", "zh-CN"),
        ("is_new_login", "1"),
        ("is_from_iesaccountsaas", "1"),
        ("p_ui", "2.1.4"),
        ("p_ca", "4.0.21"),
        ("p_ca_real", "1.0.0.1069"),
        ("fp", verify_fp),
        ("verifyFp", verify_fp),
        ("p_js_v", "3.4.9"),
        ("p_js_t", "pro"),
        ("p_zt", "3.3.10"),
        ("p_ver", "1.1.4-beta.5"),
        ("p_ver_real", "0"),
        ("request_host", "https://www.douyin.com"),
        ("p_bd", "1.0.1.19-fix.01"),
        ("p_ts", p_ts.as_str()),
        ("p_no", p_no.as_str()),
        ("biz_trace_id", trace_id),
        ("account_sdk_source_info", browser_info_enc),
    ] {
        serializer.append_pair(k, v);
    }
    for (k, v) in extra {
        serializer.append_pair(k, v);
    }
    serializer.finish()
}

async fn bootstrap_web_passport_session(
    account_id: &str,
) -> Result<(
    Client,
    Arc<Jar>,
    NativeDevice,
    String,
    String,
    String,
    Vec<u8>,
    String,
)> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let device = NativeDevice::derive(account_id);
    device.validate()?;
    let jar = Arc::new(Jar::default());
    let client = Client::builder()
        .cookie_provider(jar.clone())
        .user_agent(WEB_LOGIN_UA)
        .timeout(Duration::from_secs(20))
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("创建 Web Passport HTTP 客户端失败")?;

    let ttwid_body = serde_json::json!({
        "region": "cn",
        "aid": 6383,
        "needFid": false,
        "service": "www.douyin.com",
        "migrate_info": { "ticket": "", "source": "node" },
        "cbUrlProtocol": "https",
        "union": true
    });
    if let Ok(resp) = client
        .post("https://ttwid.bytedance.com/ttwid/union/register/")
        .header(header::CONTENT_TYPE, "application/json")
        .json(&ttwid_body)
        .send()
        .await
    {
        for value in resp.headers().get_all(header::SET_COOKIE).iter() {
            if let Ok(cookie_line) = value.to_str() {
                if let Some((kv, _)) = cookie_line.split_once(';') {
                    if let Some((k, v)) = kv.trim().split_once('=') {
                        set_douyin_web_cookie(&jar, k.trim(), v.trim());
                    }
                }
            }
        }
    }

    let csrf_token = uuid::Uuid::new_v4().simple().to_string();
    set_douyin_web_cookie(&jar, "passport_csrf_token", &csrf_token);
    set_douyin_web_cookie(&jar, "passport_csrf_token_default", &csrf_token);
    let verify_fp = generate_web_verify_fp(account_id);
    set_douyin_web_cookie(&jar, "s_v_web_id", &verify_fp);
    let guard_key = super::pcim_guard::GuardKey::derive_for_account(account_id);
    if let Ok(guard_cookie) = guard_key.initialization_cookie_value() {
        let guard_cookie_encoded = guard_cookie.replace('=', "%3D");
        set_douyin_web_cookie(&jar, "bd_ticket_guard_client_data", &guard_cookie_encoded);
        set_douyin_web_cookie(&jar, "bd_ticket_guard_client_web_domain", "2");
    }
    let guard_key_hex = guard_key.to_hex();

    let now_ms = Utc::now().timestamp_millis();
    let rev_t: String = now_ms.to_string().chars().rev().collect();
    let browser_info = serde_json::json!({
        "hardwareConcurrency": 8,
        "webdriver": false,
        "chromedriver": false,
        "shelldriver": false,
        "plugins": 5,
        "innerHeight": 945,
        "innerWidth": 1920,
        "outerHeight": 1055,
        "outerWidth": 1920,
        "webgl": {
            "vendor": "Google Inc. (Apple)",
            "renderer": "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)"
        },
        "automation": {
            "s": "00000000",
            "c": "0000",
            "p": "0000000",
            "s1": "00000000",
            "c1": "0000",
            "p1": "0"
        },
        "performance": {
            "timeOrigin": now_ms - 5000,
            "usedJSHeapSize": 24500000,
            "navigationTiming": {
                "decodedBodySize": 120000,
                "entryType": "navigation",
                "initiatorType": "navigation",
                "name": "https://www.douyin.com/",
                "renderBlockingStatus": "non-blocking",
                "serverTiming": "",
                "guleStart": 120,
                "guleDuration": 45
            }
        },
        "browser": {
            "t": rev_t,
            "bit_protocol": "false",
            "bit_helper": false
        }
    });
    let browser_info_enc = encode_d_ticket(&serde_json::to_string(&browser_info)?);

    let cert_body = "server_data=1&need_session_dtrait=1";
    let cert_url = sign_web_passport_url(
        "https://www.douyin.com/passport/ticket_guard/get_client_cert/?aid=6383&type=trait&sdk_version=1.1.16&is_from_ttaccountsdk=1",
        cert_body,
    )?;
    let cert_resp = client
        .post(&cert_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(header::REFERER, "https://www.douyin.com/")
        .header(header::ORIGIN, "https://www.douyin.com")
        .header("x-tt-passport-csrf-token", &csrf_token)
        .body(cert_body.to_string())
        .send()
        .await
        .context("获取 Web 登录 DTrait 证书失败")?;
    let dtrait_bytes = read_limited_body(cert_resp, "DTrait 证书响应").await?;
    let _ = super::pcim_dtrait::DTraitCipher::from_server_response(&dtrait_bytes)
        .context("解析 Web 登录 DTrait 证书失败")?;

    let trace_ch = &uuid::Uuid::new_v4().simple().to_string()[..8];
    set_douyin_web_cookie(&jar, "biz_trace_id", trace_ch);
    let sign_g = challenge_aes256_cbc_base64url_pad4(
        STANDARD.encode(WEB_FP_JSON.as_bytes()).as_bytes(),
        WEB_LOGIN_UA,
    );
    let stack_err = "    at Object.getStackError (https://lf-douyin-pc-web.douyinstatic.com/obj/douyin-pc-web/ies/account/saas/518.3bef8cb0.js:1:48000)    at https://lf-douyin-pc-web.douyinstatic.com/obj/douyin-pc-web/ies/account/saas/518.3bef8cb0.js:1:3200";
    let encoded_stack: String = url::form_urlencoded::byte_serialize(stack_err.as_bytes()).collect();
    let sk_val = encode_d_ticket(&encoded_stack);
    let ch_body = {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        ser.append_pair("sign", &sign_g);
        ser.append_pair("sk", &sk_val);
        ser.finish()
    };
    let ch_query =
        make_web_passport_query(trace_ch, &verify_fp, &browser_info_enc, &[("skip_c", "1")]);
    let ch_url = sign_web_passport_url(
        &format!("https://www.douyin.com/passport/web/challenge/?{ch_query}"),
        &ch_body,
    )?;
    let ch_resp = client
        .post(&ch_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json, text/javascript")
        .header(header::REFERER, "https://www.douyin.com/")
        .header(header::ORIGIN, "https://www.douyin.com")
        .header("x-tt-passport-csrf-token", &csrf_token)
        .header("x-tt-passport-trace-id", trace_ch)
        .header("web-sdk-version", "1")
        .body(ch_body)
        .send()
        .await
        .context("请求 Web 登录环境挑战失败")?;
    let ch_bytes = read_limited_body(ch_resp, "Web 登录环境挑战响应").await?;
    let ch_root: Value = serde_json::from_slice(&ch_bytes).context("挑战响应不是合法 JSON")?;
    let ch_data = ch_root
        .get("data")
        .and_then(Value::as_object)
        .context("挑战响应缺少 data")?;
    let passport_iv = ch_data
        .get("passportiv")
        .and_then(Value::as_str)
        .unwrap_or_default();
    ensure!(!passport_iv.is_empty(), "挑战响应未返回 passportiv");
    let ts = ch_data.get("ts").and_then(Value::as_i64).unwrap_or(0);
    let template = ch_data
        .get("template")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let enc_iv = challenge_aes256_cbc_base64url_pad4(passport_iv.as_bytes(), WEB_LOGIN_UA);
    let (p_in, e_in) = run_web_challenge_template(template, ts, &enc_iv)?;
    let sdk_source_info: String = url::form_urlencoded::byte_serialize(
        encode_d_ticket(&serde_json::to_string(&e_in)?).as_bytes(),
    )
    .collect();
    let bit_env: String = url::form_urlencoded::byte_serialize(enc_iv.as_bytes()).collect();
    let gulu_raw = STANDARD.encode(serde_json::json!({ "p_in": p_in }).to_string().as_bytes());
    let gulu_source_res: String = url::form_urlencoded::byte_serialize(gulu_raw.as_bytes()).collect();
    let mix_state = uuid::Uuid::new_v4().simple().to_string();
    set_douyin_web_cookie(&jar, "sdk_source_info", &sdk_source_info);
    set_douyin_web_cookie(&jar, "bit_env", &bit_env);
    set_douyin_web_cookie(&jar, "gulu_source_res", &gulu_source_res);
    set_douyin_web_cookie(&jar, "passport_auth_mix_state", &mix_state);

    Ok((
        client,
        jar,
        device,
        csrf_token,
        verify_fp,
        guard_key_hex,
        dtrait_bytes,
        browser_info_enc,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn post_web_passport_action(
    client: &Client,
    jar: &Jar,
    csrf_token: &str,
    verify_fp: &str,
    guard_key_hex: Option<&str>,
    dtrait_bytes: &[u8],
    browser_info_enc: &str,
    path: &str,
    form_pairs: &[(&str, String)],
    verify_portrait_id: Option<&str>,
    extra_query: &[(&str, &str)],
    extra_headers: &[(String, String)],
) -> Result<(Value, header::HeaderMap)> {
    let trace_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    set_douyin_web_cookie(jar, "biz_trace_id", trace_id);
    let query = make_web_passport_query(trace_id, verify_fp, browser_info_enc, extra_query);
    let body = {
        let mut body_ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in form_pairs {
            body_ser.append_pair(k, v);
        }
        body_ser.finish()
    };
    let signed_url = sign_web_passport_url(&format!("https://www.douyin.com{path}?{query}"), &body)?;
    let dtrait_cipher = super::pcim_dtrait::DTraitCipher::from_server_response(dtrait_bytes)?;
    let dtrait_central = web_dtrait_central_string();
    let dtrait_header =
        dtrait_cipher.central_header(&dtrait_central, path, &[], Utc::now().timestamp())?;
    let mut req = client
        .post(&signed_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json, text/javascript")
        .header(header::REFERER, "https://www.douyin.com/")
        .header(header::ORIGIN, "https://www.douyin.com")
        .header("x-tt-passport-csrf-token", csrf_token)
        .header("x-tt-passport-trace-id", trace_id)
        .header("x-tt-session-dtrait", dtrait_header)
        .header("web-sdk-version", "1");
    if let Some(portrait) = verify_portrait_id.filter(|v| !v.is_empty()) {
        req = req.header("x-tt-passport-verify-portrait", portrait);
    }
    if let Some(gk_hex) = guard_key_hex
        && let Ok(gk) = super::pcim_guard::GuardKey::from_hex(gk_hex)
        && let Ok(init_headers) = gk.initialization_headers()
    {
        for (k, v) in init_headers.iter() {
            req = req.header(k, v);
        }
        req = req.header("bd-ticket-guard-iteration-version", "1");
    }
    for (k, v) in extra_headers {
        if !k.trim().is_empty() && !v.trim().is_empty() {
            req = req.header(k.as_str(), v.as_str());
        }
    }
    let response = req
        .body(body)
        .send()
        .await
        .with_context(|| format!("请求抖音 Web Passport {path} 失败"))?;
    let headers = response.headers().clone();
    sync_response_cookies_to_jar(jar, &headers, guard_key_hex);
    let bytes = read_limited_body(response, "Web Passport 响应").await?;
    let root: Value = serde_json::from_slice(&bytes).context("Web Passport 响应不是合法 JSON")?;
    Ok((root, headers))
}

fn sync_response_cookies_to_jar(
    jar: &Jar,
    headers: &header::HeaderMap,
    guard_key_hex: Option<&str>,
) {
    let mut captured_server_data: Option<String> = None;
    for value in headers.get_all(header::SET_COOKIE).iter() {
        if let Ok(cookie_line) = value.to_str() {
            if let Some((kv, _)) = cookie_line.split_once(';') {
                if let Some((k, v)) = kv.trim().split_once('=') {
                    let name = k.trim();
                    let val = v.trim();
                    if !name.is_empty() && !val.is_empty() && !val.eq_ignore_ascii_case("deleted") {
                        if name == "bd_ticket_guard_server_data" {
                            captured_server_data = Some(val.to_string());
                            continue;
                        }
                        if name == "bd_ticket_guard_web_domain" {
                            continue;
                        }
                        set_douyin_web_cookie(jar, name, val);
                    }
                }
            }
        }
    }
    if let Some(srv_data) = headers
        .get("bd-ticket-guard-server-data")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let encoded = srv_data.replace('=', "%3D");
        captured_server_data = Some(encoded);
    }
    remove_douyin_web_cookie(jar, "bd_ticket_guard_server_data");
    remove_douyin_web_cookie(jar, "bd_ticket_guard_web_domain");
    if let Some(encoded_srv) = captured_server_data {
        store_internal_guard_server_data(jar, &encoded_srv);
        if let Some(gk_hex) = guard_key_hex
            && let Ok(gk) = super::pcim_guard::GuardKey::from_hex(gk_hex)
        {
            let carrier = format!("bd_ticket_guard_server_data={encoded_srv}");
            let snap = cookie_snapshot(jar);
            if let Ok(Some(mat)) =
                gk.bind_server_cookie(&carrier, 1, &snap, Utc::now().timestamp())
                && let Ok(crypt_hash) = mat.compute_crypt_cookie()
            {
                set_douyin_web_cookie(jar, "_bd_ticket_crypt_cookie", &crypt_hash);
                set_douyin_web_cookie(jar, "_bd_ticket_crypt_doamin", "2");
                set_douyin_web_cookie(jar, "__security_server_data_status", "1");
            }
        }
    }
}

async fn get_web_secondary_verify_action(
    client: &Client,
    csrf_token: &str,
    verify_portrait_id: &str,
    path: &str,
    query_pairs: &[(&str, String)],
) -> Result<Value> {
    let query = {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in query_pairs {
            ser.append_pair(k, v);
        }
        ser.finish()
    };
    let raw_url = format!("https://www.douyin.com{path}?{query}");
    let signed_url = sign_web_passport_request("GET", &raw_url, None).unwrap_or(raw_url);
    let mut req = client
        .get(&signed_url)
        .header(header::ACCEPT, "application/json, text/javascript")
        .header(header::REFERER, "https://www.douyin.com/")
        .header(header::ORIGIN, "https://www.douyin.com")
        .header("x-tt-passport-csrf-token", csrf_token)
        .header("x-use-secondary-verify-sdk", "1")
        .header("web-sdk-version", "1");
    if !verify_portrait_id.is_empty() {
        req = req.header("x-tt-passport-verify-portrait", verify_portrait_id);
    }
    let response = req
        .send()
        .await
        .with_context(|| format!("请求二次验证接口 {path} 失败"))?;
    let bytes = read_limited_body(response, "二次验证响应").await?;
    serde_json::from_slice(&bytes).context("二次验证响应不是合法 JSON")
}

async fn post_web_uc_second_verify_action(
    session: &PhoneLoginSession,
    sv: &WebSecondVerifyState,
    path: &str,
    extra_form: &[(&str, String)],
) -> Result<Value> {
    let trace_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    set_douyin_web_cookie(&session.jar, "biz_trace_id", trace_id);
    let query = {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in [
            ("passport_jssdk_version", "5.4.0"),
            ("passport_jssdk_type", "lite"),
            ("is_from_ttaccountsdk", "1"),
            ("aid", "6383"),
            ("language", "zh"),
            ("account_app_language", "zh-CN"),
            ("new_authn_sdk_version", WEB_NEW_AUTHN_SDK_VERSION),
            ("biz_trace_id", trace_id),
        ] {
            ser.append_pair(k, v);
        }
        ser.finish()
    };
    let mut form_pairs = sv.common_form_pairs();
    for (k, v) in extra_form {
        if let Some(existing) = form_pairs.iter_mut().find(|(ek, _)| ek == k) {
            existing.1 = v.clone();
        } else {
            form_pairs.push(((*k).to_string(), v.clone()));
        }
    }
    if !form_pairs.iter().any(|(k, _)| k == "new_authn_sdk_version") {
        form_pairs.push((
            "new_authn_sdk_version".to_string(),
            WEB_NEW_AUTHN_SDK_VERSION.to_string(),
        ));
    }
    let body = {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in &form_pairs {
            ser.append_pair(k, v);
        }
        ser.finish()
    };
    let raw_url = format!("https://www.douyin.com{path}?{query}");
    let signed_url = sign_web_passport_url(&raw_url, &body).unwrap_or(raw_url);
    let mut req = session
        .client
        .post(&signed_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json, text/javascript")
        .header(header::REFERER, "https://www.douyin.com/")
        .header(header::ORIGIN, "https://www.douyin.com")
        .header("x-tt-passport-csrf-token", &session.csrf_token)
        .header("x-tt-passport-trace-id", trace_id)
        .header("web-sdk-version", "1");
    if !sv.verify_portrait_id.is_empty() {
        req = req.header("x-tt-passport-verify-portrait", &sv.verify_portrait_id);
    }
    if let Ok(gk) = super::pcim_guard::GuardKey::from_hex(&session.guard_key_hex)
        && let Ok(init_headers) = gk.initialization_headers()
    {
        for (k, v) in init_headers.iter() {
            req = req.header(k, v);
        }
        req = req.header("bd-ticket-guard-iteration-version", "1");
    }
    if let Ok(dtrait_cipher) =
        super::pcim_dtrait::DTraitCipher::from_server_response(&session.dtrait_bytes)
    {
        let dtrait_central = web_dtrait_central_string();
        if let Ok(dtrait_header) =
            dtrait_cipher.central_header(&dtrait_central, path, &[], Utc::now().timestamp())
        {
            req = req.header("x-tt-session-dtrait", dtrait_header);
        }
    }
    let response = req
        .body(body)
        .send()
        .await
        .with_context(|| format!("请求二次验证接口 {path} 失败"))?;
    sync_response_cookies_to_jar(&session.jar, response.headers(), Some(&session.guard_key_hex));
    let bytes = read_limited_body(response, "二次验证响应").await?;
    serde_json::from_slice(&bytes).context("二次验证响应不是合法 JSON")
}

fn web_verification_way_metadata(kind: &str) -> (&'static str, bool, &'static str) {
    match kind {
        "mobile_up_sms_verify" | "assist_mobile_up_sms_verify" => (
            "发送短信验证",
            true,
            "使用绑定手机发送指定短信内容，发送后点击确认完成登录",
        ),
        "pwd_verify" => ("验证登录密码", true, "输入抖音登录密码完成本人身份核验"),
        "mobile_sms_verify" | "assist_mobile_sms_verify" | "mobile_sms_check_or_verify" => (
            "接收短信验证码",
            true,
            "向账号绑定手机发送二次安全验证码",
        ),
        "mobile_voice_sms_verify" | "assist_mobile_voice_sms_verify" => (
            "接收语音验证码",
            true,
            "向账号绑定手机拨打语音验证码",
        ),
        "push_verify" | "mobile_push_verify" | "aweme_push_verify" => (
            "抖音 App 一键确认",
            true,
            "向手机抖音 App 发送登录确认通知，在手机点击允许即可",
        ),
        "qr_code_verify" | "scan_qrcode_verify" => (
            "抖音 App 扫码验证",
            true,
            "打开手机抖音扫一扫完成本次安全身份验证",
        ),
        "face_verify" | "qr_code_face_verify" | "identity_verify" => (
            "抖音 App 扫码刷脸验证",
            true,
            "打开手机抖音扫一扫按提示完成本人刷脸核验",
        ),
        _ => ("其他安全验证", false, "请在手机抖音官方 App 内按提示完成验证"),
    }
}

fn web_verification_way_priority(kind: &str) -> u8 {
    match kind {
        "qr_code_verify" | "scan_qrcode_verify" => 0,
        "mobile_sms_verify" | "assist_mobile_sms_verify" | "mobile_sms_check_or_verify" => 1,
        "mobile_up_sms_verify" | "assist_mobile_up_sms_verify" => 2,
        "pwd_verify" => 3,
        "push_verify" | "mobile_push_verify" | "aweme_push_verify" => 4,
        "mobile_voice_sms_verify" | "assist_mobile_voice_sms_verify" => 5,
        "face_verify" | "qr_code_face_verify" | "identity_verify" => 6,
        _ => 7,
    }
}

impl WebSecondVerifyState {
    fn common_form_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = vec![
            (
                "encrypt_uid".to_string(),
                self.encrypt_uid.clone().unwrap_or_default(),
            ),
            (
                "verify_ticket".to_string(),
                self.verify_ticket.clone().unwrap_or_default(),
            ),
        ];
        for (k, v) in &self.common_params {
            if let Some(existing) = pairs.iter_mut().find(|(ek, _)| ek == k) {
                if existing.1.is_empty() && !v.is_empty() {
                    existing.1 = v.clone();
                }
            } else {
                pairs.push((k.clone(), v.clone()));
            }
        }
        pairs
    }

    fn to_challenge_view(&self, fallback_masked_mobile: &str) -> LoginChallengeView {
        let masked_mobile = self
            .ways
            .iter()
            .find_map(|w| w.public.masked_mobile.clone())
            .or_else(|| {
                (!fallback_masked_mobile.is_empty()).then(|| fallback_masked_mobile.to_string())
            });
        LoginChallengeView::TwoStep {
            ways: self.ways.iter().map(|w| w.public.clone()).collect(),
            masked_mobile,
            profile_name: None,
            avatar_url: None,
            ticket_ready: self.verify_ticket.is_some()
                || self.auth_ticket.is_some()
                || self.encrypt_uid.is_some()
                || !self.common_params.is_empty(),
            scene_description: self.scene_description.clone(),
        }
    }
}

async fn unpack_web_verify_ways_data(
    client: &Client,
    csrf_token: &str,
    verify_portrait_id: &str,
    decision_obj: &serde_json::Map<String, Value>,
    verify_fp: &str,
) -> Option<serde_json::Map<String, Value>> {
    let mut pairs: Vec<(String, String)> = vec![
        ("aid".to_string(), "6383".to_string()),
        ("fp".to_string(), verify_fp.to_string()),
        (
            "verify_portrait_id".to_string(),
            verify_portrait_id.to_string(),
        ),
    ];
    for (k, v) in decision_obj {
        if k == "is_login" || k == "aid" || k == "fp" || k == "verify_portrait_id" {
            continue;
        }
        match v {
            Value::String(s) if !s.is_empty() && s.len() <= 16384 => {
                pairs.push((k.clone(), s.clone()));
            }
            Value::Number(n) => pairs.push((k.clone(), n.to_string())),
            Value::Bool(b) => pairs.push((k.clone(), b.to_string())),
            _ => {}
        }
    }
    let body = {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in &pairs {
            ser.append_pair(k, v);
        }
        ser.finish()
    };
    for host in ["https://www.douyin.com", "https://verify.zijieapi.com"] {
        let raw_url = format!("{host}/passport/safe/pack_verify_ways_data/?aid=6383&account_sdk_source=web&is_from_ttaccountsdk=1");
        let url = if host.contains("douyin.com") {
            sign_web_passport_url(&raw_url, &body).unwrap_or(raw_url)
        } else {
            raw_url
        };
        if let Ok(resp) = client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json, text/javascript")
            .header(header::REFERER, "https://www.douyin.com/")
            .header(header::ORIGIN, "https://www.douyin.com")
            .header("x-tt-passport-csrf-token", csrf_token)
            .header("x-tt-passport-verify-portrait", verify_portrait_id)
            .body(body.clone())
            .send()
            .await
            && let Ok(bytes) = read_limited_body(resp, "pack_verify_ways_data").await
            && let Ok(json) = serde_json::from_slice::<Value>(&bytes)
            && let Some(data) = json.get("data").and_then(Value::as_object)
            && !data.is_empty()
        {
            return Some(data.clone());
        }
    }
    None
}

async fn build_web_second_verify_state(
    session: &PhoneLoginSession,
    root: &Value,
    response_headers: &header::HeaderMap,
    verify_portrait_id: &str,
    pending_action: PendingWebLoginAction,
) -> WebSecondVerifyState {
    let mut merged_data = root
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut replay_headers = Vec::new();
    let mut direct_subtype: Option<String> = None;
    let decision_raw = first_value_string(
        &merged_data,
        &[
            "verify_center_decision_conf",
            "verify_center_secondary_decision_conf",
        ],
    )
    .or_else(|| header_string(response_headers, "x-vc-bdturing-parameters"));

    if let Some(raw) = decision_raw.as_deref()
        && let Some(vc_obj) = parse_json_value(raw).and_then(|v| v.as_object().cloned())
    {
        if let Some(replay) = vc_obj.get("replay_data").and_then(Value::as_object) {
            for (hk, hv) in replay {
                if let Some(hv_str) = hv.as_str() {
                    replay_headers.push((hk.clone(), hv_str.to_string()));
                }
            }
        }
        direct_subtype = first_value_string(&vc_obj, &["subtype"]);
        for key in ["verify_ticket", "mobile", "channel_mobile", "sms_content", "detail"] {
            if !merged_data.contains_key(key)
                && let Some(v) = vc_obj.get(key)
            {
                merged_data.insert(key.to_string(), v.clone());
            }
        }
        if let Some(mfa_raw) = first_value_string(&vc_obj, &["mfa_decision"])
            && let Some(mfa_obj) = parse_json_value(&mfa_raw).and_then(|v| v.as_object().cloned())
        {
            for (k, v) in mfa_obj {
                merged_data.insert(k, v);
            }
        }
        if direct_subtype.as_deref() == Some("mobile_sms_check_or_verify") {
            merged_data.insert(
                "verify_ways".to_string(),
                Value::String("mobile_sms_check_or_verify".to_string()),
            );
            merged_data.insert(
                "verify_from".to_string(),
                Value::String("verify_center".to_string()),
            );
            merged_data.insert("scene".to_string(), Value::String("engineType".to_string()));
            if let Some(detail) = first_value_string(&vc_obj, &["detail"]) {
                merged_data.insert("origin_decision".to_string(), Value::String(detail));
            }
        }
    }

    if first_value_string(&merged_data, &["verify_from"]).as_deref() == Some("verify_center")
        && let Some(unpacked) = unpack_web_verify_ways_data(
            &session.client,
            &session.csrf_token,
            verify_portrait_id,
            &merged_data,
            &session.verify_fp,
        )
        .await
    {
        for (k, v) in unpacked {
            if !v.is_null() {
                merged_data.insert(k, v);
            }
        }
    }

    let mut biz_params = Vec::new();
    if let Some(bp) = merged_data.get("biz_params").and_then(Value::as_object) {
        for (k, v) in bp {
            match v {
                Value::String(s) => biz_params.push((k.clone(), s.clone())),
                Value::Number(n) => biz_params.push((k.clone(), n.to_string())),
                Value::Bool(b) => biz_params.push((k.clone(), b.to_string())),
                _ => {}
            }
        }
    }

    let mut common_params: Vec<(String, String)> = Vec::new();
    let mut upsert_common = |k: String, v: String| {
        if k == "copywriting" || k.trim().is_empty() {
            return;
        }
        if let Some(existing) = common_params.iter_mut().find(|(ek, _)| ek == &k) {
            if existing.1.is_empty() && !v.is_empty() {
                existing.1 = v;
            }
        } else {
            common_params.push((k, v));
        }
    };
    if let Some(cp) = merged_data.get("common_params").and_then(Value::as_object) {
        for (k, v) in cp {
            match v {
                Value::String(s) => upsert_common(k.clone(), s.clone()),
                Value::Number(n) => upsert_common(k.clone(), n.to_string()),
                Value::Bool(b) => upsert_common(k.clone(), b.to_string()),
                _ => {}
            }
        }
    }
    if let Some(url_str) = first_value_string(&merged_data, &["url"])
        && let Some((_, query_part)) = url_str.split_once('?')
    {
        for (k, v) in url::form_urlencoded::parse(query_part.as_bytes()) {
            if k.starts_with("std_verify_") && k != "std_verify_way" {
                upsert_common(k.into_owned(), v.into_owned());
            }
        }
    }
    for (k, v) in &biz_params {
        if k.starts_with("std_verify_") && k != "std_verify_way" && !v.is_empty() {
            upsert_common(k.clone(), v.clone());
        }
    }

    let encrypt_uid = first_value_string(&merged_data, &["encrypt_uid"]).or_else(|| {
        common_params
            .iter()
            .find(|(k, _)| k == "encrypt_uid")
            .map(|(_, v)| v.clone())
            .filter(|s| !s.is_empty())
    });
    let event_obj = merged_data.get("event_params").and_then(Value::as_object);
    let verify_scene = event_obj
        .and_then(|ep| first_value_string(ep, &["verify_scene"]))
        .or_else(|| {
            common_params
                .iter()
                .find(|(k, _)| k == "std_verify_scene")
                .map(|(_, v)| v.clone())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| first_value_string(&merged_data, &["passport_scene", "scene"]));
    let verify_reason = event_obj.and_then(|ep| first_value_string(ep, &["verify_reason"]));

    let sms_code_key = first_value_string(&merged_data, &["sms_code_key"]).or_else(|| {
        biz_params
            .iter()
            .find(|(k, _)| k == "sms_code_key")
            .map(|(_, v)| v.clone())
            .filter(|s| !s.is_empty())
    });
    let verify_ticket = first_value_string(&merged_data, &["verify_ticket", "ticket"]);
    let auth_ticket = first_value_string(&merged_data, &["auth_ticket"]);
    let sec_user_id = first_value_string(&merged_data, &["sec_user_id", "sec_uid"]).or_else(|| {
        biz_params
            .iter()
            .find(|(k, _)| k == "sec_user_id" || k == "sec_uid")
            .map(|(_, v)| v.clone())
    }).or_else(|| header_string(response_headers, "d-ticket-sec-uid"));
    let scene_description = first_value_string(
        &merged_data,
        &["verify_scene_desc", "instruction_text", "description"],
    )
    .filter(|s| !s.trim().is_empty())
    .or_else(|| Some("抖音检测到新设备登录，请任选一种方式完成本人身份核验".to_string()));

    let synthetic_root = Value::Object({
        let mut m = serde_json::Map::new();
        m.insert("data".to_string(), Value::Object(merged_data.clone()));
        m
    });

    let mut ways: Vec<VerificationWay> = Vec::new();
    if let Some(payload) = verification_payload(&synthetic_root) {
        for entry in payload.ways.iter().take(16) {
            let Some(entry_obj) = entry.as_object() else {
                continue;
            };
            let Some(kind) = first_value_string(entry_obj, &["verify_way", "verify_type", "way"])
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty())
            else {
                continue;
            };
            if ways.iter().any(|w| w.public.kind == kind) {
                continue;
            }
            let (label, supported, desc) = web_verification_way_metadata(&kind);
            let masked = first_value_string(entry_obj, &["mobile", "mobile_number"])
                .map(|m| mask_mobile(&m))
                .filter(|m| !m.is_empty());
            let cert_app_id = entry_obj.get("cert_app_id").and_then(|v| match v {
                Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            });
            let is_oper_staff_user = entry_obj
                .get("is_oper_staff_user")
                .map(|v| v.as_bool() == Some(true) || v.as_str() == Some("true"))
                .unwrap_or(false);
            ways.push(VerificationWay {
                public: LoginVerifyWay {
                    kind,
                    label: label.to_string(),
                    masked_mobile: masked,
                    supported,
                    description: Some(desc.to_string()),
                },
                auth_ticket: first_value_string(entry_obj, &["auth_ticket"]),
                sms_content: first_value_string(entry_obj, &["sms_content"]),
                channel_mobile: first_value_string(entry_obj, &["channel_mobile"]),
                scene: first_value_string(entry_obj, &["scene"]),
                cert_app_id,
                flow: first_value_string(entry_obj, &["flow"]),
                act_type: entry_obj.get("act_type").and_then(Value::as_i64),
                is_oper_staff_user,
            });
        }
    }

    if ways.is_empty()
        && let Some(sub) = direct_subtype.as_deref()
        && sub != "slide"
        && sub != "whirl"
        && sub != "3d"
    {
        let kind = sub.trim().to_ascii_lowercase();
        let (label, supported, desc) = web_verification_way_metadata(&kind);
        if supported {
            ways.push(VerificationWay {
                public: LoginVerifyWay {
                    kind,
                    label: label.to_string(),
                    masked_mobile: first_value_string(&merged_data, &["mobile"])
                        .map(|m| mask_mobile(&m)),
                    supported,
                    description: Some(desc.to_string()),
                },
                auth_ticket: auth_ticket.clone(),
                sms_content: first_value_string(&merged_data, &["sms_content"]),
                channel_mobile: first_value_string(&merged_data, &["channel_mobile"]),
                ..Default::default()
            });
        }
    }

    if ways.is_empty() || !ways.iter().any(|w| w.public.supported) {
        let default_masked = Some(session.mobile_masked());
        for kind in [
            "mobile_up_sms_verify",
            "pwd_verify",
            "mobile_sms_verify",
            "push_verify",
            "qr_code_verify",
        ] {
            if ways.iter().any(|w| w.public.kind == kind) {
                continue;
            }
            let (label, supported, desc) = web_verification_way_metadata(kind);
            ways.push(VerificationWay {
                public: LoginVerifyWay {
                    kind: kind.to_string(),
                    label: label.to_string(),
                    masked_mobile: default_masked.clone(),
                    supported,
                    description: Some(desc.to_string()),
                },
                auth_ticket: auth_ticket.clone(),
                sms_content: first_value_string(&merged_data, &["sms_content"]),
                channel_mobile: first_value_string(&merged_data, &["channel_mobile"]),
                ..Default::default()
            });
        }
    }

    ways.sort_by_key(|w| web_verification_way_priority(&w.public.kind));

    let way_kinds = ways
        .iter()
        .map(|w| w.public.kind.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let keys = merged_data
        .keys()
        .take(32)
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    tracing::info!(
        data_keys = %keys,
        has_verify_ticket = verify_ticket.is_some(),
        has_sms_code_key = sms_code_key.is_some(),
        has_decision_conf = decision_raw.is_some(),
        ways = %way_kinds,
        "抖音登录返回 2046，已进入内置二次安全验证流程"
    );

    WebSecondVerifyState {
        verify_portrait_id: verify_portrait_id.to_string(),
        encrypt_uid,
        verify_ticket,
        up_verify_ticket: None,
        auth_ticket,
        sms_code_key,
        common_params,
        verify_scene,
        verify_reason,
        biz_params,
        replay_headers,
        ways,
        push_token: None,
        qr_token: None,
        qr_image: None,
        sec_user_id,
        scene_description,
        pending_action: Some(pending_action),
    }
}

fn extract_multi_account_selection(root: &Value) -> Option<(String, String)> {
    let data = root.get("data")?.as_object()?;
    let sub_accounts = data.get("sub_account")?.as_array()?;
    if sub_accounts.is_empty() {
        return None;
    }
    let chosen = sub_accounts
        .iter()
        .find(|item| {
            item.get("is_bind_login_mobile")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .or_else(|| sub_accounts.first())?;
    let sec_uid = chosen
        .get("sec_uid")
        .or_else(|| chosen.get("sec_user_id"))
        .and_then(Value::as_str)?
        .trim()
        .to_string();
    if sec_uid.is_empty() {
        return None;
    }
    let sms_code_key = data
        .get("sms_code_key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    Some((sec_uid, sms_code_key))
}

pub async fn start_phone_login(
    account_id: &str,
    alias: &str,
    mobile: &str,
) -> Result<PhoneLoginSession> {
    let (mobile_digits, _) = normalize_cn_mobile(mobile)?;
    let web_mobile = format!("+86 {mobile_digits}");
    let (
        client,
        jar,
        device,
        csrf_token,
        verify_fp,
        guard_key_hex,
        dtrait_bytes,
        browser_info_enc,
    ) = bootstrap_web_passport_session(account_id).await?;

    let form = vec![
        ("is6Digits", "1".to_string()),
        ("mobile", encode_d_ticket(&web_mobile)),
        ("type", encode_d_ticket("24")),
        ("mix_mode", "1".to_string()),
        ("fixed_mix_mode", "1".to_string()),
    ];
    let (root, _) = post_web_passport_action(
        &client,
        &jar,
        &csrf_token,
        &verify_fp,
        None,
        &dtrait_bytes,
        &browser_info_enc,
        "/passport/web/send_code/",
        &form,
        None,
        &[],
        &[],
    )
    .await
    .context("请求抖音短信验证码失败")?;

    let (top_error, data_error) = response_error_codes(&root);
    if top_error != 0 || data_error != 0 || root.get("message").and_then(Value::as_str) == Some("error") {
        let message = qr_response_string(
            &root,
            &["description", "error_description", "verify_scene_desc"],
        )
        .unwrap_or_default();
        bail!(
            "发送验证码未成功（error={top_error} data_error={data_error} {}）",
            if message.is_empty() {
                "请确认手机号可用".to_string()
            } else {
                message
            }
        );
    }
    let sms_code_key = qr_response_string(&root, &["sms_code_key"]);
    let ticket = qr_response_string(&root, &["ticket", "verify_ticket", "mobile_ticket"]);

    Ok(PhoneLoginSession {
        id: uuid::Uuid::new_v4().simple().to_string(),
        account_id: account_id.to_string(),
        alias: alias.to_string(),
        expires_at: Utc::now().timestamp() + LOGIN_CHALLENGE_TTL_SECS,
        mobile: mobile_digits,
        web_mobile,
        csrf_token,
        verify_fp,
        guard_key_hex,
        dtrait_bytes,
        browser_info_enc,
        sms_code_key,
        ticket,
        second_verify: Arc::new(Mutex::new(None)),
        device,
        jar,
        client,
    })
}

pub async fn verify_phone_login(
    session: &PhoneLoginSession,
    code: &str,
) -> Result<PhoneLoginOutcome> {
    let code = code.trim();
    ensure!(
        code.len() >= 4 && code.len() <= 8 && code.bytes().all(|b| b.is_ascii_digit()),
        "请输入短信验证码"
    );
    let verify_portrait_id = format!("{}.login", uuid::Uuid::new_v4());
    let mut form = vec![
        ("mobile", encode_d_ticket(&session.web_mobile)),
        ("code", encode_d_ticket(code)),
        ("service", "https://www.douyin.com/".to_string()),
        ("mix_mode", "1".to_string()),
        ("fixed_mix_mode", "1".to_string()),
    ];
    let (mut root, mut response_headers) = post_web_passport_action(
        &session.client,
        &session.jar,
        &session.csrf_token,
        &session.verify_fp,
        Some(&session.guard_key_hex),
        &session.dtrait_bytes,
        &session.browser_info_enc,
        "/passport/web/sms_login/",
        &form,
        Some(&verify_portrait_id),
        &[],
        &[],
    )
    .await
    .context("请求抖音短信登录失败")?;

    let (top_error, data_error) = response_error_codes(&root);
    if (top_error == 1454 || data_error == 1454)
        && let Some((sec_uid, sms_code_key)) = extract_multi_account_selection(&root)
    {
        form.push(("safe_mobile_register_to_login", "true".to_string()));
        form.push(("ignore_reused_mobile", "1".to_string()));
        form.push(("sec_uid", sec_uid));
        if !sms_code_key.is_empty() {
            form.push(("sms_code_key", sms_code_key));
            form.push(("sms_code_key_not_mix", "1".to_string()));
        }
        let retry = post_web_passport_action(
            &session.client,
            &session.jar,
            &session.csrf_token,
            &session.verify_fp,
            Some(&session.guard_key_hex),
            &session.dtrait_bytes,
            &session.browser_info_enc,
            "/passport/web/sms_login/",
            &form,
            Some(&verify_portrait_id),
            &[],
            &[],
        )
        .await
        .context("请求抖音多账号短信登录失败")?;
        root = retry.0;
        response_headers = retry.1;
    }

    let (top_error, data_error) = response_error_codes(&root);
    if top_error == 2046 || data_error == 2046 {
        let sv_state = build_web_second_verify_state(
            session,
            &root,
            &response_headers,
            &verify_portrait_id,
            PendingWebLoginAction::Sms {
                code: code.to_string(),
            },
        )
        .await;
        let challenge = sv_state.to_challenge_view(&session.mobile_masked());
        let message = sv_state
            .scene_description
            .clone()
            .unwrap_or_else(|| "抖音要求完成安全身份验证".to_string());
        if let Ok(mut guard) = session.second_verify.lock() {
            *guard = Some(sv_state);
        }
        let mut updated = session.clone();
        updated.expires_at = Utc::now().timestamp() + LOGIN_CHALLENGE_TTL_SECS;
        return Ok(PhoneLoginOutcome::NeedSecondVerify {
            session: updated,
            challenge,
            message,
        });
    }

    let mut confirmed = extract_native_login_record(
        &session.client,
        &session.device,
        &session.jar,
        &session.mobile,
        &root,
        &response_headers,
        "短信验证码登录",
    )
    .await?;
    confirmed.record.guard_key_hex = Some(session.guard_key_hex.clone());
    confirmed.record.guard_server_data = load_internal_guard_server_data(&session.jar);
    if let Some((pem, ver)) = parse_dtrait_pem_and_version(&session.dtrait_bytes) {
        confirmed.record.dtrait_pk1_pem = Some(pem);
        confirmed.record.dtrait_version = Some(ver);
    }
    Ok(PhoneLoginOutcome::Confirmed(confirmed))
}

pub async fn login_with_password(
    account_id: &str,
    alias: &str,
    mobile: &str,
    password: &str,
) -> Result<PhoneLoginOutcome> {
    let (mobile_digits, _) = normalize_cn_mobile(mobile)?;
    let web_mobile = format!("+86 {mobile_digits}");
    let password = password.trim();
    ensure!(!password.is_empty(), "请输入登录密码");
    let (
        client,
        jar,
        device,
        csrf_token,
        verify_fp,
        guard_key_hex,
        dtrait_bytes,
        browser_info_enc,
    ) = bootstrap_web_passport_session(account_id).await?;
    let verify_portrait_id = format!("{}.login", uuid::Uuid::new_v4());
    let session = PhoneLoginSession {
        id: uuid::Uuid::new_v4().simple().to_string(),
        account_id: account_id.to_string(),
        alias: alias.to_string(),
        expires_at: Utc::now().timestamp() + LOGIN_CHALLENGE_TTL_SECS,
        mobile: mobile_digits.clone(),
        web_mobile: web_mobile.clone(),
        csrf_token: csrf_token.clone(),
        verify_fp: verify_fp.clone(),
        guard_key_hex: guard_key_hex.clone(),
        dtrait_bytes: dtrait_bytes.clone(),
        browser_info_enc: browser_info_enc.clone(),
        sms_code_key: None,
        ticket: None,
        second_verify: Arc::new(Mutex::new(None)),
        device: device.clone(),
        jar: jar.clone(),
        client: client.clone(),
    };
    let mut form = vec![
        ("account", encode_d_ticket(&web_mobile)),
        ("password", encode_d_ticket(password)),
        ("need_check_base_info", "true".to_string()),
        ("service", "https://www.douyin.com/".to_string()),
        ("account_type", "0".to_string()),
        ("mix_mode", "1".to_string()),
        ("fixed_mix_mode", "1".to_string()),
    ];
    let (mut root, mut response_headers) = post_web_passport_action(
        &client,
        &jar,
        &csrf_token,
        &verify_fp,
        Some(&guard_key_hex),
        &dtrait_bytes,
        &browser_info_enc,
        "/passport/web/user/login/",
        &form,
        Some(&verify_portrait_id),
        &[],
        &[],
    )
    .await
    .context("请求抖音密码登录失败")?;

    let (top_error, data_error) = response_error_codes(&root);
    if (top_error == 1454 || data_error == 1454)
        && let Some((sec_uid, sms_code_key)) = extract_multi_account_selection(&root)
    {
        form.push(("safe_mobile_register_to_login", "true".to_string()));
        form.push(("ignore_reused_mobile", "1".to_string()));
        form.push(("sec_uid", sec_uid));
        if !sms_code_key.is_empty() {
            form.push(("sms_code_key", sms_code_key));
            form.push(("sms_code_key_not_mix", "1".to_string()));
        }
        let retry = post_web_passport_action(
            &client,
            &jar,
            &csrf_token,
            &verify_fp,
            Some(&guard_key_hex),
            &dtrait_bytes,
            &browser_info_enc,
            "/passport/web/user/login/",
            &form,
            Some(&verify_portrait_id),
            &[],
            &[],
        )
        .await
        .context("请求抖音多账号密码登录失败")?;
        root = retry.0;
        response_headers = retry.1;
    }

    let (top_error, data_error) = response_error_codes(&root);
    if top_error == 2046 || data_error == 2046 {
        let sv_state = build_web_second_verify_state(
            &session,
            &root,
            &response_headers,
            &verify_portrait_id,
            PendingWebLoginAction::Password {
                password: password.to_string(),
            },
        )
        .await;
        let challenge = sv_state.to_challenge_view(&session.mobile_masked());
        let message = sv_state
            .scene_description
            .clone()
            .unwrap_or_else(|| "抖音要求完成安全身份验证".to_string());
        if let Ok(mut guard) = session.second_verify.lock() {
            *guard = Some(sv_state);
        }
        return Ok(PhoneLoginOutcome::NeedSecondVerify {
            session,
            challenge,
            message,
        });
    }

    let mut confirmed = extract_native_login_record(
        &client,
        &device,
        &jar,
        &mobile_digits,
        &root,
        &response_headers,
        "手机号密码登录",
    )
    .await?;
    confirmed.record.guard_key_hex = Some(guard_key_hex);
    confirmed.record.guard_server_data = load_internal_guard_server_data(&jar);
    if let Some((pem, ver)) = parse_dtrait_pem_and_version(&dtrait_bytes) {
        confirmed.record.dtrait_pk1_pem = Some(pem);
        confirmed.record.dtrait_version = Some(ver);
    }
    Ok(PhoneLoginOutcome::Confirmed(confirmed))
}

pub async fn prepare_phone_second_verify(
    session: &PhoneLoginSession,
    way: &str,
) -> Result<(VerificationDelivery, String)> {
    let sv = session
        .second_verify
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .context("当前登录会话没有待完成的二次验证，请重新发起登录")?;
    let ts = Utc::now().timestamp_millis().to_string();

    match way {
        "mobile_sms_verify"
        | "assist_mobile_sms_verify"
        | "mobile_sms_check_or_verify"
        | "mobile_voice_sms_verify"
        | "assist_mobile_voice_sms_verify" => {
            let act_type = sv
                .ways
                .iter()
                .find(|w| w.public.kind == way)
                .and_then(|w| w.act_type)
                .unwrap_or(if way.starts_with("assist_") { 39 } else { 22 });
            let form = vec![
                ("is6Digits", "1".to_string()),
                ("type", encode_d_ticket(&act_type.to_string())),
                ("aid", "6383".to_string()),
                ("std_verify_way", way.to_string()),
                ("mix_mode", "1".to_string()),
                ("fixed_mix_mode", "1".to_string()),
            ];
            if way.contains("voice") {
                let root = post_web_uc_second_verify_action(
                    session,
                    &sv,
                    "/passport/web/send_voice_code/",
                    &form,
                )
                .await?;
                ensure_success(&root, "语音验证码发送")?;
                return Ok((
                    VerificationDelivery {
                        kind: way.to_string(),
                        sms_content: None,
                        channel_mobile: None,
                        qrcode: None,
                    },
                    "语音验证码已拨出，请注意接听绑定手机来电".to_string(),
                ));
            }
            let root = post_web_uc_second_verify_action(
                session,
                &sv,
                "/passport/web/send_code/",
                &form,
            )
            .await?;
            let (te, de) = response_error_codes(&root);
            if (te != 0 || de != 0) && de != 1206 {
                ensure_success(&root, "二次短信验证码发送")?;
            }
            Ok((
                VerificationDelivery {
                    kind: way.to_string(),
                    sms_content: None,
                    channel_mobile: None,
                    qrcode: None,
                },
                "安全验证码已发送至绑定手机，请输入收到的验证码".to_string(),
            ))
        }
        "mobile_up_sms_verify" | "assist_mobile_up_sms_verify" => {
            if let Some(existing) = sv
                .ways
                .iter()
                .find(|w| w.public.kind == way)
                && let Some(content) = existing.sms_content.clone()
                && let Some(channel) = existing.channel_mobile.clone()
            {
                return Ok((
                    VerificationDelivery {
                        kind: way.to_string(),
                        sms_content: Some(content),
                        channel_mobile: Some(channel),
                        qrcode: None,
                    },
                    "请使用绑定手机发送以下短信内容，发送后点击确认".to_string(),
                ));
            }
            let mut query = vec![
                ("aid", "6383".to_string()),
                ("language", "zh".to_string()),
                ("timestamp", ts),
            ];
            if let Some(vt) = sv.verify_ticket.as_deref() {
                query.push(("verify_ticket", vt.to_string()));
            }
            let root = get_web_secondary_verify_action(
                &session.client,
                &session.csrf_token,
                &sv.verify_portrait_id,
                "/passport/upsms/gen_verify_ticket/",
                &query,
            )
            .await?;
            ensure_success(&root, "获取上行短信验证指令")?;
            let data = root
                .get("data")
                .and_then(Value::as_object)
                .context("上行短信响应缺少 data")?;
            let up_vt = first_value_string(data, &["verify_ticket"])
                .context("上行短信响应缺少 verify_ticket")?;
            let sms_content = first_value_string(data, &["sms_content"])
                .context("上行短信响应缺少短信内容")?;
            let channel_mobile = first_value_string(data, &["channel_mobile"])
                .context("上行短信响应缺少接收号码")?;
            if let Ok(mut guard) = session.second_verify.lock()
                && let Some(state) = guard.as_mut()
            {
                state.up_verify_ticket = Some(up_vt);
                if let Some(w) = state
                    .ways
                    .iter_mut()
                    .find(|w| w.public.kind == way)
                {
                    w.sms_content = Some(sms_content.clone());
                    w.channel_mobile = Some(channel_mobile.clone());
                }
            }
            Ok((
                VerificationDelivery {
                    kind: way.to_string(),
                    sms_content: Some(sms_content),
                    channel_mobile: Some(channel_mobile),
                    qrcode: None,
                },
                "请使用绑定手机发送短信，完成后点击「我已发送短信，立即验证」".to_string(),
            ))
        }
        "push_verify" | "mobile_push_verify" | "aweme_push_verify" => {
            let vt = sv
                .verify_ticket
                .as_deref()
                .context("当前会话缺少 verify_ticket，请选择其他验证方式")?;
            let mut form = vec![
                ("is_new_login", "1".to_string()),
                ("verify_ticket", vt.to_string()),
            ];
            if let Some(sec_uid) = sv.sec_user_id.as_deref() {
                form.push(("sec_user_id", sec_uid.to_string()));
            }
            let (root, _) = post_web_passport_action(
                &session.client,
                &session.jar,
                &session.csrf_token,
                &session.verify_fp,
                None,
                &session.dtrait_bytes,
                &session.browser_info_enc,
                "/passport/web/send_push/",
                &form,
                Some(&sv.verify_portrait_id),
                &[],
                &[],
            )
            .await?;
            ensure_success(&root, "发送抖音 App 确认推送")?;
            let token = qr_response_string(&root, &["token"])
                .context("推送确认响应未返回轮询 token")?;
            if let Ok(mut guard) = session.second_verify.lock()
                && let Some(state) = guard.as_mut()
            {
                state.push_token = Some(token);
            }
            Ok((
                VerificationDelivery {
                    kind: way.to_string(),
                    sms_content: None,
                    channel_mobile: None,
                    qrcode: None,
                },
                "已向手机抖音 App 发送确认通知，请在手机端点击「允许登录」".to_string(),
            ))
        }
        "qr_code_verify" | "scan_qrcode_verify" => {
            let verify_scene = sv
                .verify_scene
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("account_login")
                .to_string();
            let verify_reason = sv.verify_reason.clone().unwrap_or_default();
            let qr_form = vec![
                ("aid", "6383".to_string()),
                ("verify_type", String::new()),
                ("next", "https://www.douyin.com/".to_string()),
                ("need_record", "1".to_string()),
                ("scene", "secondary_verify".to_string()),
                ("verify_scene", verify_scene),
                ("verify_reason", verify_reason),
                ("std_verify_way", "qr_code_verify".to_string()),
                ("source", "app".to_string()),
            ];
            let qr_root = post_web_uc_second_verify_action(
                session,
                &sv,
                "/passport/web/get_qrcode/",
                &qr_form,
            )
            .await?;
            ensure_success(&qr_root, "获取安全验证二维码")?;
            let qr_data = qr_root
                .get("data")
                .and_then(Value::as_object)
                .context("验证二维码响应缺少 data")?;
            let qr_token = first_value_string(qr_data, &["token"])
                .context("验证二维码响应缺少 token")?;
            let qrcode = normalize_qrcode(qr_data.get("qrcode"))?;
            if let Ok(mut guard) = session.second_verify.lock()
                && let Some(state) = guard.as_mut()
            {
                state.qr_token = Some(qr_token);
                state.qr_image = Some(qrcode.clone());
            }
            Ok((
                VerificationDelivery {
                    kind: way.to_string(),
                    sms_content: None,
                    channel_mobile: None,
                    qrcode: Some(qrcode),
                },
                "请使用手机抖音 App 扫描上方安全验证二维码".to_string(),
            ))
        }
        "face_verify" | "qr_code_face_verify" | "identity_verify" => {
            let entry = sv.ways.iter().find(|w| w.public.kind == way).cloned();
            let way_scene = entry
                .as_ref()
                .and_then(|w| w.scene.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "account_scan_face_verify".to_string());
            let cert_app_id = entry
                .as_ref()
                .and_then(|w| w.cert_app_id.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "6383".to_string());
            let flow = entry
                .as_ref()
                .and_then(|w| w.flow.clone())
                .unwrap_or_default();
            let initial_auth_ticket = entry
                .as_ref()
                .and_then(|w| w.auth_ticket.clone())
                .or_else(|| sv.auth_ticket.clone())
                .unwrap_or_default();
            let auth_form = vec![
                ("mode", "1".to_string()),
                ("verify_scene", "secondary_verify".to_string()),
                ("scene", way_scene.clone()),
                ("std_verify_way", "face_verify".to_string()),
                ("verify_way", "face_verify".to_string()),
                ("cert_app_id", cert_app_id.clone()),
                ("flow", flow.clone()),
                ("auth_ticket", initial_auth_ticket.clone()),
                ("aid", "6383".to_string()),
            ];
            let auth_root = post_web_uc_second_verify_action(
                session,
                &sv,
                "/passport/safe/get_auth_ticket/v1/",
                &auth_form,
            )
            .await;
            let auth_ticket = match auth_root {
                Ok(ref root) => qr_response_string(root, &["auth_ticket"])
                    .filter(|s| !s.is_empty())
                    .or_else(|| (!initial_auth_ticket.is_empty()).then_some(initial_auth_ticket.clone()))
                    .ok_or_else(|| {
                        ensure_success(root, "获取刷脸验证票据").err().unwrap_or_else(|| {
                            anyhow::anyhow!("未获取到刷脸验证 auth_ticket")
                        })
                    })?,
                Err(err) => {
                    if !initial_auth_ticket.is_empty() {
                        initial_auth_ticket
                    } else {
                        return Err(err);
                    }
                }
            };
            let cert_url = format!(
                "aweme://aweme/cert/verify?scene={way_scene}&cert_app_id={cert_app_id}&flow={flow}&ticket={auth_ticket}&ignore_result=true"
            );
            let qrcode = render_qr_svg_data_url(&cert_url)?;
            if let Ok(mut guard) = session.second_verify.lock()
                && let Some(state) = guard.as_mut()
            {
                state.auth_ticket = Some(auth_ticket);
                state.qr_image = Some(qrcode.clone());
            }
            Ok((
                VerificationDelivery {
                    kind: way.to_string(),
                    sms_content: None,
                    channel_mobile: None,
                    qrcode: Some(qrcode),
                },
                "请使用手机抖音 App 扫描上方二维码完成本人刷脸核验".to_string(),
            ))
        }
        _ => bail!("当前验证方式无需预先发送凭证"),
    }
}

async fn replay_web_login_after_verify(
    session: &PhoneLoginSession,
    sv: &WebSecondVerifyState,
    verified_ticket: Option<&str>,
    verified_way: &str,
) -> Result<ConfirmedLogin> {
    let action = sv
        .pending_action
        .as_ref()
        .context("登录会话缺少原始提交凭据，请重新发起登录")?;
    let (path, label, mut form): (&str, &str, Vec<(&str, String)>) = match action {
        PendingWebLoginAction::Sms { code } => (
            "/passport/web/sms_login/",
            "短信验证码登录",
            vec![
                ("mobile", encode_d_ticket(&session.web_mobile)),
                ("code", encode_d_ticket(code)),
                ("service", "https://www.douyin.com/".to_string()),
                ("mix_mode", "1".to_string()),
                ("fixed_mix_mode", "1".to_string()),
            ],
        ),
        PendingWebLoginAction::Password { password } => (
            "/passport/web/user/login/",
            "手机号密码登录",
            vec![
                ("account", encode_d_ticket(&session.web_mobile)),
                ("password", encode_d_ticket(password)),
                ("need_check_base_info", "true".to_string()),
                ("service", "https://www.douyin.com/".to_string()),
                ("account_type", "0".to_string()),
                ("mix_mode", "1".to_string()),
                ("fixed_mix_mode", "1".to_string()),
            ],
        ),
    };

    let mut dynamic_keys: Vec<(String, String)> = sv.biz_params.clone();
    if !verified_way.trim().is_empty() {
        if let Some(existing) = dynamic_keys.iter_mut().find(|(k, _)| k == "std_verify_way") {
            existing.1 = verified_way.to_string();
        } else {
            dynamic_keys.push(("std_verify_way".to_string(), verified_way.to_string()));
        }
    }
    if let Some(key) = sv.sms_code_key.as_deref().filter(|s| !s.is_empty()) {
        if !dynamic_keys.iter().any(|(k, _)| k == "sms_code_key") {
            dynamic_keys.push(("sms_code_key".to_string(), key.to_string()));
        }
        if !dynamic_keys.iter().any(|(k, _)| k == "sms_code_key_not_mix") {
            dynamic_keys.push(("sms_code_key_not_mix".to_string(), "1".to_string()));
        }
    }
    let has_std_verify_token = dynamic_keys
        .iter()
        .any(|(k, v)| k == "std_verify_token" && !v.is_empty());
    if let Some(vt) = verified_ticket
        .or(sv.verify_ticket.as_deref())
        .filter(|s| !s.is_empty())
    {
        if !has_std_verify_token
            || verified_ticket.is_some_and(|s| !s.is_empty())
            || dynamic_keys
                .iter()
                .any(|(k, _)| k == "verify_ticket" || k == "ticket")
        {
            dynamic_keys.retain(|(k, _)| k != "verify_ticket" && k != "ticket");
            dynamic_keys.push(("verify_ticket".to_string(), vt.to_string()));
            dynamic_keys.push(("ticket".to_string(), vt.to_string()));
        }
    }

    let mut full_pairs: Vec<(&str, String)> = form.clone();
    for (k, v) in &dynamic_keys {
        full_pairs.push((k.as_str(), v.clone()));
    }

    let (mut root, mut response_headers) = post_web_passport_action(
        &session.client,
        &session.jar,
        &session.csrf_token,
        &session.verify_fp,
        Some(&session.guard_key_hex),
        &session.dtrait_bytes,
        &session.browser_info_enc,
        path,
        &full_pairs,
        Some(&sv.verify_portrait_id),
        &[],
        &sv.replay_headers,
    )
    .await
    .context("二次验证通过后重放登录请求失败")?;

    let (top_error, data_error) = response_error_codes(&root);
    tracing::info!(
        verified_way,
        has_verified_ticket = verified_ticket.is_some_and(|s| !s.is_empty()),
        top_error,
        data_error,
        has_strong_cookie = has_strong_auth_cookie(&cookie_snapshot(&session.jar)),
        "二次验证后重放登录响应"
    );
    if (top_error != 0 || data_error != 0)
        && has_std_verify_token
        && let Some(vt) = verified_ticket.filter(|s| !s.is_empty())
    {
        let mut retry_pairs: Vec<(&str, String)> = form.clone();
        for (k, v) in &dynamic_keys {
            if k != "verify_ticket" && k != "ticket" && k != "auth_ticket" {
                retry_pairs.push((k.as_str(), v.clone()));
            }
        }
        retry_pairs.push(("auth_ticket", vt.to_string()));
        let retry = post_web_passport_action(
            &session.client,
            &session.jar,
            &session.csrf_token,
            &session.verify_fp,
            Some(&session.guard_key_hex),
            &session.dtrait_bytes,
            &session.browser_info_enc,
            path,
            &retry_pairs,
            Some(&sv.verify_portrait_id),
            &[],
            &sv.replay_headers,
        )
        .await?;
        root = retry.0;
        response_headers = retry.1;
    }

    let (top_error, data_error) = response_error_codes(&root);
    if (top_error == 1454 || data_error == 1454)
        && let Some((sec_uid, sms_code_key)) = extract_multi_account_selection(&root)
    {
        form.push(("safe_mobile_register_to_login", "true".to_string()));
        form.push(("ignore_reused_mobile", "1".to_string()));
        form.push(("sec_uid", sec_uid));
        if !sms_code_key.is_empty() {
            form.push(("sms_code_key", sms_code_key));
            form.push(("sms_code_key_not_mix", "1".to_string()));
        }
        for (k, v) in &dynamic_keys {
            if k != "sms_code_key" && k != "sms_code_key_not_mix" {
                form.push((k.as_str(), v.clone()));
            }
        }
        let retry = post_web_passport_action(
            &session.client,
            &session.jar,
            &session.csrf_token,
            &session.verify_fp,
            Some(&session.guard_key_hex),
            &session.dtrait_bytes,
            &session.browser_info_enc,
            path,
            &form,
            Some(&sv.verify_portrait_id),
            &[],
            &sv.replay_headers,
        )
        .await?;
        root = retry.0;
        response_headers = retry.1;
    }

    let (top_error, data_error) = response_error_codes(&root);
    if (top_error != 0 || data_error != 0) && has_strong_auth_cookie(&cookie_snapshot(&session.jar)) {
        let empty_ok = serde_json::json!({
            "message": "success",
            "data": {
                "sec_user_id": sv.sec_user_id.clone().unwrap_or_default()
            }
        });
        let mut confirmed = extract_native_login_record(
            &session.client,
            &session.device,
            &session.jar,
            &session.mobile,
            &empty_ok,
            &response_headers,
            label,
        )
        .await?;
        confirmed.record.guard_key_hex = Some(session.guard_key_hex.clone());
        confirmed.record.guard_server_data = load_internal_guard_server_data(&session.jar);
        if let Some((pem, ver)) = parse_dtrait_pem_and_version(&session.dtrait_bytes) {
            confirmed.record.dtrait_pk1_pem = Some(pem);
            confirmed.record.dtrait_version = Some(ver);
        }
        return Ok(confirmed);
    }

    if let Some(sec_uid) = sv.sec_user_id.as_deref().filter(|s| !s.is_empty())
        && let Some(data) = root.get_mut("data").and_then(Value::as_object_mut)
        && !data.contains_key("sec_user_id")
    {
        data.insert("sec_user_id".to_string(), Value::String(sec_uid.to_string()));
    }
    let mut confirmed = extract_native_login_record(
        &session.client,
        &session.device,
        &session.jar,
        &session.mobile,
        &root,
        &response_headers,
        label,
    )
    .await?;
    confirmed.record.guard_key_hex = Some(session.guard_key_hex.clone());
    confirmed.record.guard_server_data = load_internal_guard_server_data(&session.jar);
    if let Some((pem, ver)) = parse_dtrait_pem_and_version(&session.dtrait_bytes) {
        confirmed.record.dtrait_pk1_pem = Some(pem);
        confirmed.record.dtrait_version = Some(ver);
    }
    Ok(confirmed)
}

pub async fn submit_phone_second_verify(
    session: &PhoneLoginSession,
    way: &str,
    code: Option<&str>,
    password: Option<&str>,
) -> Result<PhoneLoginOutcome> {
    let sv = session
        .second_verify
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .context("当前登录会话没有待完成的二次验证，请重新发起登录")?;

    if has_strong_auth_cookie(&cookie_snapshot(&session.jar)) {
        let empty_ok = serde_json::json!({
            "message": "success",
            "data": {
                "sec_user_id": sv.sec_user_id.clone().unwrap_or_default()
            }
        });
        let empty_headers = header::HeaderMap::new();
        if let Ok(mut confirmed) = extract_native_login_record(
            &session.client,
            &session.device,
            &session.jar,
            &session.mobile,
            &empty_ok,
            &empty_headers,
            "二次安全验证登录",
        )
        .await
        {
            confirmed.record.guard_key_hex = Some(session.guard_key_hex.clone());
            confirmed.record.guard_server_data = load_internal_guard_server_data(&session.jar);
            if let Some((pem, ver)) = parse_dtrait_pem_and_version(&session.dtrait_bytes) {
                confirmed.record.dtrait_pk1_pem = Some(pem);
                confirmed.record.dtrait_version = Some(ver);
            }
            if let Ok(mut guard) = session.second_verify.lock() {
                *guard = None;
            }
            return Ok(PhoneLoginOutcome::Confirmed(confirmed));
        }
    }

    let verified_ticket: Option<String> = match way {
        "mobile_sms_verify"
        | "assist_mobile_sms_verify"
        | "mobile_sms_check_or_verify"
        | "mobile_voice_sms_verify"
        | "assist_mobile_voice_sms_verify" => {
            let clean_code = code.unwrap_or_default().trim();
            ensure!(
                clean_code.len() >= 4
                    && clean_code.len() <= 8
                    && clean_code.bytes().all(|b| b.is_ascii_digit()),
                "请输入有效的二次安全验证码"
            );
            let act_type = sv
                .ways
                .iter()
                .find(|w| w.public.kind == way)
                .and_then(|w| w.act_type)
                .unwrap_or(if way.starts_with("assist_") { 39 } else { 22 });
            let form = vec![
                ("code", encode_d_ticket(clean_code)),
                ("type", encode_d_ticket(&act_type.to_string())),
                ("aid", "6383".to_string()),
                ("std_verify_way", way.to_string()),
                ("mix_mode", "1".to_string()),
                ("fixed_mix_mode", "1".to_string()),
            ];
            let mut root = post_web_uc_second_verify_action(
                session,
                &sv,
                "/passport/web/validate_code/",
                &form,
            )
            .await?;
            let (te, de) = response_error_codes(&root);
            if te != 0 || de != 0 {
                let fallback_root = post_web_uc_second_verify_action(
                    session,
                    &sv,
                    "/passport/web/mobile/check_code/",
                    &form,
                )
                .await?;
                root = fallback_root;
            }
            ensure_success(&root, "二次短信验证码校验")?;
            qr_response_string(&root, &["ticket", "verify_ticket"])
        }
        "pwd_verify" => {
            let clean_pwd = password.unwrap_or_default().trim();
            ensure!(!clean_pwd.is_empty(), "请输入抖音登录密码");
            let form = vec![
                ("password", encode_d_ticket(clean_pwd)),
                ("aid", "6383".to_string()),
                ("std_verify_way", "pwd_verify".to_string()),
                ("mix_mode", "1".to_string()),
                ("fixed_mix_mode", "1".to_string()),
            ];
            let root = post_web_uc_second_verify_action(
                session,
                &sv,
                "/passport/web/account/verify/",
                &form,
            )
            .await?;
            ensure_success(&root, "登录密码核验")?;
            qr_response_string(&root, &["ticket", "verify_ticket"])
        }
        "mobile_up_sms_verify" | "assist_mobile_up_sms_verify" => {
            let is_oper_staff = sv
                .ways
                .iter()
                .find(|w| w.public.kind == way)
                .map(|w| w.is_oper_staff_user)
                .unwrap_or(false);
            let up_path = if is_oper_staff {
                "/passport/upsms/chain_mobile/verify/"
            } else if way == "assist_mobile_up_sms_verify" {
                "/passport/upsms/safe_mobile/verify/"
            } else {
                "/passport/upsms/verify/"
            };
            let mut last_err = None;
            let mut found_ticket = None;
            for attempt in 0..3 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                }
                let mut form = vec![
                    ("aid", "6383".to_string()),
                    ("std_verify_way", way.to_string()),
                ];
                if let Some(up_vt) = sv.up_verify_ticket.as_deref().filter(|s| !s.is_empty()) {
                    form.push(("verify_ticket", up_vt.to_string()));
                }
                if is_oper_staff || way == "assist_mobile_up_sms_verify" {
                    form.push(("upstream_verify_type", "1".to_string()));
                }
                let root = post_web_uc_second_verify_action(session, &sv, up_path, &form).await?;
                match ensure_success(&root, "上行短信核验") {
                    Ok(()) => {
                        found_ticket = qr_response_string(&root, &["ticket", "verify_ticket"]);
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                    }
                }
            }
            if let Some(err) = last_err {
                return Err(err);
            }
            found_ticket
        }
        "push_verify" | "mobile_push_verify" | "aweme_push_verify" => {
            let push_token = sv
                .push_token
                .as_deref()
                .context("请先点击发送手机抖音确认通知")?;
            let form = vec![("token", push_token.to_string())];
            let (root, _) = post_web_passport_action(
                &session.client,
                &session.jar,
                &session.csrf_token,
                &session.verify_fp,
                None,
                &session.dtrait_bytes,
                &session.browser_info_enc,
                "/passport/web/check_push_result/",
                &form,
                Some(&sv.verify_portrait_id),
                &[],
                &[],
            )
            .await?;
            let status = qr_response_string(&root, &["status"]).unwrap_or_default();
            match status.as_str() {
                "allowed" => qr_response_string(&root, &["ticket", "verify_ticket"]),
                "rejected" | "expired" => bail!("手机端已拒绝或确认通知已过期，请重新发送通知"),
                _ => {
                    return Ok(PhoneLoginOutcome::NeedSecondVerify {
                        session: session.clone(),
                        challenge: sv.to_challenge_view(&session.mobile_masked()),
                        message: "正在等待手机抖音 App 点击「允许登录」...".to_string(),
                    });
                }
            }
        }
        "qr_code_verify" | "scan_qrcode_verify" => {
            let qr_token = sv
                .qr_token
                .as_deref()
                .context("请先生成安全验证二维码")?;
            let verify_scene = sv
                .verify_scene
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("account_login")
                .to_string();
            let verify_reason = sv.verify_reason.clone().unwrap_or_default();
            let form = vec![
                ("aid", "6383".to_string()),
                ("token", qr_token.to_string()),
                ("verify_type", String::new()),
                ("need_record", "1".to_string()),
                ("scene", "secondary_verify".to_string()),
                ("verify_scene", verify_scene),
                ("verify_reason", verify_reason),
                ("std_verify_way", "qr_code_verify".to_string()),
            ];
            let root = post_web_uc_second_verify_action(
                session,
                &sv,
                "/passport/mobile/validate_by_qrcode/",
                &form,
            )
            .await?;
            let status = qr_response_string(&root, &["status"]).unwrap_or_default();
            let (te, de) = response_error_codes(&root);
            let has_strong_cookie = has_strong_auth_cookie(&cookie_snapshot(&session.jar));
            tracing::info!(
                way,
                status = %status,
                top_error = te,
                data_error = de,
                has_strong_cookie,
                "扫码安全验证轮询状态"
            );
            if has_strong_cookie {
                qr_response_string(&root, &["ticket", "verify_ticket"])
            } else {
            match status.as_str() {
                "3" | "confirmed" => {
                    if let Some(redirect_url) = qr_response_string(&root, &["redirect_url"])
                        .filter(|u| u.starts_with("https://"))
                    {
                        let _ = session
                            .client
                            .get(&redirect_url)
                            .header(header::REFERER, "https://www.douyin.com/")
                            .send()
                            .await;
                    }
                    qr_response_string(&root, &["ticket", "verify_ticket"])
                }
                "4" | "refused" => bail!("手机端已拒绝本次安全验证，请重新生成二维码"),
                "5" | "expired" => {
                    if let Some(data) = root.get("data").and_then(Value::as_object)
                        && let Some(new_token) = first_value_string(data, &["token"])
                        && let Ok(new_qr) = normalize_qrcode(data.get("qrcode"))
                    {
                        if let Ok(mut guard) = session.second_verify.lock()
                            && let Some(state) = guard.as_mut()
                        {
                            state.qr_token = Some(new_token);
                            state.qr_image = Some(new_qr);
                        }
                        return Ok(PhoneLoginOutcome::NeedSecondVerify {
                            session: session.clone(),
                            challenge: sv.to_challenge_view(&session.mobile_masked()),
                            message: "二维码已更新，请使用手机抖音 App 扫码完成安全验证...".to_string(),
                        });
                    }
                    bail!("安全验证二维码已过期，请重新生成二维码")
                }
                "2" | "scanned" => {
                    return Ok(PhoneLoginOutcome::NeedSecondVerify {
                        session: session.clone(),
                        challenge: sv.to_challenge_view(&session.mobile_masked()),
                        message: "手机已扫码，请在手机抖音内点击确认...".to_string(),
                    });
                }
                "1" | "new" => {
                    return Ok(PhoneLoginOutcome::NeedSecondVerify {
                        session: session.clone(),
                        challenge: sv.to_challenge_view(&session.mobile_masked()),
                        message: "等待使用手机抖音 App 扫码完成安全验证...".to_string(),
                    });
                }
                _ => {
                    if te != 0 || de != 0 {
                        ensure_success(&root, "扫码安全验证状态查询")?;
                    }
                    if let Some(ticket) =
                        qr_response_string(&root, &["ticket", "verify_ticket"]).filter(|s| !s.is_empty())
                    {
                        Some(ticket)
                    } else {
                    return Ok(PhoneLoginOutcome::NeedSecondVerify {
                        session: session.clone(),
                        challenge: sv.to_challenge_view(&session.mobile_masked()),
                        message: "等待使用手机抖音 App 扫码完成安全验证...".to_string(),
                    });
                    }
                }
            }
            }
        }
        "face_verify" | "qr_code_face_verify" | "identity_verify" => {
            let entry = sv.ways.iter().find(|w| w.public.kind == way).cloned();
            let way_scene = entry
                .as_ref()
                .and_then(|w| w.scene.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "account_scan_face_verify".to_string());
            let auth_ticket = sv
                .auth_ticket
                .clone()
                .or_else(|| entry.and_then(|w| w.auth_ticket))
                .filter(|s| !s.is_empty())
                .context("请先生成刷脸验证二维码")?;
            let form = vec![
                ("need_auth_action_detail", "true".to_string()),
                ("auth_ticket", auth_ticket),
                ("scene", way_scene),
                ("aid", "6383".to_string()),
                ("std_verify_way", "face_verify".to_string()),
            ];
            let root = post_web_uc_second_verify_action(
                session,
                &sv,
                "/passport/safe/verify_auth_ticket/",
                &form,
            )
            .await?;
            let (te, de) = response_error_codes(&root);
            let has_strong_cookie = has_strong_auth_cookie(&cookie_snapshot(&session.jar));
            let ticket_opt =
                qr_response_string(&root, &["ticket", "verify_ticket"]).filter(|s| !s.is_empty());
            tracing::info!(
                way,
                top_error = te,
                data_error = de,
                has_ticket = ticket_opt.is_some(),
                has_strong_cookie,
                "刷脸安全验证轮询状态"
            );
            if has_strong_cookie || (te == 0 && de == 0 && ticket_opt.is_some()) {
                ticket_opt
            } else {
                let has_action_query = root
                    .get("data")
                    .and_then(Value::as_object)
                    .and_then(|d| d.get("has_action_query"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if has_action_query {
                    bail!("刷脸验证二维码已失效或核验未通过，请重新生成二维码");
                }
                return Ok(PhoneLoginOutcome::NeedSecondVerify {
                    session: session.clone(),
                    challenge: sv.to_challenge_view(&session.mobile_masked()),
                    message: "等待使用手机抖音 App 扫码完成本人刷脸核验...".to_string(),
                });
            }
        }
        _ => bail!("不支持的二次验证方式: {way}"),
    };

    let confirmed =
        replay_web_login_after_verify(session, &sv, verified_ticket.as_deref(), way).await?;
    if let Ok(mut guard) = session.second_verify.lock() {
        *guard = None;
    }
    Ok(PhoneLoginOutcome::Confirmed(confirmed))
}

async fn extract_native_login_record(
    client: &Client,
    device: &NativeDevice,
    jar: &Jar,
    fallback_mobile: &str,
    root: &Value,
    response_headers: &header::HeaderMap,
    label: &str,
) -> Result<ConfirmedLogin> {
    let (top_error, data_error) = response_error_codes(root);
    if top_error != 0 || data_error != 0 {
        let message = qr_response_string(
            root,
            &["description", "error_description", "verify_scene_desc"],
        )
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            if top_error == 3052 || data_error == 3052 {
                "验证码不正确或已过期".to_string()
            } else {
                format!("{label}未成功（error={top_error} data_error={data_error}）")
            }
        });
        bail!("{message}（error={top_error} data_error={data_error}）");
    }

    let mut identity = root
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if first_value_string(&identity, &["sec_user_id", "sec_uid"])
        .filter(|value| !value.trim().is_empty())
        .is_none()
        && let Some(header_sec_uid) = header_string(response_headers, "d-ticket-sec-uid")
    {
        identity.insert("sec_user_id".to_string(), Value::String(header_sec_uid));
    }
    if first_positive_uid(&identity).is_none()
        || first_value_string(&identity, &["sec_user_id", "sec_uid"])
            .filter(|value| !value.trim().is_empty())
            .is_none()
    {
        let profile = fetch_profile_with(client, device, &identity).await?;
        merge_identity_fields(&mut identity, Some(&profile));
    }

    let uid = first_positive_uid(&identity)
        .with_context(|| format!("{label}成功，但未返回有效 UID"))?;
    let sec_uid = first_value_string(&identity, &["sec_user_id", "sec_uid"])
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{label}成功，但未返回 sec_user_id"))?;
    let nickname = first_value_string(&identity, &["name", "username", "nickname", "screen_name"])
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "抖音用户".to_string());
    let avatar_url = avatar_url(&identity);
    let cookie = cookie_snapshot(jar);
    ensure!(
        has_strong_auth_cookie(&cookie),
        "{label}成功，但未收到可用的会话凭证"
    );
    let now = Utc::now().timestamp();
    let record = NativeSessionRecord {
        device: device.clone(),
        cookie: cookie.clone(),
        uid,
        sec_uid,
        nickname,
        avatar_url,
        mobile: first_value_string(&identity, &["mobile"])
            .unwrap_or_else(|| fallback_mobile.to_string()),
        session_key: first_value_string(&identity, &["session_key"])
            .or_else(|| cookie_value(&cookie, "sessionid"))
            .or_else(|| cookie_value(&cookie, "sid_tt")),
        d_ticket: first_value_string(&identity, &["d_ticket"])
            .or_else(|| header_string(response_headers, "x-tt-d-ticket"))
            .or_else(|| cookie_value(&cookie, "d_ticket")),
        x_tt_token: header_string(response_headers, "x-tt-token")
            .or_else(|| first_value_string(&identity, &["X-Tt-Token", "x_tt_token"]))
            .or_else(|| cookie_value(&cookie, "x_tt_token")),
        token_encrypted: first_value_string(&identity, &["token_encrypted", "TokenEncrypted"]),
        ts_sign: first_value_string(&identity, &["ts_sign"]),
        attest_ts_sign: first_value_string(&identity, &["attest_ts_sign"]),
        mfa_token: first_value_string(&identity, &["mfa_token"])
            .or_else(|| header_string(response_headers, "x-tt-passport-mfa-token"))
            .or_else(|| cookie_value(&cookie, "passport_mfa_token")),
        guard_key_hex: None,
        guard_server_data: load_internal_guard_server_data(jar),
        dtrait_pk1_pem: None,
        dtrait_version: None,
        logged_in_at: now,
        last_verified_at: Some(now),
        last_beat_at: None,
    };
    record.validate()?;
    Ok(ConfirmedLogin {
        record,
        status: "confirmed".to_string(),
        message: format!("{label}成功"),
    })
}

pub async fn start(account_id: &str, alias: &str) -> Result<LoginSession> {
    let device = NativeDevice::derive(account_id);
    device.validate()?;
    let jar = Arc::new(Jar::default());
    let client = Client::builder()
        .cookie_provider(jar.clone())
        .user_agent(device.user_agent.clone())
        .timeout(Duration::from_secs(20))
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("创建原生登录 HTTP 客户端失败")?;
    // Oct-22 可登录版的客户端身份 + 表单设备身份线格式保持不变；本轮唯一变量
    // 是补回设备登记与 x-tt-dt 绑定：上次验证 1049 已消失、确认环节变成 2156
    // 「来源设备未生效」，与确认页“未获取到信息”指向同一缺陷。不带 TicketGuard 头。
    let device = match register_login_device(&client, device.clone()).await {
        Ok(device) => device,
        Err(error) => {
            tracing::warn!(
                reason = %error,
                "登录设备登记未完成，改用本地推导设备号继续申请二维码"
            );
            device
        }
    };

    let form = qr_get_form(&device);
    let response = passport_request(
        &client,
        &jar,
        Method::POST,
        "/passport/mobile/get_qrcode/",
        &device_query(&device),
        &form,
        device.device_token.as_deref(),
    )
    .await
    .context("请求抖音 App 二维码失败")?;
    let response_status = response.status();
    let response_headers = response.headers().clone();
    let bytes = read_limited_body(response, "二维码响应").await?;
    let root: Value = serde_json::from_slice(&bytes).context("抖音二维码响应不是合法 JSON")?;
    let (top_error, data_error) = response_error_codes(&root);
    if top_error != 0 || data_error != 0 {
        tracing::warn!(
            http_status = response_status.as_u16(),
            top_error,
            data_error,
            has_x_ms_token = header_string(&response_headers, "x-ms-token")
                .is_some_and(|value| !value.trim().is_empty()),
            "抖音二维码请求被拒绝"
        );
    }
    if let Err(error) = ensure_success(&root, "抖音二维码") {
        let message = error.to_string();
        if message.contains("4044") {
            // 4044 的文案在官方响应里固定写成“请升级应用”，但 108 实测它只由
            // Passport saas 标记缺失（is_from_ttaccountsdk 等）触发，与版本、
            // 设备型号、TicketGuard 证书都无关。这里给出可定位的真实原因。
                tracing::warn!(
                    top_error,
                    data_error,
                    "抖音二维码 4044：按 Passport 请求合同缺陷处理，非应用版本问题"
                );
            bail!("{message}");
        }
        return Err(error);
    }
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .context("抖音二维码响应缺少 data")?;
    let frontier_keys = data
        .get("frontier_params")
        .and_then(Value::as_object)
        .map(|params| {
            params
                .keys()
                .take(16)
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let is_frontier = data
        .get("is_frontier")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_qrcode_index_url = !value_string(data.get("qrcode_index_url")).trim().is_empty();
    tracing::info!(
        root_keys = %json_object_keys(&root, 32),
        data_keys = %data.keys().take(48).cloned().collect::<Vec<_>>().join(","),
        expire_time_raw = ?data.get("expire_time"),
        expire_time = ?value_i64(data.get("expire_time")),
        is_frontier,
        frontier_param_keys = %frontier_keys,
        has_qrcode_index_url,
        "抖音二维码响应字段"
    );
    let token = value_string(data.get("token")).trim().to_string();
    ensure!(
        !token.is_empty() && token.len() <= 8192,
        "抖音二维码 token 无效"
    );
    let qrcode = normalize_qrcode(data.get("qrcode"))?;
    let now = Utc::now().timestamp();
    let expires_at = resolve_login_expiry(value_i64(data.get("expire_time")), now);

    Ok(LoginSession {
        id: uuid::Uuid::new_v4().simple().to_string(),
        account_id: account_id.to_string(),
        alias: alias.to_string(),
        qrcode,
        expires_at,
        token,
        device,
        jar,
        client,
        verification: Arc::new(Mutex::new(None)),
        scan_profile: Arc::new(Mutex::new(None)),
        seen_scan: Arc::new(AtomicBool::new(false)),
        busy_polls: Arc::new(AtomicU32::new(0)),
    })
}

pub async fn poll(session: &LoginSession) -> Result<LoginPoll> {
    let now = Utc::now().timestamp();
    if session.is_expired(now) {
        return Ok(LoginPoll::Terminal {
            status: "expired".to_string(),
            message: if session.qr_expired(now) && session.verification_snapshot().is_none() {
                "二维码已过期，请重新获取".to_string()
            } else {
                "身份验证已超时，请重新获取二维码".to_string()
            },
        });
    }
    if session.qr_expired(now) {
        if let Some(verification) = session.verification_snapshot() {
            let verification = session.with_scan_profile(verification);
            return Ok(LoginPoll::Pending {
                status: "verifying".to_string(),
                challenge: Some(LoginChallenge::from_verification(&verification)),
            });
        }
    }

    tracing::info!(
        has_passport_csrf_token = passport_csrf_token(&session.jar).is_some(),
        "准备轮询抖音 App 二维码状态"
    );
    let checked = fetch_qr_check(session)
        .await
        .context("轮询抖音 App 二维码状态失败")?;
    let response_status = checked.status;
    let response_headers = checked.headers;
    let root = checked.root;
    let transport = checked.transport;
    let status = qr_response_status(&root);
    let (top_error, data_error) = response_error_codes(&root);
    if !bare_qr_busy(&root) {
        session.busy_polls.store(0, Ordering::Relaxed);
    }
    let set_cookie_count = response_headers.get_all(header::SET_COOKIE).iter().count();
    let set_cookie_names = set_cookie_names(&response_headers);
    let root_keys = json_object_keys(&root, 32);
    let data_keys = root
        .get("data")
        .and_then(Value::as_object)
        .map(|data| data.keys().take(48).cloned().collect::<Vec<_>>().join(","))
        .unwrap_or_default();
    let response_token = qr_response_string(&root, &["token"]);
    let token_matches_session = response_token
        .as_deref()
        .is_some_and(|token| token == session.token);
    let error_name = qr_response_string(&root, &["error_name"]).unwrap_or_default();
    let description = compact_diagnostic(
        &qr_response_string(&root, &["description"]).unwrap_or_default(),
        96,
    );
    let message = compact_diagnostic(
        &qr_response_string(&root, &["message"]).unwrap_or_default(),
        96,
    );
    let diagnostic_status = matches!(
        status.as_str(),
        "scanned" | "confirmed" | "success" | "authorized" | "expired" | "refused" | "failed"
    ) || top_error != 0
        || data_error != 0;
    if diagnostic_status {
        tracing::info!(
            http_status = response_status.as_u16(),
            status = %status,
            top_error,
            data_error,
            root_keys = %root_keys,
            data_keys = %data_keys,
            error_name = %compact_diagnostic(&error_name, 64),
            description = %description,
            message = %message,
            has_response_token = response_token.is_some(),
            token_matches_session,
            has_qrcode_index_url = qr_response_string(&root, &["qrcode_index_url"]).is_some(),
            has_redirect_url = qr_response_string(&root, &["redirect_url"]).is_some(),
            has_user_data = qr_user_data(&root).is_some(),
            scan_user_info_keys = %scan_user_info_keys(&root),
            has_scan_avatar = scan_profile_from_response(&root)
                .is_some_and(|profile| profile.avatar_url.is_some()),
            set_cookie_count,
            set_cookie_names = %set_cookie_names,
            has_sessionid_cookie = set_cookie_names
                .split(',')
                .any(|name| matches!(name, "sessionid" | "sessionid_ss")),
            has_captcha = nonempty_response_field(&root, "captcha"),
            has_desc_url = nonempty_response_field(&root, "desc_url"),
            transport = %transport,
            scan_app_id = %compact_diagnostic(
                &qr_response_string(&root, &["scan_app_id"]).unwrap_or_default(),
                32
            ),
            scan_device_info = %compact_diagnostic(
                &qr_response_string(&root, &["scan_device_info"]).unwrap_or_default(),
                200
            ),
            extra = %compact_diagnostic(
                &qr_response_string(&root, &["extra"]).unwrap_or_default(),
                300
            ),
            "抖音二维码状态响应"
        );
    }

    session.note_scan(&root, &status);
    if let Some(challenge) = challenge_for_status(&status, &root) {
        if let Some(incoming) = LoginVerification::from_response(&root) {
            let incoming = session.with_scan_profile(incoming);
            let verification = if let Some(existing) = session.verification_snapshot() {
                session.with_scan_profile(existing.merge(incoming))
            } else {
                incoming
            };
            session.store_verification(verification);
        } else {
            tracing::warn!(
                qr_status = %status,
                top_error,
                data_error,
                verification_fields = %verification_diagnostic(&root),
                "抖音返回身份验证挑战，但验证方式未完整解包"
            );
        }
        let challenge = session
            .verification_snapshot()
            .map_or(challenge, |verification| {
                LoginChallenge::from_verification(&session.with_scan_profile(verification))
            });
        tracing::info!(
            challenge_kind = challenge_kind(&challenge),
            qr_status = %status,
            top_error,
            data_error,
            "抖音二维码返回可继续的身份验证挑战"
        );
        return Ok(LoginPoll::Pending {
            status: "verifying".to_string(),
            challenge: Some(challenge),
        });
    }

    // Once Douyin has entered the native second-step flow, its later QR polls may only
    // report `conf/status=3` or `verifying` without repeating the ticket and ways.
    // Keep the in-memory challenge alive until login truly completes or the user
    // explicitly cancels/refuses the scan.
    if let Some(existing) = session.verification_snapshot() {
        if Utc::now().timestamp() < existing.expires_at {
            let normalized_status = normalize_qr_status(&status);
            if !matches!(
                normalized_status.as_str(),
                "confirmed"
                    | "success"
                    | "authorized"
                    | "expired"
                    | "refresh"
                    | "refused"
                    | "failed"
                    | "canceled"
                    | "cancelled"
            ) {
                let verification = if let Some(incoming) = LoginVerification::from_response(&root) {
                    session.with_scan_profile(existing.merge(incoming))
                } else {
                    session.with_scan_profile(existing)
                };
                session.store_verification(verification.clone());
                return Ok(LoginPoll::Pending {
                    status: "verifying".to_string(),
                    challenge: Some(LoginChallenge::from_verification(&verification)),
                });
            }
        }
    }

    if status.is_empty() {
        if let Some(verification) = session.verification_snapshot() {
            let verification = session.with_scan_profile(verification);
            session.store_verification(verification.clone());
            return Ok(LoginPoll::Pending {
                status: "verifying".to_string(),
                challenge: Some(LoginChallenge::from_verification(&verification)),
            });
        }
        if let Some((error_code, pending_status)) = transient_status_error(&root) {
            if bare_qr_busy(&root) {
                let count = session.busy_polls.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= MAX_BARE_BUSY_POLLS {
                    tracing::warn!(error_code, count, "扫码确认后连续返回空状态 2156，停止空转");
                    return Ok(LoginPoll::Terminal {
                        status: "failed".to_string(),
                        message: qr_error_message(&root),
                    });
                }
            }
            if session.seen_scan.load(Ordering::Relaxed) {
                let verification = session.with_scan_profile(
                    session
                        .verification_snapshot()
                        .unwrap_or_else(|| fallback_verification(session, &root)),
                );
                session.store_verification(verification.clone());
                tracing::warn!(
                    error_code,
                    top_error,
                    data_error,
                    has_scan_avatar = verification.avatar_url.is_some(),
                    "扫码后二维码状态暂不可用，保留身份验证并等待手机端完成"
                );
                return Ok(LoginPoll::Pending {
                    status: "verifying".to_string(),
                    challenge: Some(LoginChallenge::from_verification(&verification)),
                });
            }
            tracing::warn!(
                error_code,
                top_error,
                data_error,
                pending_status,
                "抖音二维码登录仍在处理中，保留会话并等待下次轮询"
            );
            return Ok(LoginPoll::Pending {
                status: pending_status.to_string(),
                challenge: None,
            });
        }
        if top_error != 0 || data_error != 0 {
            tracing::warn!(top_error, data_error, "抖音二维码状态返回明确错误");
            return Ok(LoginPoll::Terminal {
                status: "failed".to_string(),
                message: qr_error_message(&root),
            });
        }
        ensure_success(&root, "二维码状态")?;
        return Ok(LoginPoll::Pending {
            status: "loading".to_string(),
            challenge: None,
        });
    }

    let status = normalize_qr_status(&status);
    if matches!(status.as_str(), "new" | "loading" | "scanned") {
        if let Some(verification) = session.verification_snapshot() {
            let verification = session.with_scan_profile(verification);
            session.store_verification(verification.clone());
            return Ok(LoginPoll::Pending {
                status: "verifying".to_string(),
                challenge: Some(LoginChallenge::from_verification(&verification)),
            });
        }
    }
    match status.as_str() {
        "new" | "loading" | "scanned" => Ok(LoginPoll::Pending {
            status,
            challenge: None,
        }),
        "expired" => Ok(LoginPoll::Terminal {
            status,
            message: terminal_message(root.get("data").and_then(Value::as_object), &root),
        }),
        "refresh" => Ok(LoginPoll::Terminal {
            status: "expired".to_string(),
            message: "二维码需要刷新，请重新获取".to_string(),
        }),
        "refused" | "failed" | "canceled" | "cancelled" => Ok(LoginPoll::Terminal {
            status,
            message: terminal_message(root.get("data").and_then(Value::as_object), &root),
        }),
        "confirmed" | "success" | "authorized" => {
            match build_confirmed_login(session, &root, &response_headers, status).await {
                Ok(confirmed) => Ok(LoginPoll::Confirmed(confirmed)),
                Err(error) if !has_strong_auth_cookie(&cookie_snapshot(&session.jar)) => {
                    tracing::warn!(
                        error = %compact_diagnostic(&format!("{error:#}"), 160),
                        "扫码已确认，但登录 Cookie 尚未就绪，保留会话继续轮询"
                    );
                    let verification = if let Some(incoming) =
                        LoginVerification::from_response(&root)
                    {
                        let incoming = session.with_scan_profile(incoming);
                        session.store_verification(incoming.clone());
                        incoming
                    } else if let Some(existing) = session.verification_snapshot() {
                        session.with_scan_profile(existing)
                    } else {
                        let fb = session.with_scan_profile(fallback_verification(session, &root));
                        session.store_verification(fb.clone());
                        fb
                    };
                    Ok(LoginPoll::Pending {
                        status: "verifying".to_string(),
                        challenge: Some(LoginChallenge::from_verification(&verification)),
                    })
                }
                Err(error) => Err(error),
            }
        }
        _ => Ok(LoginPoll::Terminal {
            status: "failed".to_string(),
            message: format!("抖音返回了未识别的二维码状态：{status}"),
        }),
    }
}

/// 请求抖音向绑定手机发送二次验证码。
pub async fn send_verification_code(session: &LoginSession, way: &str) -> Result<String> {
    ensure!(way == "mobile_sms_verify", "当前验证方式不支持发送验证码");
    let verification = require_verification(session)?;
    let mut form = common_form(&session.device, None);
    form.push(("type".to_string(), "22".to_string()));
    form.push((
        "verify_ticket".to_string(),
        verification
            .ticket()
            .context("当前身份验证缺少官方验证票据，请重新扫码")?
            .to_string(),
    ));
    let response = verification_request(
        session,
        Method::POST,
        "https://aweme.snssdk.com/passport/mobile/send_code/",
        Some(&form),
        None,
    )
    .await?;
    read_verification_response(response, "短信验证码发送").await?;
    Ok("验证码已发送，请留意绑定手机的短信".to_string())
}

/// 生成上行短信挑战。该票据只保存在当前登录会话内。
pub async fn prepare_up_sms_verification(
    session: &LoginSession,
    way: &str,
) -> Result<VerificationDelivery> {
    ensure!(way == "mobile_up_sms_verify", "当前验证方式不支持上行短信");
    let verification = require_verification(session)?;
    if let Some(delivery) = verification.up_sms_delivery() {
        return Ok(delivery);
    }
    let mut query = common_form(&session.device, None);
    query.push(("aid".to_string(), session.device.aid.clone()));
    let response = verification_request(
        session,
        Method::GET,
        "https://aweme.snssdk.com/passport/upsms/gen_verify_ticket/",
        None,
        Some(&query),
    )
    .await?;
    let root = read_verification_response(response, "上行短信验证").await?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .context("上行短信响应缺少 data")?;
    let ticket =
        first_value_string(data, &["verify_ticket"]).context("上行短信响应缺少验证票据")?;
    let sms_content =
        first_value_string(data, &["sms_content"]).context("上行短信响应缺少短信内容")?;
    let channel_mobile = first_value_string(data, &["channel_mobile"]);
    session
        .update_verification(|verification| {
            verification.verify_ticket = Some(ticket);
            if let Some(way) = verification
                .ways
                .iter_mut()
                .find(|item| item.public.kind == "mobile_up_sms_verify")
            {
                way.sms_content = Some(sms_content.clone());
                way.channel_mobile = channel_mobile.clone();
            }
        })
        .context("当前登录会话的上行短信挑战已失效")?;
    Ok(VerificationDelivery {
        kind: way.to_string(),
        sms_content: Some(sms_content),
        channel_mobile,
        qrcode: None,
    })
}

/// 提交验证码、密码或确认已完成上行短信，成功后换正式登录会话。
pub async fn submit_verification(
    session: &LoginSession,
    way: &str,
    code: Option<&str>,
    password: Option<&str>,
) -> Result<LoginPoll> {
    let verification = require_verification(session)?;
    ensure!(
        verification.ways.iter().any(|item| item.public.kind == way),
        "抖音未提供该身份验证方式"
    );
    let result = match way {
        "mobile_sms_verify" => {
            let code = code.unwrap_or_default().trim();
            ensure!(code.len() >= 4 && code.len() <= 12, "请输入有效短信验证码");
            ensure!(
                code.chars().all(|ch| ch.is_ascii_digit()),
                "短信验证码格式无效"
            );
            let mut query = common_form(&session.device, None);
            query.extend([
                ("code".to_string(), code.to_string()),
                ("type".to_string(), "22".to_string()),
                ("need_ticket".to_string(), "1".to_string()),
                (
                    "verify_ticket".to_string(),
                    verification
                        .ticket()
                        .context("当前身份验证缺少官方验证票据，请重新扫码")?
                        .to_string(),
                ),
            ]);
            if let Some(sms_code_key) = verification.sms_code_key.as_deref() {
                query.extend([
                    ("sms_code_key".to_string(), encode_d_ticket(sms_code_key)),
                    ("mix_mode".to_string(), "1".to_string()),
                ]);
            }
            verification_request(
                session,
                Method::GET,
                "https://aweme.snssdk.com/passport/mobile/validate_code/",
                None,
                Some(&query),
            )
            .await?
        }
        "pwd_verify" => {
            let password = password.unwrap_or_default();
            ensure!(!password.is_empty(), "请输入登录密码");
            ensure!(password.chars().count() <= 256, "登录密码超出安全上限");
            let mut form = common_form(&session.device, None);
            form.extend([
                (
                    "verify_ticket".to_string(),
                    verification
                        .ticket()
                        .context("当前身份验证缺少官方验证票据，请重新扫码")?
                        .to_string(),
                ),
                ("aid".to_string(), session.device.aid.clone()),
                ("password".to_string(), encode_d_ticket(password)),
                ("mix_mode".to_string(), "1".to_string()),
            ]);
            if let Some(sms_code_key) = verification.sms_code_key.as_deref() {
                form.push(("sms_code_key".to_string(), encode_d_ticket(sms_code_key)));
            }
            verification_request(
                session,
                Method::POST,
                "https://aweme.snssdk.com/passport/account/verify/",
                Some(&form),
                None,
            )
            .await?
        }
        "mobile_up_sms_verify" => {
            let verification = require_verification(session)?;
            let mut query = common_form(&session.device, None);
            query.extend([
                (
                    "verify_ticket".to_string(),
                    verification
                        .ticket()
                        .context("当前身份验证缺少官方验证票据，请重新扫码")?
                        .to_string(),
                ),
                ("aid".to_string(), session.device.aid.clone()),
            ]);
            if let Some(auth_ticket) = verification
                .auth_ticket_for(way)
                .or(verification.auth_ticket.as_deref())
            {
                query.push(("auth_ticket".to_string(), auth_ticket.to_string()));
            }
            if let Some(sms_code_key) = verification.sms_code_key.as_deref() {
                query.extend([
                    ("sms_code_key".to_string(), encode_d_ticket(sms_code_key)),
                    ("mix_mode".to_string(), "1".to_string()),
                ]);
            }
            verification_request(
                session,
                Method::GET,
                "https://aweme.snssdk.com/passport/upsms/verify/",
                None,
                Some(&query),
            )
            .await?
        }
        _ => bail!("当前验证方式不支持服务端提交"),
    };
    let (_, root) = read_verification_result(result, "身份验证").await?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .context("身份验证已通过，但响应缺少 data")?;
    let success_ticket = first_value_string(data, &["ticket"])
        .or_else(|| first_value_string(data, &["verify_ticket"]))
        .or_else(|| first_value_string(root.as_object()?, &["ticket", "verify_ticket"]))
        .context("身份验证已通过，但响应缺少换票凭证")?;
    session
        .update_verification(|verification| {
            verification.verify_ticket = Some(success_ticket);
        })
        .context("当前登录会话已失效，请重新扫码")?;
    match exchange_verify_ticket(session).await {
        Ok(polled) => Ok(polled),
        Err(error) if !has_strong_auth_cookie(&cookie_snapshot(&session.jar)) => {
            tracing::warn!(
                error = %compact_diagnostic(&format!("{error:#}"), 160),
                "身份验证已提交，但登录 Cookie 尚未就绪，保留会话继续轮询"
            );
            let verification = require_verification(session)?;
            Ok(LoginPoll::Pending {
                status: "verifying".to_string(),
                challenge: Some(LoginChallenge::from_verification(&verification)),
            })
        }
        Err(error) => Err(error),
    }
}

async fn exchange_verify_ticket(session: &LoginSession) -> Result<LoginPoll> {
    let verification = session
        .verification_snapshot()
        .context("当前登录会话缺少二次验证状态")?;
    let mut form = common_form(&session.device, None);
    form.push((
        "verify_ticket".to_string(),
        verification
            .ticket()
            .context("当前身份验证缺少官方验证票据，请重新扫码")?
            .to_string(),
    ));
    form.push(("multi_login".to_string(), "1".to_string()));
    let response = verification_request(
        session,
        Method::POST,
        "https://aweme.snssdk.com/passport/user/login_by_verify_ticket/",
        Some(&form),
        None,
    )
    .await?;
    let (response_headers, root) = read_verification_result(response, "登录会话换票").await?;
    let confirmed =
        build_confirmed_login(session, &root, &response_headers, "confirmed".to_string()).await?;
    session.clear_verification();
    Ok(LoginPoll::Confirmed(confirmed))
}

fn require_verification(session: &LoginSession) -> Result<LoginVerification> {
    let verification = session
        .verification_snapshot()
        .context("当前登录会话没有待完成的身份验证")?;
    ensure!(
        Utc::now().timestamp() < verification.expires_at,
        "身份验证已超时，请重新获取二维码"
    );
    Ok(verification)
}

async fn verification_request(
    session: &LoginSession,
    method: Method,
    url: &str,
    form: Option<&[(String, String)]>,
    query: Option<&[(String, String)]>,
) -> Result<reqwest::Response> {
    let csrf_token = passport_csrf_token(&session.jar);
    let mut request = session
        .client
        .request(method, url)
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .header("sdk-version", "2")
        .header("passport-sdk-version", PASSPORT_SDK_VERSION);
    if let Some(device_token) = session
        .device
        .device_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        request = request.header("x-tt-dt", device_token);
    }
    if let Some(csrf_token) = csrf_token {
        request = request.header("x-tt-passport-csrf-token", csrf_token);
    }
    if let Some(query) = query {
        request = request.query(query);
    }
    if let Some(form) = form {
        request = request.form(form);
    }
    request.send().await.context("请求抖音身份验证接口失败")
}

async fn read_verification_response(response: reqwest::Response, label: &str) -> Result<Value> {
    read_verification_result(response, label)
        .await
        .map(|(_, root)| root)
}

async fn read_verification_result(
    response: reqwest::Response,
    label: &str,
) -> Result<(header::HeaderMap, Value)> {
    let headers = response.headers().clone();
    let bytes = read_limited_body(response, &format!("{label}响应")).await?;
    let root: Value =
        serde_json::from_slice(&bytes).with_context(|| format!("{label}响应不是合法 JSON"))?;
    ensure_success(&root, label)?;
    Ok((headers, root))
}

async fn build_confirmed_login(
    session: &LoginSession,
    root: &Value,
    response_headers: &header::HeaderMap,
    status: String,
) -> Result<ConfirmedLogin> {
    let redirect_url = qr_response_string(root, &["redirect_url"]);
    if let Some(redirect_url) = redirect_url.as_deref() {
        follow_official_login_redirect(session, redirect_url).await?;
    }

    let mut identity = qr_user_data(root).cloned().unwrap_or_default();
    merge_identity_fields(&mut identity, root.get("data").and_then(Value::as_object));

    if first_value_string(&identity, &["user_id_str", "user_id", "uid_str", "uid"])
        .and_then(|value| value.parse::<u64>().ok())
        .is_none()
        || first_value_string(&identity, &["sec_user_id", "sec_uid"])
            .filter(|value| !value.trim().is_empty())
            .is_none()
    {
        let profile = fetch_authenticated_profile(session, &identity).await?;
        merge_identity_fields(&mut identity, Some(&profile));
    }

    let uid = first_value_string(&identity, &["user_id_str", "user_id", "uid_str", "uid"])
        .filter(|value| value.parse::<u64>().ok().is_some_and(|uid| uid > 0))
        .context("登录已确认，但未返回有效 UID")?;
    let sec_uid = first_value_string(&identity, &["sec_user_id", "sec_uid"])
        .filter(|value| !value.trim().is_empty())
        .context("登录已确认，但未返回 sec_user_id")?;
    let nickname = first_value_string(&identity, &["name", "username", "nickname", "screen_name"])
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "抖音用户".to_string());
    let avatar_url = avatar_url(&identity);
    let mobile = first_value_string(&identity, &["mobile"]).unwrap_or_default();
    let cookie = cookie_snapshot(&session.jar);
    ensure!(
        has_strong_auth_cookie(&cookie),
        "登录已确认，但 Cookie Jar 未收到可用的强认证会话凭证"
    );
    let d_ticket = first_value_string(&identity, &["d_ticket"]);
    let session_key = first_value_string(&identity, &["session_key"]);
    let x_tt_token = header_string(response_headers, "x-tt-token")
        .or_else(|| first_value_string(&identity, &["X-Tt-Token", "x_tt_token"]));
    let token_encrypted = first_value_string(&identity, &["token_encrypted", "TokenEncrypted"]);
    let ts_sign = first_value_string(&identity, &["ts_sign"]);
    let attest_ts_sign = first_value_string(&identity, &["attest_ts_sign"]);
    let mfa_token = first_value_string(&identity, &["mfa_token"]);
    let now = Utc::now().timestamp();
    let record = NativeSessionRecord {
        device: session.device.clone(),
        cookie,
        uid,
        sec_uid,
        nickname,
        avatar_url,
        mobile,
        session_key,
        d_ticket,
        x_tt_token,
        token_encrypted,
        ts_sign,
        attest_ts_sign,
        mfa_token,
        guard_key_hex: None,
        guard_server_data: None,
        dtrait_pk1_pem: None,
        dtrait_version: None,
        logged_in_at: now,
        last_verified_at: Some(now),
        last_beat_at: None,
    };
    record.validate()?;
    Ok(ConfirmedLogin {
        record,
        status,
        message: "扫码登录已确认".to_string(),
    })
}

async fn follow_official_login_redirect(session: &LoginSession, raw_url: &str) -> Result<()> {
    let mut url = reqwest::Url::parse(raw_url).context("登录确认跳转地址无效")?;
    for _ in 0..MAX_LOGIN_REDIRECTS {
        ensure!(
            is_official_login_url(&url),
            "登录确认跳转到了非官方域名：{}",
            url.host_str().unwrap_or("unknown")
        );
        let response = session
            .client
            .get(url.clone())
            .header(header::ACCEPT, "text/html,application/xhtml+xml")
            .send()
            .await
            .context("跟随登录确认跳转失败")?;
        let status = response.status();
        if status.is_redirection() {
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .context("登录确认跳转缺少 Location")?;
            url = url.join(location).context("登录确认跳转地址无效")?;
            continue;
        }
        ensure!(status.is_success(), "登录确认跳转返回 HTTP {status}");
        return Ok(());
    }
    bail!("登录确认跳转次数超过安全上限")
}

fn is_official_login_url(url: &reqwest::Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    ["douyin.com", "snssdk.com", "iesdouyin.com"]
        .iter()
        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

fn challenge_from_response(root: &Value) -> Option<LoginChallenge> {
    if let Some(verification) = LoginVerification::from_response(root) {
        return Some(verification.challenge());
    }
    let data = root.get("data").and_then(Value::as_object)?;
    let raw = first_value_string(
        data,
        &["desc_url", "captcha", "verify_url", "challenge_url"],
    )?;
    let url = reqwest::Url::parse(&raw).ok()?;
    if !is_official_login_url(&url) {
        return None;
    }
    let decision_config =
        first_value_string(data, &["verify_center_decision_conf", "decision_config"]);
    Some(LoginChallenge::Web {
        url: url.to_string(),
        decision_config,
    })
}

fn challenge_for_status(status: &str, root: &Value) -> Option<LoginChallenge> {
    let pending = status.is_empty()
        || matches!(
            normalize_qr_status(status).as_str(),
            "new" | "loading" | "scanned" | "verifying"
        );
    if pending {
        return challenge_from_response(root);
    }

    // App 在部分扫码确认响应中仍返回 status=3，同时用 error_code 明确要求二次验证。
    // 只有同时解析出官方验证载荷时才覆盖 terminal 状态，避免陈旧字段误触发。
    let (top_error, data_error) = response_error_codes(root);
    let two_step_error = [top_error, data_error]
        .into_iter()
        .any(is_two_step_error_code);
    two_step_error
        .then(|| {
            LoginVerification::from_response(root).map(|verification| verification.challenge())
        })
        .flatten()
}

fn is_two_step_error_code(code: i64) -> bool {
    matches!(
        code,
        2020 | 2022 | 2025 | 2046 | 2085 | 2156 | 40102 | 40103
    )
}

fn verification_diagnostic(root: &Value) -> String {
    let mut current = root.get("data").cloned().unwrap_or_else(|| root.clone());
    let mut levels = Vec::new();
    for _ in 0..4 {
        let Some(object) = current.as_object() else {
            break;
        };
        let array_ways = object
            .get("verify_ways")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let string_ways = first_value_string(object, &["auth_ways_data", "verify_ways_data"])
            .and_then(|raw| parse_json_value(&raw))
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        let ways = array_ways.len().max(string_ways.len());
        levels.push(format!(
            "keys={} ways={} ticket={} auth_ticket={} profile_key={} sms_code_key={}",
            json_object_keys(&current, 24),
            ways,
            object.contains_key("verify_ticket") || object.contains_key("ticket"),
            array_ways
                .iter()
                .chain(string_ways.iter())
                .take(16)
                .any(|entry| {
                    entry
                        .as_object()
                        .is_some_and(|entry| entry.contains_key("auth_ticket"))
                }),
            object.contains_key("profile_key"),
            object.contains_key("sms_code_key"),
        ));
        let Some(next) = object
            .get("data")
            .or_else(|| object.get("result"))
            .or_else(|| object.get("response"))
            .or_else(|| object.get("extra"))
            .cloned()
        else {
            break;
        };
        current = next;
        if let Some(raw) = current.as_str() {
            let Some(parsed) = parse_json_value(raw) else {
                levels.push("wrapped_json=invalid".to_string());
                break;
            };
            current = parsed;
        }
    }
    levels.join(" -> ")
}

fn challenge_kind(challenge: &LoginChallenge) -> &'static str {
    match challenge {
        LoginChallenge::Web { .. } => "web",
        LoginChallenge::TwoStep { .. } => "two_step",
    }
}

fn challenge_url(challenge: &LoginChallenge) -> Option<String> {
    match challenge {
        LoginChallenge::Web { url, .. } => Some(url.clone()),
        LoginChallenge::TwoStep { .. } => None,
    }
}

fn verification_way_metadata(kind: &str) -> (&'static str, bool, Option<&'static str>) {
    match kind {
        "mobile_sms_verify" => ("接收短信验证码", true, Some("验证码会发送到账号绑定的手机")),
        "mobile_up_sms_verify" => (
            "发送短信验证",
            true,
            Some("按提示由绑定手机发送短信，再回到这里确认"),
        ),
        "pwd_verify" => ("验证登录密码", true, Some("仅用于本次身份校验，不会保存")),
        "identity_verify" => (
            "手机身份验证",
            false,
            Some("需在抖音官方 App 内完成身份验证，完成后本页会自动继续"),
        ),
        "face_verify" | "auth_three_element_mobile_verify" => (
            "手机刷脸验证",
            false,
            Some("需在抖音官方 App 内完成刷脸，完成后本页会自动继续"),
        ),
        "qa_verify" => ("回答安全问题", false, Some("当前版本暂不支持该验证方式")),
        "oauth_weixin_verify" => ("微信授权验证", false, Some("需要在抖音官方 App 内完成")),
        "oauth_qq_verify" => ("QQ 授权验证", false, Some("需要在抖音官方 App 内完成")),
        "oauth_toutiao_verify" => ("头条授权验证", false, Some("需要在抖音官方 App 内完成")),
        "oauth_weibo_verify" => ("微博授权验证", false, Some("需要在抖音官方 App 内完成")),
        "oauth_apple_verify" => ("Apple 授权验证", false, Some("需要在抖音官方 App 内完成")),
        _ => ("其他身份验证", false, Some("该验证方式尚未接入")),
    }
}

fn fallback_verification(session: &LoginSession, root: &Value) -> LoginVerification {
    let scanned = session.scan_profile_snapshot();
    let profile_name = qr_user_data(root)
        .and_then(|u| first_value_string(u, &["name", "username", "nickname", "screen_name"]))
        .or_else(|| scanned.as_ref().and_then(|profile| profile.name.clone()))
        .or_else(|| {
            if session.alias.is_empty() {
                None
            } else {
                Some(session.alias.clone())
            }
        });
    let avatar_url = scan_profile_from_response(root)
        .and_then(|profile| profile.avatar_url)
        .or_else(|| {
            scanned
                .as_ref()
                .and_then(|profile| profile.avatar_url.clone())
        });
    let verify_ticket = qr_response_string(root, &["verify_ticket", "ticket"]);
    let data = root.get("data").and_then(Value::as_object);
    let sms_code_key = data.and_then(|d| first_value_string(d, &["sms_code_key"]));
    let auth_ticket = data.and_then(|d| first_value_string(d, &["auth_ticket"]));
    let scene_description = data
        .and_then(|d| {
            first_value_string(d, &["verify_scene_desc", "instruction_text", "description"])
        })
        .or_else(|| Some("为保障账号安全，请先完成身份验证，以确保为本人操作".to_string()));
    let has_ticket = verify_ticket.is_some();

    let ways = vec![
        VerificationWay {
            public: LoginVerifyWay {
                kind: "face_verify".to_string(),
                label: "手机刷脸验证".to_string(),
                masked_mobile: None,
                supported: false,
                description: Some("需在抖音官方 App 内完成刷脸，系统会自动检测".to_string()),
            },
            auth_ticket: None,
            sms_content: None,
            channel_mobile: None,
            ..Default::default()
        },
        VerificationWay {
            public: LoginVerifyWay {
                kind: "mobile_sms_verify".to_string(),
                label: "接收短信验证码".to_string(),
                masked_mobile: None,
                supported: has_ticket,
                description: if has_ticket {
                    Some("验证码会发送到账号绑定的手机".to_string())
                } else {
                    Some("需在抖音官方 App 内接收短信验证，系统会自动检测".to_string())
                },
            },
            auth_ticket: None,
            sms_content: None,
            channel_mobile: None,
            ..Default::default()
        },
        VerificationWay {
            public: LoginVerifyWay {
                kind: "pwd_verify".to_string(),
                label: "验证登录密码".to_string(),
                masked_mobile: None,
                supported: has_ticket,
                description: if has_ticket {
                    Some("仅用于本次身份校验，不会保存".to_string())
                } else {
                    Some("需在抖音官方 App 内验证密码，系统会自动检测".to_string())
                },
            },
            auth_ticket: None,
            sms_content: None,
            channel_mobile: None,
            ..Default::default()
        },
        VerificationWay {
            public: LoginVerifyWay {
                kind: "mobile_up_sms_verify".to_string(),
                label: "发送短信验证".to_string(),
                masked_mobile: None,
                supported: has_ticket,
                description: if has_ticket {
                    Some("按提示由绑定手机发送短信，再回到这里确认".to_string())
                } else {
                    Some("需在抖音官方 App 内发送短信，系统会自动检测".to_string())
                },
            },
            auth_ticket: None,
            sms_content: None,
            channel_mobile: None,
            ..Default::default()
        },
    ];

    LoginVerification {
        verify_ticket,
        ways,
        sms_code_key,
        auth_ticket,
        profile_key: None,
        profile_name,
        avatar_url,
        scene_description,
        expires_at: Utc::now().timestamp() + LOGIN_CHALLENGE_TTL_SECS,
    }
}

fn mask_mobile(mobile: &str) -> String {
    let digits = mobile
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.len() >= 7 {
        format!(
            "{}{}{}",
            &digits[..3],
            "*".repeat(digits.len().saturating_sub(7).max(0)),
            &digits[digits.len() - 4..]
        )
    } else if digits.len() >= 4 {
        format!(
            "{}{}",
            "*".repeat(digits.len() - 4),
            &digits[digits.len() - 4..]
        )
    } else {
        "****".to_string()
    }
}

impl LoginVerification {
    fn from_response(root: &Value) -> Option<Self> {
        let payload = verification_payload(root)?;
        let data = &payload.data;
        let verify_ticket = first_value_string(data, &["verify_ticket", "ticket"])
            .filter(|value| value.len() <= 16 * 1024);
        let entries = &payload.ways;
        let mut ways = Vec::new();
        let sms_code_key =
            first_value_string(data, &["sms_code_key"]).filter(|value| value.len() <= 16 * 1024);
        let profile_key =
            first_value_string(data, &["profile_key"]).filter(|value| value.len() <= 16 * 1024);
        let profile_name = first_value_string(
            data,
            &[
                "user_name",
                "username",
                "nickname",
                "screen_name",
                "profile_name",
            ],
        )
        .map(|value| compact_diagnostic(&value, 80));
        let scene_description = first_value_string(
            data,
            &["verify_scene_desc", "instruction_text", "description"],
        )
        .map(|value| compact_diagnostic(&value, 160))
        .filter(|value| !value.is_empty());
        let mut auth_ticket = None;
        for entry in entries.iter().take(16) {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            let Some(kind) = first_value_string(entry, &["verify_way", "verify_type", "way"])
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            if ways
                .iter()
                .any(|existing: &VerificationWay| existing.public.kind == kind)
            {
                continue;
            }
            let (label, supported, description) = verification_way_metadata(&kind);
            let mobile = first_value_string(entry, &["mobile", "mobile_number"])
                .map(|value| compact_diagnostic(&mask_mobile(&value), 32))
                .filter(|value| !value.is_empty());
            let way_auth_ticket = first_value_string(entry, &["auth_ticket"])
                .filter(|value| value.len() <= 16 * 1024);
            if auth_ticket.is_none() {
                auth_ticket = way_auth_ticket.clone();
            }
            let sms_content = first_value_string(entry, &["sms_content"])
                .map(|value| compact_diagnostic(&value, 512))
                .filter(|value| !value.is_empty());
            let channel_mobile = first_value_string(entry, &["channel_mobile"])
                .map(|value| compact_diagnostic(&value, 64))
                .filter(|value| !value.is_empty());
            ways.push(VerificationWay {
                public: LoginVerifyWay {
                    kind,
                    label: label.to_string(),
                    masked_mobile: mobile,
                    supported,
                    description: description.map(str::to_string),
                },
                auth_ticket: way_auth_ticket,
                sms_content,
                channel_mobile,
                ..Default::default()
            });
        }
        if ways.is_empty() {
            return None;
        }
        Some(Self {
            verify_ticket,
            ways,
            sms_code_key,
            auth_ticket,
            profile_key,
            profile_name,
            avatar_url: scan_profile_from_response(root).and_then(|profile| profile.avatar_url),
            scene_description,
            expires_at: Utc::now().timestamp() + LOGIN_CHALLENGE_TTL_SECS,
        })
    }

    fn merge(mut self, incoming: Self) -> Self {
        if incoming.verify_ticket.is_some() {
            self.verify_ticket = incoming.verify_ticket;
        }
        if incoming.sms_code_key.is_some() {
            self.sms_code_key = incoming.sms_code_key;
        }
        if incoming.auth_ticket.is_some() {
            self.auth_ticket = incoming.auth_ticket;
        }
        if incoming.profile_key.is_some() {
            self.profile_key = incoming.profile_key;
        }
        if incoming.profile_name.is_some() {
            self.profile_name = incoming.profile_name;
        }
        if incoming.avatar_url.is_some() {
            self.avatar_url = incoming.avatar_url;
        }
        if incoming.scene_description.is_some() {
            self.scene_description = incoming.scene_description;
        }
        for incoming_way in incoming.ways {
            if let Some(existing) = self
                .ways
                .iter_mut()
                .find(|way| way.public.kind == incoming_way.public.kind)
            {
                if incoming_way.auth_ticket.is_some() {
                    existing.auth_ticket = incoming_way.auth_ticket;
                }
                if incoming_way.sms_content.is_some() {
                    existing.sms_content = incoming_way.sms_content;
                }
                if incoming_way.channel_mobile.is_some() {
                    existing.channel_mobile = incoming_way.channel_mobile;
                }
                if incoming_way.public.masked_mobile.is_some() {
                    existing.public.masked_mobile = incoming_way.public.masked_mobile;
                }
                if incoming_way.public.description.is_some() {
                    existing.public.description = incoming_way.public.description;
                }
            } else {
                self.ways.push(incoming_way);
            }
        }
        self.expires_at = self.expires_at.max(incoming.expires_at);
        self
    }

    fn auth_ticket_for(&self, kind: &str) -> Option<&str> {
        self.ways
            .iter()
            .find(|way| way.public.kind == kind)
            .and_then(|way| way.auth_ticket.as_deref())
    }

    fn up_sms_delivery(&self) -> Option<VerificationDelivery> {
        let way = self
            .ways
            .iter()
            .find(|way| way.public.kind == "mobile_up_sms_verify")?;
        let sms_content = way.sms_content.clone()?;
        Some(VerificationDelivery {
            kind: "mobile_up_sms_verify".to_string(),
            sms_content: Some(sms_content),
            channel_mobile: way.channel_mobile.clone(),
            qrcode: None,
        })
    }

    fn can_begin(&self, way: &str) -> bool {
        match way {
            "mobile_sms_verify" => self.verify_ticket.is_some(),
            "pwd_verify" => self.verify_ticket.is_some(),
            "mobile_up_sms_verify" => {
                self.verify_ticket.is_some()
                    || self.auth_ticket.is_some()
                    || self.auth_ticket_for(way).is_some()
            }
            _ => false,
        }
    }

    fn can_submit(&self, way: &str) -> bool {
        self.verify_ticket.is_some()
            && matches!(
                way,
                "mobile_sms_verify" | "pwd_verify" | "mobile_up_sms_verify"
            )
    }

    fn challenge(&self) -> LoginChallenge {
        let verification_started = self.verify_ticket.is_some() || self.auth_ticket.is_some();
        LoginChallenge::TwoStep {
            ways: self
                .ways
                .iter()
                .map(|way| {
                    let mut public = way.public.clone();
                    if public.supported && !self.can_begin(&public.kind) {
                        public.supported = false;
                        public.description = Some(
                            "官方当前未返回验证票据，请先在抖音 App 完成身份验证；本页会继续自动检测"
                                .to_string(),
                        );
                    } else if public.supported
                        && way.public.kind == "mobile_up_sms_verify"
                        && !self.can_submit(&public.kind)
                    {
                        public.description = Some(
                            "先获取官方短信内容，再由绑定手机发送；完成后在页面确认".to_string(),
                        );
                    }
                    public
                })
                .collect(),
            masked_mobile: self
                .ways
                .iter()
                .find_map(|way| way.public.masked_mobile.clone()),
            profile_name: self.profile_name.clone(),
            avatar_url: self.avatar_url.clone(),
            ticket_ready: verification_started,
            scene_description: self.scene_description.clone(),
        }
    }

    fn ticket(&self) -> Option<&str> {
        self.verify_ticket.as_deref()
    }
}

struct VerificationPayload {
    data: serde_json::Map<String, Value>,
    ways: Vec<Value>,
}

fn verification_payload(root: &Value) -> Option<VerificationPayload> {
    let mut current = root.get("data").cloned().unwrap_or_else(|| root.clone());
    for _ in 0..4 {
        if let Some(raw) = current.as_str() {
            current = parse_json_value(raw)?;
            continue;
        }
        let object = current.as_object()?.clone();
        let ways = object
            .get("verify_ways")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| {
                let raw = first_value_string(&object, &["auth_ways_data", "verify_ways_data"])?;
                parse_json_value(&raw)?.as_array().cloned()
            });
        if let Some(ways) = ways.filter(|ways| !ways.is_empty()) {
            return Some(VerificationPayload { data: object, ways });
        }
        match object
            .get("data")
            .or_else(|| object.get("result"))
            .or_else(|| object.get("response"))
            .or_else(|| object.get("extra"))
            .cloned()
        {
            Some(value) => current = value,
            None => return None,
        }
    }
    None
}

fn parse_json_value(raw: &str) -> Option<Value> {
    if raw.len() > 64 * 1024 {
        return None;
    }
    serde_json::from_str(raw).ok()
}

impl LoginChallenge {
    fn from_verification(verification: &LoginVerification) -> Self {
        verification.challenge()
    }
}

async fn fetch_authenticated_profile(
    session: &LoginSession,
    identity: &serde_json::Map<String, Value>,
) -> Result<serde_json::Map<String, Value>> {
    fetch_profile_with(&session.client, &session.device, identity).await
}

async fn fetch_profile_with(
    client: &Client,
    device: &NativeDevice,
    identity: &serde_json::Map<String, Value>,
) -> Result<serde_json::Map<String, Value>> {
    if let Ok(resp) = client
        .get("https://www.douyin.com/passport/account/info/v2/?aid=6383&account_sdk_source=web&is_from_ttaccountsdk=1")
        .header(header::USER_AGENT, WEB_LOGIN_UA)
        .header(header::ACCEPT, "application/json, text/javascript")
        .header(header::REFERER, "https://www.douyin.com/")
        .send()
        .await
        && let Ok(bytes) = read_limited_body(resp, "Web登录账号资料响应").await
        && let Ok(root) = serde_json::from_slice::<Value>(&bytes)
        && ensure_success(&root, "Web登录账号资料").is_ok()
        && let Some(data) = root.get("data").and_then(Value::as_object)
    {
        let mut profile = data
            .get("user_data")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(|| data.clone());
        if first_value_string(&profile, &["name", "username", "nickname", "screen_name"]).is_none()
            && let Some(sec_uid) = first_value_string(&profile, &["sec_user_id", "sec_uid"])
                .or_else(|| first_value_string(identity, &["sec_user_id", "sec_uid"]))
        {
            let sec_uids_json = serde_json::to_string(&vec![sec_uid]).unwrap_or_default();
            if let Ok(im_resp) = client
                .post("https://www.douyin.com/aweme/v1/web/im/user/info/?aid=6383&device_platform=webapp")
                .header(header::USER_AGENT, WEB_LOGIN_UA)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::REFERER, "https://www.douyin.com/")
                .form(&[("sec_uids", sec_uids_json)])
                .send()
                .await
                && let Ok(im_bytes) = read_limited_body(im_resp, "IM用户资料响应").await
                && let Ok(im_root) = serde_json::from_slice::<Value>(&im_bytes)
                && let Some(first_user) = im_root
                    .get("data")
                    .and_then(Value::as_array)
                    .and_then(|arr| arr.first())
                    .and_then(Value::as_object)
            {
                if let Some(nick) = first_value_string(first_user, &["nickname", "name"]) {
                    profile.insert("nickname".to_string(), Value::String(nick));
                }
                if let Some(avatar) = first_user.get("avatar_thumb") {
                    profile.insert("avatar_thumb".to_string(), avatar.clone());
                }
            }
        }
        return Ok(profile);
    }
    let form = common_form(device, None);
    let mut request = client
        .get("https://aweme.snssdk.com/passport/account/info/v2/")
        .query(&form)
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .header("sdk-version", "2")
        .header("passport-sdk-version", PASSPORT_SDK_VERSION);
    if let Some(sec_uid) = first_value_string(identity, &["sec_user_id", "sec_uid"]) {
        request = request.header("x-uc-sec-uid", sec_uid);
    }
    let response = request.send().await.context("登录确认后读取账号资料失败")?;
    let bytes = read_limited_body(response, "登录账号资料响应").await?;
    let root: Value = serde_json::from_slice(&bytes).context("登录账号资料响应不是合法 JSON")?;
    ensure_success(&root, "登录账号资料")?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .context("登录账号资料响应缺少 data")?;
    Ok(data
        .get("user_data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(|| data.clone()))
}

fn merge_identity_fields(
    target: &mut serde_json::Map<String, Value>,
    source: Option<&serde_json::Map<String, Value>>,
) {
    let Some(source) = source else {
        return;
    };
    for (key, value) in source {
        if value.is_null() || value.as_str().is_some_and(|value| value.trim().is_empty()) {
            continue;
        }
        if matches!(key.as_str(), "user_id" | "user_id_str" | "uid" | "uid_str")
            && value_string(Some(value)).trim() == "0"
        {
            continue;
        }
        target.insert(key.clone(), value.clone());
    }
}

fn header_string(headers: &header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn avatar_url(identity: &serde_json::Map<String, Value>) -> String {
    for key in [
        "avatar_url",
        "avatar_thumb",
        "avatar_medium",
        "avatar_larger",
        "avatar",
        "avatar_uri",
        "avatar_thumb_url",
    ] {
        let Some(value) = identity.get(key) else {
            continue;
        };
        if let Some(value) = value.as_str() {
            if value.starts_with("https://") {
                return value.to_string();
            }
        }
        if let Some(first) = value
            .get("url_list")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str)
        {
            if first.starts_with("https://") {
                return first.to_string();
            }
        }
    }
    String::new()
}

fn scan_user_info_keys(root: &Value) -> String {
    let Some(value) = root
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get("scan_user_info"))
    else {
        return String::new();
    };
    let object = match value {
        Value::Object(object) => object,
        Value::String(raw) => {
            return parse_json_value(raw)
                .and_then(|parsed| parsed.as_object().cloned())
                .map(|object| {
                    object
                        .keys()
                        .take(24)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
        }
        _ => return String::new(),
    };
    object
        .keys()
        .take(24)
        .cloned()
        .collect::<Vec<_>>()
        .join(",")
}

fn scan_profile_from_response(root: &Value) -> Option<ScanProfile> {
    let data = root.get("data").and_then(Value::as_object)?;
    let mut profile = ScanProfile::default();
    for key in [
        "scan_user_info",
        "user_data",
        "user",
        "user_info",
        "profile",
        "extra",
    ] {
        if let Some(value) = data.get(key) {
            absorb_scan_profile(&mut profile, value);
        }
    }
    if profile.name.is_none() && profile.avatar_url.is_none() {
        None
    } else {
        Some(profile)
    }
}

fn absorb_scan_profile(profile: &mut ScanProfile, value: &Value) {
    let object = match value {
        Value::Object(object) => object,
        Value::String(raw) => {
            let Some(parsed) = parse_json_value(raw) else {
                return;
            };
            let Some(object) = parsed.as_object() else {
                return;
            };
            absorb_scan_profile(profile, &Value::Object(object.clone()));
            return;
        }
        _ => return,
    };
    if profile.name.is_none() {
        profile.name = first_value_string(
            object,
            &[
                "screen_name",
                "name",
                "nickname",
                "nick_name",
                "username",
                "user_name",
            ],
        )
        .map(|value| compact_diagnostic(&value, 80))
        .filter(|value| !value.is_empty());
    }
    if profile.avatar_url.is_none() {
        let avatar = avatar_url(object);
        if avatar.starts_with("https://") && avatar.len() <= 2048 {
            profile.avatar_url = Some(avatar);
        }
    }
}

fn qr_response_status(root: &Value) -> String {
    root.get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get("status"))
        .or_else(|| root.get("status"))
        .map(|value| value_string(Some(value)))
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn normalize_qr_status(status: &str) -> String {
    match status.trim().to_ascii_lowercase().as_str() {
        "1" => "new".to_string(),
        "2" => "scanned".to_string(),
        "3" => "confirmed".to_string(),
        "4" => "refresh".to_string(),
        "5" => "expired".to_string(),
        value => value.to_string(),
    }
}

fn qr_response_string(root: &Value, keys: &[&str]) -> Option<String> {
    root.get("data")
        .and_then(Value::as_object)
        .and_then(|data| first_value_string(data, keys))
        .or_else(|| first_value_string(root.as_object()?, keys))
}

fn qr_user_data(root: &Value) -> Option<&serde_json::Map<String, Value>> {
    root.get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get("user_data"))
        .and_then(Value::as_object)
}

fn response_error_codes(root: &Value) -> (i64, i64) {
    let top_error = error_code_at(root);
    let data_error = root.get("data").map(error_code_at).unwrap_or(0);
    (top_error, data_error)
}

fn error_code_at(value: &Value) -> i64 {
    let mut current = value;
    for _ in 0..5 {
        if let Some(raw) = current.as_str() {
            let Some(parsed) = parse_json_value(raw).filter(|parsed| !parsed.is_string()) else {
                return 0;
            };
            let mut parsed = parsed;
            // A JSON string may wrap another data object. Walk the owned value here and
            // return immediately; nested string wrappers are intentionally bounded.
            for _ in 0..4 {
                let Some(object) = parsed.as_object() else {
                    return 0;
                };
                if let Some(code) = value_i64(object.get("error_code"))
                    .or_else(|| value_i64(object.get("status_code")))
                    .or_else(|| value_i64(object.get("code")))
                    .filter(|code| *code != 0)
                {
                    return code;
                }
                let Some(next) = object
                    .get("data")
                    .or_else(|| object.get("result"))
                    .or_else(|| object.get("response"))
                    .or_else(|| object.get("extra"))
                else {
                    return 0;
                };
                if let Some(nested) = next.as_str() {
                    let Some(value) = parse_json_value(nested) else {
                        return 0;
                    };
                    parsed = value;
                } else {
                    parsed = next.clone();
                }
            }
            return 0;
        }
        let Some(object) = current.as_object() else {
            return 0;
        };
        if let Some(code) = value_i64(object.get("error_code"))
            .or_else(|| value_i64(object.get("status_code")))
            .or_else(|| value_i64(object.get("code")))
            .filter(|code| *code != 0)
        {
            return code;
        }
        let Some(next) = object
            .get("data")
            .or_else(|| object.get("result"))
            .or_else(|| object.get("response"))
            .or_else(|| object.get("extra"))
        else {
            return 0;
        };
        current = next;
    }
    0
}

fn qr_error_message(root: &Value) -> String {
    let (top_error, data_error) = response_error_codes(root);
    let message = root
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| first_value_string(data, &["message", "description", "error_name"]))
        .or_else(|| {
            root.get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let code = if data_error != 0 {
        data_error
    } else {
        top_error
    };
    match code {
        2156 => {
            "本次扫码确认未生效（error=2156），请重新获取二维码后再扫码；若连续出现，请先在抖音 App 完成安全验证。".to_string()
        }
        4044 => QR_4044_REJECTION.to_string(),
        1049 => QR_1049_REJECTION.to_string(),
        7 => "抖音提示操作过于频繁（error=7），请稍后再试".to_string(),
        _ if !message.trim().is_empty() => {
            format!("二维码登录未完成（error={code} message={message}）")
        }
        _ => format!("二维码登录未完成（error={code}）"),
    }
}

fn json_object_keys(root: &Value, limit: usize) -> String {
    root.as_object()
        .map(|root| {
            root.keys()
                .take(limit)
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

fn set_cookie_names(headers: &header::HeaderMap) -> String {
    let mut names = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty())
        .take(24)
        .map(str::to_string)
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names.join(",")
}

fn compact_diagnostic(value: &str, limit: usize) -> String {
    value
        .replace(['\r', '\n'], " ")
        .chars()
        .take(limit)
        .collect()
}

struct QrHttp {
    status: reqwest::StatusCode,
    headers: header::HeaderMap,
    root: Value,
    transport: &'static str,
}

fn device_query(device: &NativeDevice) -> Vec<(String, String)> {
    // 官方 TTNet 把设备身份与 sdk 标记一起作为 URL query 透传，body 只留协议字段。
    // 只放 body 时二维码能出码，但手机确认页显示“登录设备 未获取到信息”，
    // check_qrconnect 随后返回 2156。
    common_form(device, None)
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct RegisteredDevice {
    device_id: String,
    install_id: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    device_token: String,
    /// 设备特征（dtrait）材料。官方 App 用它在后续请求上生成
    /// `x-tt-device-dtrait` / `x-tt-device-dtrait-token` 头；缺失时 Pad 扫码
    /// 确认页的“登录设备”会显示“未获取到信息”。
    #[serde(default)]
    dtrait_pk1: String,
    #[serde(default)]
    dtrait_pk2: String,
    #[serde(default)]
    dtrait_pk1_version: String,
    #[serde(default)]
    dtrait_pk2_version: String,
    #[serde(default)]
    dtrait_version: String,
    #[serde(default)]
    klink_egdi: String,
}

fn current_device_profile() -> String {
    let profile = serde_json::json!({
        // 设备令牌是官方按“客户端身份 + 设备形状”签发的。换版本号或渠道后
        // 复用旧令牌会被服务端判成“非官方渠道”而返回 1049，因此版本与渠道
        // 必须参与指纹，身份一变就重新登记。
        "aid": "1128",
        "app_name": "aweme",
        "version_code": APP_VERSION_CODE,
        "version_name": APP_VERSION_NAME,
        "manifest_version_code": APP_PACKAGE_VERSION_CODE,
        "update_version_code": APP_UPDATE_VERSION_CODE,
        "channel": APP_CHANNEL,
        "passport_sdk_version": PASSPORT_SDK_VERSION,
        "brand": DEVICE_BRAND,
        "model": DEVICE_TYPE,
        "model_display_name": DEVICE_DISPLAY_MODEL,
        "manufacturer": DEVICE_MANUFACTURER,
        "os_version": DEVICE_OS_VERSION,
        "resolution": DEVICE_RESOLUTION,
        "is_android_pad": IS_ANDROID_PAD,
        "category": "phone",
        "sig_hash": APK_SIG_HASH,
        "profile_rev": "20261110-phone-native-v1",
    });
    hex::encode(Sha256::digest(profile.to_string().as_bytes()))
}

fn registered_device_matches_profile(registered: &RegisteredDevice, profile: &str) -> bool {
    accepted_device_id(&registered.device_id)
        && accepted_device_id(&registered.install_id)
        && !registered.profile.is_empty()
        && registered.profile == profile
}

fn hex_prefix(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn response_shape(root: &Value) -> String {
    let mut parts = Vec::new();
    for (label, container) in [("top", Some(root)), ("data", root.get("data"))] {
        let Some(object) = container.and_then(Value::as_object) else {
            continue;
        };
        let keys = object
            .keys()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let id_len = object
            .get("device_id_str")
            .and_then(Value::as_str)
            .map(str::len)
            .or_else(|| {
                object
                    .get("device_id")
                    .and_then(Value::as_u64)
                    .map(|value| value.to_string().len())
            })
            .unwrap_or(0);
        parts.push(format!("{label}=[{keys}] id_len={id_len}"));
    }
    if parts.is_empty() {
        "shape=empty".to_string()
    } else {
        parts.join(" ")
    }
}

fn accepted_device_id(value: &str) -> bool {
    let value = value.trim();
    (10..=20).contains(&value.len())
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn id_from_json(value: Option<&Value>) -> Option<String> {
    let value = value?;
    let text = if let Some(text) = value.as_str() {
        text.trim().to_string()
    } else if let Some(number) = value.as_u64() {
        number.to_string()
    } else {
        return None;
    };
    accepted_device_id(&text).then_some(text)
}

fn registered_ids_from_response(root: &Value) -> Option<(String, String)> {
    let containers = [Some(root), root.get("data")];
    let device_id = containers.into_iter().find_map(|container| {
        let container = container?;
        id_from_json(container.get("device_id_str"))
            .or_else(|| id_from_json(container.get("device_id")))
    })?;
    let install_id = containers.into_iter().find_map(|container| {
        let container = container?;
        id_from_json(container.get("install_id_str"))
            .or_else(|| id_from_json(container.get("install_id")))
            .or_else(|| id_from_json(container.get("iid")))
    })?;
    Some((device_id, install_id))
}

fn device_register_query(device: &NativeDevice, now_ms: i64) -> Vec<(String, String)> {
    // 首次登记不能带本地编造的 device_id/iid。带了假号，服务端不会发新号，手机也查不到设备名。
    vec![
        ("aid".to_string(), device.aid.clone()),
        ("app_name".to_string(), device.app_name.clone()),
        ("version_code".to_string(), device.version_code.clone()),
        ("version_name".to_string(), device.app_version.clone()),
        (
            "device_platform".to_string(),
            device.device_platform.clone(),
        ),
        ("os".to_string(), "android".to_string()),
        ("os_api".to_string(), "34".to_string()),
        ("os_version".to_string(), DEVICE_OS_VERSION.to_string()),
        ("device_type".to_string(), DEVICE_TYPE.to_string()),
        ("device_brand".to_string(), DEVICE_BRAND.to_string()),
        ("language".to_string(), "zh".to_string()),
        ("channel".to_string(), device.channel.clone()),
        (
            "manifest_version_code".to_string(),
            APP_PACKAGE_VERSION_CODE.to_string(),
        ),
        (
            "update_version_code".to_string(),
            APP_UPDATE_VERSION_CODE.to_string(),
        ),
        ("resolution".to_string(), DEVICE_RESOLUTION.to_string()),
        ("dpi".to_string(), "320".to_string()),
        ("ac".to_string(), "wifi".to_string()),
        ("openudid".to_string(), device.openudid.clone()),
        ("cdid".to_string(), device.cdid.clone()),
        ("appkey".to_string(), "24698276".to_string()),
        ("package".to_string(), device.package.clone()),
        ("is_android_pad".to_string(), IS_ANDROID_PAD.to_string()),
        ("tt_data".to_string(), "a".to_string()),
        ("_rticket".to_string(), now_ms.to_string()),
    ]
}

fn stable_mac(openudid: &str) -> String {
    let digest = Sha256::digest(format!("sparklight-mac:{openudid}").as_bytes());
    let mut bytes = [
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
    ];
    bytes[0] = (bytes[0] & 0xfe) | 0x02;
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// 官方 clientudid 与 openudid 相互独立，这里用固定域派生，避免每次登记漂移。
fn stable_client_udid(openudid: &str) -> String {
    let digest = Sha256::digest(format!("sparklight-clientudid:{openudid}").as_bytes());
    hex::encode(&digest[..16])
}

fn device_register_body(device: &NativeDevice, now_ms: i64) -> Value {
    serde_json::json!({
        "magic_tag": "ss_app_log",
        "_gen_time": now_ms,
        "header": {
            "display_name": DEVICE_DISPLAY_NAME,
            "aid": 1128,
            "app_name": device.app_name,
            "package": device.package,
            "appkey": "24698276",
            "channel": device.channel,
            "app_version": device.app_version,
            "version_code": APP_VERSION_CODE_INT,
            "update_version_code": APP_UPDATE_VERSION_CODE_INT,
            "manifest_version_code": APP_PACKAGE_VERSION_CODE_INT,
            "app_version_minor": "",
            "openudid": device.openudid,
            "cdid": device.cdid,
            "device_id": 0,
            "install_id": 0,
            "mc": stable_mac(&device.openudid),
            "sig_hash": APK_SIG_HASH,
            "clientudid": stable_client_udid(&device.openudid),
            "os": "Android",
            "os_version": DEVICE_OS_VERSION,
            "os_api": 34,
            "device_model": DEVICE_TYPE,
            "model_display_name": DEVICE_DISPLAY_MODEL,
            "device_brand": DEVICE_BRAND,
            "device_manufacturer": DEVICE_MANUFACTURER,
            "device_category": "phone",
            "cpu_abi": "arm64-v8a",
            "language": "zh",
            "app_language": "zh",
            "app_region": "CN",
            "region": "CN",
            "timezone": 8,
            "tz_name": "Asia/Shanghai",
            "tz_offset": 28800,
            "access": "wifi",
            "resolution": "1200x2670",
            "density_dpi": 480,
            "display_density": "xxhdpi",
            "not_request_sender": 0,
            "sdk_version": "6.1.0-rc.7",
            "sdk_target_version": 29,
            "git_hash": "06f9f5f",
            "release_build": "967feac_20261016",
            "is_android_pad": 0
        }
    })
}

fn registry_path() -> Option<PathBuf> {
    let dir = std::env::var("SPARK_DATA_DIR").ok()?;
    let dir = dir.trim();
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir).join("native_device_registry.json"))
}

fn load_device_registry() -> HashMap<String, RegisteredDevice> {
    let Some(path) = registry_path() else {
        return HashMap::new();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return HashMap::new();
    };
    let Ok(raw) = serde_json::from_slice::<HashMap<String, RegisteredDevice>>(&bytes) else {
        tracing::warn!("设备登记缓存无法解析，忽略损坏文件");
        return HashMap::new();
    };
    let profile = current_device_profile();
    raw.into_iter()
        .filter(|(_, item)| registered_device_matches_profile(item, &profile))
        .collect()
}

fn persist_device_registry(map: &HashMap<String, RegisteredDevice>) {
    let Some(path) = registry_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let Ok(bytes) = serde_json::to_vec_pretty(map) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, bytes).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

fn device_registry() -> &'static Mutex<HashMap<String, RegisteredDevice>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, RegisteredDevice>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(load_device_registry()))
}

fn apply_registered(device: &mut NativeDevice, registered: &RegisteredDevice) {
    device.device_id = registered.device_id.clone();
    device.install_id = registered.install_id.clone();
    if !registered.device_token.is_empty() {
        device.device_token = Some(registered.device_token.clone());
    }
}

async fn register_device_once(client: &Client, device: &NativeDevice) -> Result<RegisteredDevice> {
    let now_ms = Utc::now().timestamp_millis();
    let query = device_register_query(device, now_ms);
    let body = device_register_body(device, now_ms);
    ensure!(
        !query
            .iter()
            .any(|(name, _)| matches!(name.as_str(), "device_id" | "iid" | "install_id")),
        "设备登记请求错误地带上了本地设备号"
    );
    let plain = serde_json::to_vec(&body).context("设备登记报文编码失败")?;
    let wire = super::applog_wire::seal_register_body(&plain).context("设备登记报文封包失败")?;
    let response = client
        .post(DEVICE_REGISTER_URL)
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/octet-stream;tt-data=a")
        .header("sdk-version", "2")
        .query(&query)
        .body(wire)
        .send()
        .await
        .map_err(|err| anyhow::anyhow!("无法连接官方设备登记接口（{}）", err.without_url()))?;
    let bytes = read_limited_body(response, "设备登记响应")
        .await
        .context("设备登记未完成")?;
    let decoded = super::applog_wire::open_register_response(&bytes);
    let root: Value = serde_json::from_slice(&decoded).with_context(|| {
        format!(
            "响应不是合法 JSON（{} 字节，前缀 {}）",
            decoded.len(),
            hex_prefix(&decoded, 8)
        )
    })?;
    // 诊断：服务端是否把这些设备档案字段回显/落库。只记录字段名与模型名，
    // 不打印任何令牌。
    tracing::info!(
        response_keys = %json_object_keys(&root, 32),
        device_model_echo = %qr_response_string(&root, &["device_model", "device_name", "model"])
            .map(|value| compact_diagnostic(&value, 48))
            .unwrap_or_default(),
        "设备登记响应字段"
    );
    let Some((device_id, install_id)) = registered_ids_from_response(&root) else {
        let (top_error, data_error) = response_error_codes(&root);
        bail!(
            "官方没有返回可用设备号（error={top_error} data_error={data_error} {}）",
            response_shape(&root)
        );
    };
    // 官方 RegistrationHeaderHelper 把响应里的 device_token 持久化，之后每个 Passport
    // 请求都以 x-tt-dt 头带回。缺令牌时必须补发，否则来源设备无法被识别。
    let device_token = [Some(&root), root.get("data")]
        .into_iter()
        .flatten()
        .filter_map(|container| container.get("device_token"))
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string();
    Ok(RegisteredDevice {
        device_id,
        install_id,
        profile: current_device_profile(),
        device_token,
        dtrait_pk1: registration_field(&root, "dtrait_pk1"),
        dtrait_pk2: registration_field(&root, "dtrait_pk2"),
        dtrait_pk1_version: registration_field(&root, "dtrait_pk1_version"),
        dtrait_pk2_version: registration_field(&root, "dtrait_pk2_version"),
        dtrait_version: registration_field(&root, "dtrait_version"),
        klink_egdi: registration_field(&root, "klink_egdi"),
    })
}

fn registration_field(root: &Value, key: &str) -> String {
    [Some(root), root.get("data")]
        .into_iter()
        .flatten()
        .filter_map(|container| container.get(key))
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

async fn register_login_device(client: &Client, mut device: NativeDevice) -> Result<NativeDevice> {
    static REGISTER_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    let _permit = REGISTER_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let cached = {
        let registry = device_registry()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let profile = current_device_profile();
        registry
            .get(&device.openudid)
            .filter(|found| registered_device_matches_profile(found, &profile))
            .cloned()
    };
    if let Some(found) = cached.as_ref() {
        apply_registered(&mut device, found);
        if !found.device_token.is_empty() {
            tracing::info!(
                device_id_len = device.device_id.len(),
                install_id_len = device.install_id.len(),
                "复用已登记的登录设备与 x-tt-dt 令牌"
            );
            return Ok(device);
        }
        // 旧缓存只存了设备号。108 实测：同一 openudid 重复登记会返回相同 device_id
        // 与新的 device_token，所以这里再登记一次把 x-tt-dt 补上。
        tracing::info!("已登记设备缺少 x-tt-dt 设备令牌，向官方补发");
    }

    // 官方对同一 openudid 重复登记会返回相同 device_id 与新的 device_token，所以这里
    // 允许有限重试：限流时 device_id=0，缺令牌时补发。缺 x-tt-dt 的登录在确认环节
    // 会被按“来源设备无法识别”拒绝，值得用几秒退避换一个完整设备身份。
    let mut last_shape = String::new();
    let mut registered: Option<RegisteredDevice> = None;
    for attempt in 0..DEVICE_REGISTER_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(1_500)).await;
        }
        match register_device_once(client, &device).await {
            Ok(item) => {
                let complete = !item.device_token.is_empty();
                registered = Some(item);
                if complete {
                    break;
                }
                tracing::warn!("设备登记未下发 x-tt-dt 设备令牌，退避后补发");
            }
            Err(error) => {
                last_shape = error.to_string();
                tracing::warn!(reason = %error, attempt, "设备登记单次尝试未完成");
            }
        }
    }
    let Some(registered) = registered else {
        // 限流时官方返回 device_id=0。已有缓存身份就继续沿用，登录入口不能被堵死。
        if let Some(found) = cached {
            apply_registered(&mut device, &found);
            tracing::warn!(
                device_id_len = device.device_id.len(),
                "设备登记被限流，沿用已登记设备身份继续申请二维码"
            );
            return Ok(device);
        }
        bail!(
            "设备登记未完成：{}。请稍后再获取二维码，不要连续重试。",
            if last_shape.is_empty() {
                "官方没有返回可用设备号".to_string()
            } else {
                last_shape
            }
        );
    };
    let registered = match (registered.device_token.is_empty(), cached.as_ref()) {
        (true, Some(found)) if !found.device_token.is_empty() => RegisteredDevice {
            device_token: found.device_token.clone(),
            ..registered
        },
        _ => registered,
    };
    apply_registered(&mut device, &registered);
    {
        let mut registry = device_registry()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.insert(device.openudid.clone(), registered);
        persist_device_registry(&registry);
    }
    tracing::info!(
        device_id_len = device.device_id.len(),
        install_id_len = device.install_id.len(),
        device_token_present = !device
            .device_token
            .as_deref()
            .unwrap_or_default()
            .is_empty(),
        "登录设备已完成官方登记"
    );
    Ok(device)
}

async fn passport_request(
    client: &Client,
    jar: &Jar,
    method: Method,
    path: &str,
    query: &[(String, String)],
    form: &[(String, String)],
    device_token: Option<&str>,
) -> Result<reqwest::Response> {
    // 官方 TTNet 把设备身份作为 URL query 透传，body 只承载各自接口的
    // 协议字段。只放 body 时二维码能出码，但手机端确认页会显示
    // “登录设备 未获取到信息”，确认后 check_qrconnect 返回 2156。
    let mut request = client
        .request(method.clone(), format!("https://aweme.snssdk.com{path}"))
        .query(query)
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .header("sdk-version", "2");
    if let Some(csrf_token) = passport_csrf_token(jar) {
        request = request.header("x-tt-passport-csrf-token", csrf_token);
    }
    // DeviceRegisterManager 把登记的 device_token 固定写成 x-tt-dt 头，服务端
    // 在扫码确认环节用它绑定来源设备；缺失时确认返回空状态 2156。
    if let Some(device_token) = device_token.filter(|value| !value.trim().is_empty()) {
        request = request.header("x-tt-dt", device_token);
    }
    // TTNet 原生签名头里有两项是确定性算法，可以先按官方规则补齐：
    //   x-khronos  = 当前 Unix 秒
    //   x-ss-stub  = 请求体的 MD5，大写十六进制
    // 其余 x-gorgon / x-argus / x-ladon 由原生签名器生成。
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().map(|(key, value)| (key.as_str(), value.as_str())))
        .finish();
    let khronos = Utc::now().timestamp().to_string();
    let stub = format!("{:X}", md5::compute(body.as_bytes()));
    request = request
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("tt-request-time", &khronos)
        .header("x-khronos", khronos)
        .header("x-ss-stub", stub)
        .body(body);
    tracing::info!(
        method = %method,
        path = %path,
        query_keys = %query.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(","),
        form_keys = %form.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(","),
        user_agent_present = true,
        "passport_request_debug"
    );
    request.send().await.context("请求抖音 Passport 失败")
}

async fn read_qr_http(response: reqwest::Response, transport: &'static str) -> Result<QrHttp> {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = read_limited_body(response, "二维码状态响应").await?;
    let root: Value = serde_json::from_slice(&bytes).context("二维码状态响应不是合法 JSON")?;
    Ok(QrHttp {
        status,
        headers,
        root,
        transport,
    })
}

fn bare_qr_busy(root: &Value) -> bool {
    let status = normalize_qr_status(&qr_response_status(root));
    if !matches!(status.as_str(), "" | "new" | "loading") {
        return false;
    }
    if challenge_from_response(root).is_some() || LoginVerification::from_response(root).is_some() {
        return false;
    }
    let (top_error, data_error) = response_error_codes(root);
    top_error == 2156 || data_error == 2156
}

fn nonempty_response_field(root: &Value, key: &str) -> bool {
    qr_response_string(root, &[key]).is_some_and(|value| !value.trim().is_empty())
}

async fn fetch_qr_check(session: &LoginSession) -> Result<QrHttp> {
    // 官方 CheckQrConnectParams 只 POST 一次。2156 后改 GET is_frontier 会打出 4044，
    // 而该错误又会盖住仍可继续等待的确认。
    let form = qr_check_form(&session.device, &session.token);
    read_qr_http(
        passport_request(
            &session.client,
            &session.jar,
            Method::POST,
            "/passport/mobile/check_qrconnect/",
            &device_query(&session.device),
            &form,
            session.device.device_token.as_deref(),
        )
        .await?,
        "post",
    )
    .await
}

fn common_form(device: &NativeDevice, extra: Option<(&str, &str)>) -> Vec<(String, String)> {
    let mut form = vec![
        ("aid".to_string(), device.aid.clone()),
        ("app_name".to_string(), device.app_name.clone()),
        (
            "device_platform".to_string(),
            device.device_platform.clone(),
        ),
        ("device_id".to_string(), device.device_id.clone()),
        ("iid".to_string(), device.install_id.clone()),
        ("install_id".to_string(), device.install_id.clone()),
        ("openudid".to_string(), device.openudid.clone()),
        ("cdid".to_string(), device.cdid.clone()),
        ("channel".to_string(), device.channel.clone()),
        ("version_code".to_string(), device.version_code.clone()),
        ("version_name".to_string(), device.app_version.clone()),
        (
            "passport-sdk-version".to_string(),
            PASSPORT_SDK_VERSION.to_string(),
        ),
        ("use_new_token_expire_rule".to_string(), "true".to_string()),
        ("request_from_account_sdk".to_string(), "1".to_string()),
        ("is_from_ttaccountsdk".to_string(), "1".to_string()),
        ("account_sdk_source".to_string(), "app".to_string()),
        ("is_from_iesaccountsaas".to_string(), "1".to_string()),
        ("account_app_language".to_string(), "zh".to_string()),
        ("language".to_string(), "zh".to_string()),
        ("sec_sdk_version".to_string(), "67699200".to_string()),
        // App 的公共参数清单（CommonParamsAuditor / RelatedSDKVersionChecker）用
        // 单字母键 `n` 上报 Passport SDK 版本，值为 67699200；缺失时服务端会把
        // 客户端按“SDK 版本过低”处理，扫码确认阶段返回 1049。
        ("n".to_string(), "67699200".to_string()),
        ("auth_sdk_version".to_string(), "4.4.0".to_string()),
        ("verify_sdk_version".to_string(), "3.7.5".to_string()),
        ("ttnet_sdk_version".to_string(), "4.2.223.13".to_string()),
        ("ac".to_string(), "wifi".to_string()),
        ("device_brand".to_string(), DEVICE_BRAND.to_string()),
        ("device_type".to_string(), DEVICE_TYPE.to_string()),
        ("os_version".to_string(), DEVICE_OS_VERSION.to_string()),
        ("resolution".to_string(), DEVICE_RESOLUTION.to_string()),
        (
            "update_version_code".to_string(),
            APP_UPDATE_VERSION_CODE.to_string(),
        ),
        (
            "manifest_version_code".to_string(),
            APP_PACKAGE_VERSION_CODE.to_string(),
        ),
        ("package".to_string(), device.package.clone()),
        ("is_android_pad".to_string(), IS_ANDROID_PAD.to_string()),
        (
            "passport_support_flow".to_string(),
            // oldsrc（Oct-22 确认可登录）用 real_name_check；当前值引入了
            // choose_account，确认环节被服务端按“非官方渠道”拒绝（1049）。
            "real_name_check".to_string(),
        ),
        ("multi_login".to_string(), "1".to_string()),
        ("is_vcd".to_string(), "1".to_string()),
        (
            "identity_token_client_request".to_string(),
            "1".to_string(),
        ),
    ];
    if let Some((key, value)) = extra {
        form.push((key.to_string(), value.to_string()));
    }
    form
}

fn qr_get_form(device: &NativeDevice) -> Vec<(String, String)> {
    // X.02Ks（GetQrCodeParams）toMap 的真实字段；设备身份由 TTNet 层作为
    // query 透传，因此 body 只保留协议字段。
    let _ = device;
    vec![
        ("service".to_string(), QR_GET_SERVICE.to_string()),
        ("scene".to_string(), "0".to_string()),
        ("need_logo".to_string(), "1".to_string()),
        ("source".to_string(), QR_SOURCE.to_string()),
        ("path".to_string(), "/passport/mobile/get_qrcode/".to_string()),
        ("is_from_iesaccountsaas".to_string(), "1".to_string()),
        ("is_from_ttaccountsdk".to_string(), "1".to_string()),
        ("is_vcd".to_string(), "1".to_string()),
        ("multi_login".to_string(), "1".to_string()),
        (
            "safe_mobile_register_to_login".to_string(),
            "true".to_string(),
        ),
        // Pad 确认页的“登录设备”取自这里；缺省时手机端显示“未获取到信息”。
        ("device_name".to_string(), DEVICE_DISPLAY_MODEL.to_string()),
        ("device_model".to_string(), DEVICE_DISPLAY_MODEL.to_string()),
    ]
}

fn qr_check_form(device: &NativeDevice, token: &str) -> Vec<(String, String)> {
    // X.02MZ（CheckQrConnectParams）toMap 的真实字段。
    let _ = device;
    vec![
        ("token".to_string(), token.to_string()),
        ("service".to_string(), QR_CHECK_SERVICE.to_string()),
        ("scene".to_string(), "0".to_string()),
        ("user_api_need_combine".to_string(), "1".to_string()),
        ("is_from_iesaccountsaas".to_string(), "1".to_string()),
        ("is_from_ttaccountsdk".to_string(), "1".to_string()),
        ("is_vcd".to_string(), "1".to_string()),
        ("multi_login".to_string(), "1".to_string()),
        (
            "safe_mobile_register_to_login".to_string(),
            "true".to_string(),
        ),
    ]
}

fn has_strong_auth_cookie(cookie: &str) -> bool {
    cookie.split(';').any(|part| {
        let Some((name, value)) = part.trim().split_once('=') else {
            return false;
        };
        !value.trim().is_empty()
            && matches!(
                name.trim(),
                "sessionid" | "sessionid_ss" | "sid_guard" | "sid_tt"
            )
    })
}

fn transient_status_error(root: &Value) -> Option<(i64, &'static str)> {
    let status = normalize_qr_status(&qr_response_status(root));
    if !matches!(
        status.as_str(),
        "" | "new" | "loading" | "scanned" | "verifying"
    ) {
        return None;
    }
    let (top_error, data_error) = response_error_codes(root);
    [top_error, data_error]
        .into_iter()
        .find_map(|code| match code {
            // 2156 is the App's retryable "system busy / error" class, not a terminal
            // login failure. Keep the QR session alive and let the user scan it.
            7 => Some((7, "loading")),
            2156 => Some((2156, "loading")),
            _ => None,
        })
}

fn normalize_qrcode(value: Option<&Value>) -> Result<String> {
    let raw = value_string(value);
    ensure!(!raw.trim().is_empty(), "抖音二维码图片为空");
    if raw.starts_with("data:image/") {
        ensure!(raw.len() <= 2 * 1024 * 1024, "抖音二维码图片超长");
        return Ok(raw);
    }
    if raw.starts_with("https://") || raw.starts_with("http://") {
        bail!("抖音返回了未登记的二维码图片地址");
    }
    ensure!(raw.len() <= 2 * 1024 * 1024, "抖音二维码图片超出安全上限");
    Ok(format!("data:image/png;base64,{raw}"))
}

fn official_error_detail(root: &Value) -> String {
    let detail = root
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| {
            first_value_string(
                data,
                &["description", "error_description", "verify_scene_desc"],
            )
        })
        .or_else(|| {
            root.get("description")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let detail = compact_diagnostic(&detail, 160);
    if detail.is_empty() || detail == "error" || detail == "success" {
        String::new()
    } else {
        detail
    }
}

fn ensure_success(root: &Value, label: &str) -> Result<()> {
    let message = root
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (top_error, data_error) = response_error_codes(root);
    if top_error != 0 || data_error != 0 || (!message.is_empty() && message != "success") {
        if top_error == 4044 || data_error == 4044 {
            bail!("{label}未成功：{QR_4044_REJECTION}");
        }
        let message = compact_diagnostic(message, 120);
        let detail = official_error_detail(root);
        if detail.is_empty() || detail == message {
            bail!(
                "{}未成功（error={} data_error={} message={}）",
                label,
                top_error,
                data_error,
                message
            );
        }
        bail!(
            "{}未成功（error={} data_error={} message={} description={}）",
            label,
            top_error,
            data_error,
            message,
            detail
        );
    }
    Ok(())
}

/// 4044 在官方响应里固定写成“请将应用升级至最新版本后重试”，但 108 实测它由
/// Passport 请求合同缺陷触发：get_qrcode 的 body 缺少 `is_from_ttaccountsdk=1`
/// 时立即返回 4044，补齐即可出码；version_code、设备型号、TicketGuard 证书均不影响。
const QR_4044_REJECTION: &str = "抖音拒绝了本次登录发起（error=4044）：官方提示的“请升级应用”具有误导性，实测该错误由 Passport 请求合同缺陷触发，与应用版本无关。请联系维护者按 get_qrcode 请求合同排查，或改用官方 Android 客户端已登录的原生会话导入。";
const QR_1049_REJECTION: &str = "抖音拒绝了本次扫码登录（error=1049）：官方提示的“应用版本过低或非官方渠道”具有误导性，实测由客户端身份（版本/渠道/SDK 号）或请求线格式与官方 Android App 不一致触发，与应用升级无关。请重新扫码；若复现，改用官方 Android 客户端已登录的原生会话导入。";

async fn read_limited_body(response: reqwest::Response, label: &str) -> Result<Vec<u8>> {
    let status = response.status();
    ensure!(status.is_success(), "{label} HTTP 状态异常：{status}");
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= MAX_RESPONSE_BYTES as u64),
        "{label}超出安全上限"
    );
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("读取官方响应失败")? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_RESPONSE_BYTES,
            "{label}超出安全上限"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn cookie_snapshot(jar: &Jar) -> String {
    let mut cookie = String::new();
    for url in [
        "https://aweme.snssdk.com/",
        "https://snssdk.com/",
        "https://www.douyin.com/",
        "https://douyin.com/",
    ] {
        let Ok(url) = reqwest::Url::parse(url) else {
            continue;
        };
        let Some(header) = CookieStore::cookies(jar, &url) else {
            continue;
        };
        let Ok(header) = header.to_str() else {
            continue;
        };
        let parts: Vec<&str> = header
            .split(';')
            .map(str::trim)
            .filter(|part| {
                part.contains('=')
                    && !part.starts_with("bd_ticket_guard_server_data=")
                    && !part.starts_with("bd_ticket_guard_web_domain=")
            })
            .collect();
        let (merged, _) = merge_cookies(&cookie, &parts);
        cookie = merged;
    }
    cookie
}

fn passport_csrf_token(jar: &Jar) -> Option<String> {
    let url = reqwest::Url::parse("https://aweme.snssdk.com/").ok()?;
    let cookies = CookieStore::cookies(jar, &url)?;
    let cookies = cookies.to_str().ok()?;
    let mut fallback = None;
    for part in cookies.split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match name.trim() {
            "passport_csrf_token" => return Some(value.to_string()),
            "passport_csrf_token_default" if fallback.is_none() => {
                fallback = Some(value.to_string());
            }
            _ => {}
        }
    }
    fallback
}

fn value_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn value_i64(value: Option<&Value>) -> Option<i64> {
    value.and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
}

fn first_value_string(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .map(|value| value_string(Some(value)))
        .filter(|value| !value.trim().is_empty())
}

fn first_positive_uid(object: &serde_json::Map<String, Value>) -> Option<String> {
    for key in ["user_id_str", "user_id", "uid_str", "uid"] {
        let candidate = value_string(object.get(key));
        let trimmed = candidate.trim();
        if trimmed.parse::<u64>().ok().is_some_and(|uid| uid > 0) {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn cookie_value(cookie: &str, target: &str) -> Option<String> {
    cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name.trim() == target)
            .then(|| value.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

fn terminal_message(data: Option<&serde_json::Map<String, Value>>, root: &Value) -> String {
    let message = data
        .and_then(|data| first_value_string(data, &["error_name", "message", "description"]))
        .or_else(|| {
            root.get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    if message.trim().is_empty() {
        "二维码登录未完成，请重新获取".to_string()
    } else {
        message.chars().take(160).collect()
    }
}

fn normalize_unix_timestamp(value: i64) -> i64 {
    if value > 10_000_000_000 {
        value / 1000
    } else {
        value
    }
}

fn resolve_login_expiry(official_expiry: Option<i64>, now: i64) -> i64 {
    official_expiry
        .map(normalize_unix_timestamp)
        .filter(|value| *value > now)
        .unwrap_or_else(|| now + LOGIN_SESSION_TTL_SECS)
}

/// App 侧 `d_ticket` 的传递编码：UTF-8 每个字节 XOR 0x05，再输出小写十六进制。
pub fn encode_d_ticket(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{:02x}", byte ^ 0x05))
        .collect()
}

/// App Token 的本地持久化编码：每个字符减去 `i % 5`，然后反转字符串。
pub fn decode_token_encrypted(value: &str) -> String {
    let shifted = value
        .chars()
        .enumerate()
        .map(|(index, ch)| char::from_u32(ch as u32 - (index % 5) as u32).unwrap_or(ch))
        .collect::<String>();
    shifted.chars().rev().collect()
}

/// 与 [`decode_token_encrypted`] 对称的编码，便于测试和恢复明确格式。
pub fn encode_token_encrypted(value: &str) -> String {
    let reversed = value.chars().rev().collect::<String>();
    reversed
        .chars()
        .enumerate()
        .map(|(index, ch)| char::from_u32(ch as u32 + (index % 5) as u32).unwrap_or(ch))
        .collect()
}

fn plain_x_tt_token(record: &NativeSessionRecord) -> Option<String> {
    record
        .x_tt_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            record
                .token_encrypted
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .map(decode_token_encrypted)
        })
}

fn native_client(record: &NativeSessionRecord) -> Result<Client> {
    record.validate()?;
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        header::HeaderValue::from_str(&record.device.user_agent)
            .context("原生设备 User-Agent 无效")?,
    );
    headers.insert(
        header::ACCEPT,
        header::HeaderValue::from_static("application/json, text/plain, */*"),
    );
    Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(20))
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("创建原生会话检查客户端失败")
}

#[derive(Debug, Clone)]
pub enum NativeCheck {
    Valid(DouyinUserProfile),
    Expired(String),
    Unconfirmed(String),
}

impl NativeCheck {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Valid(_) => "App 原生会话有效",
            Self::Expired(message) | Self::Unconfirmed(message) => message,
        }
    }
}

/// 使用 App 原生凭证访问官方账号资料接口。
///
/// 只有响应明确返回有效 UID 才判定有效；只有明确的 `session_expired` /
/// `session_drop` / 登录注销错误才判定失效。网络、限流、非 JSON 与协议变化全部返回
/// “未确认”，调用方不得因此覆盖仍可恢复的 Cookie。
pub async fn check_native_session(record: &NativeSessionRecord) -> NativeCheck {
    if let Some(expiry) = record.sid_expiry() {
        if expiry <= Utc::now().timestamp() {
            return NativeCheck::Expired("App 登录会话已超过 sid_guard 绝对有效期".to_string());
        }
    }
    let client = match native_client(record) {
        Ok(client) => client,
        Err(error) => return NativeCheck::Unconfirmed(format!("原生检查客户端创建失败：{error}")),
    };
    if let Ok(web_resp) = client
        .get("https://www.douyin.com/passport/account/info/v2/?aid=6383&account_sdk_source=web&is_from_ttaccountsdk=1")
        .header(header::USER_AGENT, WEB_LOGIN_UA)
        .header(header::COOKIE, &record.cookie)
        .header(header::ACCEPT, "application/json, text/javascript")
        .header(header::REFERER, "https://www.douyin.com/")
        .send()
        .await
        && let Ok(web_bytes) = read_limited_body(web_resp, "Web 账号检查响应").await
        && let Ok(web_root) = serde_json::from_slice::<Value>(&web_bytes)
    {
        let web_error_name = web_root
            .get("data")
            .and_then(Value::as_object)
            .and_then(|d| d.get("error_name"))
            .or_else(|| web_root.get("error_name"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if ["session_expired", "session_drop", "login_required"]
            .iter()
            .any(|v| web_error_name.eq_ignore_ascii_case(v))
        {
            return NativeCheck::Expired(format!("App 登录会话已失效：{web_error_name}"));
        }
        if let Some(web_data) = web_root
            .get("data")
            .and_then(Value::as_object)
            .and_then(|d| d.get("user_data").and_then(Value::as_object).or(Some(d)))
            && let Some(uid) = first_positive_uid(web_data)
        {
            if uid != record.uid {
                return NativeCheck::Expired("App 登录身份与绑定账号不一致".to_string());
            }
            return NativeCheck::Valid(DouyinUserProfile {
                uid,
                sec_uid: first_value_string(web_data, &["sec_user_id", "sec_uid"])
                    .unwrap_or_else(|| record.sec_uid.clone()),
                nickname: first_value_string(web_data, &["name", "username", "nickname", "screen_name"])
                    .unwrap_or_else(|| record.nickname.clone()),
                avatar_url: first_value_string(web_data, &["avatar_url", "avatar_thumb"])
                    .unwrap_or_else(|| record.avatar_url.clone()),
            });
        }
        if record.ts_sign.as_deref().filter(|s| !s.is_empty()).is_none() {
            return NativeCheck::Unconfirmed("Web 会话检查未返回有效 UID，未判定会话失效".to_string());
        }
    }
    if record.ts_sign.as_deref().filter(|s| !s.is_empty()).is_none() {
        return NativeCheck::Unconfirmed("Web 会话检查网络未完成，保留现有登录态".to_string());
    }
    let mut request = client
        .request(
            Method::GET,
            "https://aweme.snssdk.com/passport/account/info/v2/",
        )
        .query(&[
            ("aid", record.device.aid.as_str()),
            ("device_platform", "android"),
            ("app_name", "aweme"),
            ("version_code", record.device.version_code.as_str()),
            ("version_name", record.device.app_version.as_str()),
            ("passport-sdk-version", PASSPORT_SDK_VERSION),
            ("request_from_account_sdk", "1"),
            ("is_from_ttaccountsdk", "1"),
            ("account_sdk_source", "app"),
            ("is_from_iesaccountsaas", "1"),
        ])
        .header(header::COOKIE, &record.cookie)
        .header("x-uc-sec-uid", &record.sec_uid)
        .header("sdk-version", "2")
        .header("passport-sdk-version", PASSPORT_SDK_VERSION);
    if let Some(device_token) = record
        .device
        .device_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        request = request.header("x-tt-dt", device_token);
    }
    if let Some(token) = plain_x_tt_token(record) {
        request = request.header("X-Tt-Token", token);
    }
    if let Some(ts_sign) = record.ts_sign.as_deref().filter(|value| !value.is_empty()) {
        request = request.header("ts_sign", ts_sign);
    }
    if let Some(attest) = record
        .attest_ts_sign
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        request = request.header("attest_ts_sign", attest);
    }
    if let Some(d_ticket) = record.d_ticket.as_deref().filter(|value| !value.is_empty()) {
        request = request.header("x-tt-d-ticket", encode_d_ticket(d_ticket));
    }
    if let Some(mfa_token) = record
        .mfa_token
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        request = request.header("x-tt-passport-mfa-token", mfa_token);
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(_) => {
            return NativeCheck::Unconfirmed("App 账号检查网络未完成，保留现有登录态".to_string());
        }
    };
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return NativeCheck::Unconfirmed(format!(
            "App 账号检查被拒绝（HTTP {status}），不能据此清除会话"
        ));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return NativeCheck::Unconfirmed("App 账号检查被限流，保留现有登录态".to_string());
    }
    if !status.is_success() {
        return NativeCheck::Unconfirmed(format!("App 账号检查服务暂不可用（HTTP {status}）"));
    }
    let bytes = match read_limited_body(response, "App 账号检查响应").await {
        Ok(bytes) => bytes,
        Err(_) => {
            return NativeCheck::Unconfirmed(
                "App 账号检查响应读取失败，保留现有登录态".to_string(),
            );
        }
    };
    let root: Value = match serde_json::from_slice(&bytes) {
        Ok(root) => root,
        Err(_) => {
            return NativeCheck::Unconfirmed("App 账号检查返回非 JSON，未判定会话失效".to_string());
        }
    };
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| {
            data.get("user_data")
                .and_then(Value::as_object)
                .or(Some(data))
        });
    let error_name = root
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get("error_name"))
        .or_else(|| root.get("error_name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if ["session_expired", "session_drop", "login_required"]
        .iter()
        .any(|value| error_name.eq_ignore_ascii_case(value))
    {
        return NativeCheck::Expired(format!("App 登录会话已失效：{error_name}"));
    }
    let Some(data) = data else {
        return NativeCheck::Unconfirmed("App 账号检查缺少账号资料，未判定会话失效".to_string());
    };
    let uid = first_positive_uid(data);
    let Some(uid) = uid else {
        return NativeCheck::Unconfirmed("App 账号检查未返回有效 UID，未判定会话失效".to_string());
    };
    if uid != record.uid {
        return NativeCheck::Expired("App 登录身份与绑定账号不一致".to_string());
    }
    NativeCheck::Valid(DouyinUserProfile {
        uid,
        sec_uid: first_value_string(data, &["sec_user_id", "sec_uid"])
            .unwrap_or_else(|| record.sec_uid.clone()),
        nickname: first_value_string(data, &["name", "username", "nickname", "screen_name"])
            .unwrap_or_else(|| record.nickname.clone()),
        avatar_url: first_value_string(data, &["avatar_url", "avatar_thumb"])
            .unwrap_or_else(|| record.avatar_url.clone()),
    })
}

/// 官方 App TokenBeat。失败时只返回错误，调用方必须保留旧记录。
pub async fn beat_native_session(
    record: &NativeSessionRecord,
    scene: &str,
) -> Result<NativeSessionRecord> {
    let (_, _, _, updated, _) = beat_native_session_observed(record, scene).await?;
    Ok(updated)
}

/// 与正式 TokenBeat 共用同一条请求与校验路径，额外返回脱敏诊断摘要。
/// 摘要只包含状态码、错误码、响应字段名和 Cookie 名，不含任何凭证值。
pub async fn beat_native_session_observed(
    record: &NativeSessionRecord,
    scene: &str,
) -> Result<(u16, i64, i64, NativeSessionRecord, Vec<String>)> {
    ensure!(
        matches!(scene, "boot" | "polling" | "active" | "wap_login"),
        "App TokenBeat scene 未登记"
    );
    if record.ts_sign.as_deref().filter(|s| !s.is_empty()).is_none() {
        let client = native_client(record)?;
        let response = client
            .get("https://www.douyin.com/passport/account/info/v2/?aid=6383&account_sdk_source=web&is_from_ttaccountsdk=1")
            .header(header::USER_AGENT, WEB_LOGIN_UA)
            .header(header::COOKIE, &record.cookie)
            .header(header::ACCEPT, "application/json, text/javascript")
            .header(header::REFERER, "https://www.douyin.com/")
            .send()
            .await
            .context("Web 会话保活检查网络失败")?;
        let response_headers = response.headers().clone();
        let http_status = response.status().as_u16();
        let bytes = read_limited_body(response, "Web 会话保活响应").await?;
        let root: Value = serde_json::from_slice(&bytes).context("Web 会话保活返回非 JSON")?;
        let (top_error, data_error) = response_error_codes(&root);
        ensure_success(&root, "Web 会话保活")?;
        let set_cookies = response_headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        let (cookie, _) = merge_cookies(&record.cookie, &set_cookies);
        let mut updated = record.clone();
        updated.cookie = cookie;
        let now = Utc::now().timestamp();
        updated.last_beat_at = Some(now);
        updated.last_verified_at = Some(now);
        updated.validate()?;
        return Ok((
            http_status,
            top_error,
            data_error,
            updated,
            vec!["mode=web_aid_6383".to_string()],
        ));
    }
    let token = plain_x_tt_token(record).context("App TokenBeat 缺少 X-Tt-Token")?;
    let client = native_client(record)?;
    let mut url = reqwest::Url::parse("https://aweme.snssdk.com/passport/token/beat/v2/")
        .context("App TokenBeat 地址无效")?;
    url.query_pairs_mut()
        .append_pair("scene", scene)
        .append_pair("first_beat", "false")
        .append_pair("aid", &record.device.aid);
    let mut request = client
        .get(url)
        .header(header::COOKIE, &record.cookie)
        .header("X-Tt-Token", token)
        .header("x-uc-sec-uid", &record.sec_uid)
        .header("sdk-version", "2")
        .header("passport-sdk-version", PASSPORT_SDK_VERSION);
    if let Some(device_token) = record
        .device
        .device_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        request = request.header("x-tt-dt", device_token);
    }
    if let Some(ts_sign) = record.ts_sign.as_deref().filter(|value| !value.is_empty()) {
        request = request.header("ts_sign", ts_sign);
    }
    if let Some(attest) = record
        .attest_ts_sign
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        request = request.header("attest_ts_sign", attest);
    }
    if let Some(mfa_token) = record
        .mfa_token
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        request = request.header("x-tt-passport-mfa-token", mfa_token);
    }
    if let Some(d_ticket) = record.d_ticket.as_deref().filter(|value| !value.is_empty()) {
        request = request.header("x-tt-d-ticket", encode_d_ticket(d_ticket));
    }
    let response = request.send().await.context("App TokenBeat 网络失败")?;
    let response_headers = response.headers().clone();
    let http_status = response.status().as_u16();
    let bytes = read_limited_body(response, "App TokenBeat 响应").await?;
    let root: Value = serde_json::from_slice(&bytes).context("App TokenBeat 返回非 JSON")?;
    let (top_error, data_error) = response_error_codes(&root);
    let set_cookie_names = set_cookie_names(&response_headers);
    let data_keys = root
        .get("data")
        .and_then(Value::as_object)
        .map(|data| data.keys().take(48).cloned().collect::<Vec<_>>().join(","))
        .unwrap_or_default();
    tracing::info!(
        scene,
        top_error,
        data_error,
        root_keys = %json_object_keys(&root, 32),
        data_keys = %data_keys,
        sent_ts_sign = record.ts_sign.as_deref().is_some_and(|value| !value.is_empty()),
        sent_attest_ts_sign = record
            .attest_ts_sign
            .as_deref()
            .is_some_and(|value| !value.is_empty()),
        sent_mfa_token = record
            .mfa_token
            .as_deref()
            .is_some_and(|value| !value.is_empty()),
        sent_d_ticket = record
            .d_ticket
            .as_deref()
            .is_some_and(|value| !value.is_empty()),
        set_cookie_names = %set_cookie_names,
        has_response_token = response_headers
            .get("x-tt-token")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.trim().is_empty()),
        "抖音 App TokenBeat 响应"
    );
    ensure_success(&root, "App TokenBeat")?;
    let set_cookies = response_headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    let (cookie, _) = merge_cookies(&record.cookie, &set_cookies);
    let mut updated = record.clone();
    updated.cookie = cookie;
    if let Some(token) = response_headers
        .get("X-Tt-Token")
        .or_else(|| response_headers.get("x-tt-token"))
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
    {
        updated.x_tt_token = Some(token.to_string());
    }
    if let Some(data) = root.get("data").and_then(Value::as_object) {
        if let Some(token) = first_value_string(data, &["X-Tt-Token", "x_tt_token"]) {
            updated.x_tt_token = Some(token);
        }
        if let Some(token) = first_value_string(data, &["token_encrypted"]) {
            updated.token_encrypted = Some(token);
        }
        if let Some(ts_sign) = first_value_string(data, &["ts_sign"]) {
            updated.ts_sign = Some(ts_sign);
        }
        if let Some(attest) = first_value_string(data, &["attest_ts_sign"]) {
            updated.attest_ts_sign = Some(attest);
        }
        if let Some(mfa_token) = first_value_string(data, &["mfa_token"]) {
            updated.mfa_token = Some(mfa_token);
        }
    }
    let now = Utc::now().timestamp();
    updated.last_beat_at = Some(now);
    updated.last_verified_at = Some(now);
    updated.validate()?;
    let diagnostics = vec![
        format!("root_keys={}", json_object_keys(&root, 32)),
        format!("data_keys={data_keys}"),
        format!("set_cookie_names={set_cookie_names}"),
        format!(
            "sent_ts_sign={}",
            record
                .ts_sign
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        ),
        format!(
            "sent_attest_ts_sign={}",
            record
                .attest_ts_sign
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        ),
        format!(
            "sent_mfa_token={}",
            record
                .mfa_token
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        ),
        format!(
            "sent_d_ticket={}",
            record
                .d_ticket
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        ),
        format!(
            "has_response_token={}",
            response_headers
                .get("x-tt-token")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| !value.trim().is_empty())
        ),
    ];
    Ok((http_status, top_error, data_error, updated, diagnostics))
}

/// 账号登录落库前尝试建立 Web/IM 上下文。
///
/// App 扫码得到的 Cookie 可能同时覆盖 Web 域。这里只在内存中完成 Guard 与身份材料校验，
/// 任一步失败都不影响原生登录本身，也不会覆盖已保存的旧 Web 上下文；调用方可以依据
/// `web_ready` 明确展示发送能力尚未就绪。
pub async fn bootstrap_web_context(
    record: &NativeSessionRecord,
    device_profile: &super::device_profile::DeviceProfile,
) -> Result<(
    String,
    super::im_auth::WebSessionContext,
    crate::douyin::types::DouyinUserProfile,
)> {
    let uid = record
        .uid
        .parse::<u64>()
        .ok()
        .filter(|uid| *uid > 0)
        .context("Web 引导 UID 无效")?;
    let now = Utc::now().timestamp();
    let mut initial_cookie = record.cookie.clone();
    let mut prebound_guard: Option<(super::pcim_guard::GuardKey, super::pcim_guard::BoundGuardMaterial)> = None;
    if let Some(gk_hex) = record.guard_key_hex.as_deref().filter(|s| !s.trim().is_empty())
        && let Ok(gk) = super::pcim_guard::GuardKey::from_hex(gk_hex)
    {
        let carrier = record
            .guard_server_data
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|srv| format!("bd_ticket_guard_server_data={srv}"))
            .unwrap_or_else(|| record.cookie.clone());
        if let Ok(Some(mat)) = gk.bind_server_cookie(&carrier, uid, &record.cookie, now) {
            if let Ok(aligned) = super::pcim_guard::align_guard_cookie(
                &record.cookie,
                &gk.public_key_base64(),
                Some(&mat),
            ) {
                initial_cookie = aligned;
            }
            prebound_guard = Some((gk, mat));
        }
    }
    let client = DouyinClient::with_device_profile(
        &initial_cookie,
        &record.nickname,
        device_profile.clone(),
    )?;
    let mut context = super::im_auth::WebSessionContext::from_session_with_device(
        uid,
        &initial_cookie,
        &device_profile.user_agent,
        Some(device_profile.clone()),
    )?;
    if let Some(gk_hex) = record.guard_key_hex.as_deref().filter(|s| !s.trim().is_empty())
        && let Ok(gk) = super::pcim_guard::GuardKey::from_hex(gk_hex)
    {
        context.guard_secret_hex = Some(gk.to_hex());
    }
    if let Some((ref gk, ref mat)) = prebound_guard {
        context.guard_secret_hex = Some(gk.to_hex());
        context.set_guard_material(mat)?;
    }
    if let (Some(pem), Some(ver)) = (
        record.dtrait_pk1_pem.as_deref().filter(|s| !s.is_empty()),
        record.dtrait_version.as_deref().filter(|s| !s.is_empty()),
    ) {
        context.set_dtrait_config(pem, ver);
    }
    client.set_web_context(context)?;
    let profile = match client.check_cookie().await {
        crate::douyin::types::CheckCookieResult::Valid(profile) => profile,
        other => bail!(
            "App Cookie 尚未形成可用 Web 会话：{}",
            other.error_message().unwrap_or("本地上下文未确认")
        ),
    };
    if prebound_guard.is_none() {
        client
            .refresh_guard_ticket()
            .await
            .context("官方 Guard 票据获取失败")?;
    } else if record.dtrait_pk1_pem.is_none() {
        let _ = client.acquire_dtrait_config().await;
    }
    client
        .acquire_im_identity(Some(&record.uid))
        .await
        .context("官方 Web IM 身份材料获取失败")?;
    let context = client
        .web_context_snapshot()
        .context("Web 引导完成后上下文丢失")?;
    let cookie = client.get_current_cookie();
    Ok((cookie, context, profile))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_session_for_test() -> LoginSession {
        LoginSession {
            id: "session-id".to_string(),
            account_id: "account-id".to_string(),
            alias: "alias".to_string(),
            qrcode: "data:image/png;base64,AA==".to_string(),
            expires_at: Utc::now().timestamp() + LOGIN_SESSION_TTL_SECS,
            token: "token".to_string(),
            device: NativeDevice::derive("account-id"),
            jar: Arc::new(Jar::default()),
            client: Client::builder().build().unwrap(),
            verification: Arc::new(Mutex::new(None)),
            scan_profile: Arc::new(Mutex::new(None)),
            seen_scan: Arc::new(AtomicBool::new(false)),
            busy_polls: Arc::new(AtomicU32::new(0)),
        }
    }

    #[test]
    fn native_device_is_stable_and_account_scoped() {
        let first = NativeDevice::derive("acc-a");
        let second = NativeDevice::derive("acc-a");
        let other = NativeDevice::derive("acc-b");
        assert_eq!(first.device_id, second.device_id);
        assert_ne!(first.device_id, other.device_id);
        first.validate().unwrap();
    }

    #[test]
    fn d_ticket_encoding_is_bytewise_xor() {
        assert_eq!(encode_d_ticket("A"), "44");
        assert_eq!(encode_d_ticket("abc"), "646766");
    }

    #[test]
    fn token_encrypted_round_trip() {
        let token = "X-Tt-Token-test-1234567890";
        let encoded = encode_token_encrypted(token);
        assert_eq!(decode_token_encrypted(&encoded), token);
    }

    #[test]
    fn qr_status_numeric_values_match_the_web_sdk() {
        assert_eq!(normalize_qr_status("1"), "new");
        assert_eq!(normalize_qr_status("2"), "scanned");
        assert_eq!(normalize_qr_status("3"), "confirmed");
        assert_eq!(normalize_qr_status("4"), "refresh");
        assert_eq!(normalize_qr_status("5"), "expired");
    }

    #[test]
    fn scan_user_info_avatar_is_kept_and_non_https_is_rejected() {
        let object = serde_json::json!({
            "data": {
                "status": "2",
                "scan_user_info": {
                    "screen_name": "用户甲",
                    "avatar_url": "https://p3.douyinpic.com/avatar.jpeg"
                }
            }
        });
        let profile = scan_profile_from_response(&object).expect("scan profile");
        assert_eq!(profile.name.as_deref(), Some("用户甲"));
        assert_eq!(
            profile.avatar_url.as_deref(),
            Some("https://p3.douyinpic.com/avatar.jpeg")
        );

        let wrapped = serde_json::json!({
            "data": {
                "scan_user_info": "{\"nickname\":\"nick\",\"avatar_thumb\":{\"url_list\":[\"https://p3.douyinpic.com/a.webp\"]}}"
            }
        });
        let profile = scan_profile_from_response(&wrapped).expect("wrapped scan profile");
        assert_eq!(profile.name.as_deref(), Some("nick"));
        assert_eq!(
            profile.avatar_url.as_deref(),
            Some("https://p3.douyinpic.com/a.webp")
        );

        let rejected = serde_json::json!({
            "data": {
                "scan_user_info": {
                    "screen_name": "x",
                    "avatar_url": "http://evil.example/a.jpg"
                }
            }
        });
        let profile = scan_profile_from_response(&rejected).expect("name without avatar");
        assert_eq!(profile.name.as_deref(), Some("x"));
        assert!(profile.avatar_url.is_none());
    }

    #[test]
    fn fallback_verification_uses_scanned_avatar() {
        let session = login_session_for_test();
        session.merge_scan_profile(ScanProfile {
            name: Some("用户甲".to_string()),
            avatar_url: Some("https://p3.douyinpic.com/avatar.jpeg".to_string()),
        });
        let verification = fallback_verification(&session, &serde_json::json!({ "data": {} }));
        let view = serde_json::to_value(verification.challenge().view()).unwrap();
        assert_eq!(view["kind"], "two_step");
        assert_eq!(view["profile_name"], "用户甲");
        assert_eq!(view["avatar_url"], "https://p3.douyinpic.com/avatar.jpeg");
        assert_eq!(view["ways"].as_array().unwrap().len(), 4);
        assert!(!view.to_string().contains("http://"));
    }

    #[test]
    fn qr_status_takes_precedence_over_data_error() {
        let root = serde_json::json!({
            "error_code": 0,
            "data": { "status": 3, "error_code": 2156, "message": "error" }
        });
        assert_eq!(qr_response_status(&root), "3");
        assert_eq!(transient_status_error(&root), None);
    }

    #[test]
    fn qr_status_2156_is_retryable_only_with_a_real_challenge() {
        let risk_error = serde_json::json!({
            "error_code": 0,
            "data": {
                "error_code": 2156,
                "message": "error",
                "desc_url": "https://www.douyin.com/passport/verify/?ticket=test"
            }
        });
        assert_eq!(transient_status_error(&risk_error), Some((2156, "loading")));
        assert!(qr_error_message(&risk_error).contains("2156"));
        assert_eq!(
            challenge_url(&challenge_from_response(&risk_error).unwrap()).as_deref(),
            Some("https://www.douyin.com/passport/verify/?ticket=test")
        );
        assert!(
            challenge_from_response(&serde_json::json!({
                "error_code": 0,
                "data": { "error_code": 2156, "message": "error" }
            }))
            .is_none()
        );

        let rate_limit = serde_json::json!({
            "error_code": 0,
            "data": { "error_code": 7, "message": "访问太频繁" }
        });
        assert_eq!(transient_status_error(&rate_limit), Some((7, "loading")));
        assert_eq!(
            transient_status_error(&serde_json::json!({
                "error_code": 0,
                "data": { "error_code": 2156, "message": "error" }
            })),
            Some((2156, "loading"))
        );
        assert_eq!(
            transient_status_error(&serde_json::json!({
                "error_code": 1001,
                "data": { "error_code": 0 }
            })),
            None
        );
    }

    #[test]
    fn login_challenge_only_accepts_https_official_domains() {
        for candidate in [
            "http://www.douyin.com/passport/verify/",
            "https://douyin.com.evil.example/passport/verify/",
            "https://evil.example/?next=https://www.douyin.com/",
            "javascript:alert(1)",
            "aweme://webview/?url=https%3A%2F%2Fwww.douyin.com%2F",
        ] {
            let root = serde_json::json!({
                "data": { "desc_url": candidate }
            });
            assert!(challenge_from_response(&root).is_none(), "{candidate}");
        }

        for (candidate, expected) in [
            (
                "https://www.douyin.com/passport/verify/?ticket=test",
                "https://www.douyin.com/passport/verify/?ticket=test",
            ),
            (
                "https://aweme.snssdk.com/passport/verify/",
                "https://aweme.snssdk.com/passport/verify/",
            ),
            (
                "https://verify.iesdouyin.com/passport/verify/",
                "https://verify.iesdouyin.com/passport/verify/",
            ),
        ] {
            let root = serde_json::json!({
                "data": { "captcha": candidate }
            });
            assert_eq!(
                challenge_url(&challenge_from_response(&root).unwrap()).as_deref(),
                Some(expected)
            );
        }
    }

    #[test]
    fn challenge_carries_decision_config_without_exposing_tickets() {
        let root = serde_json::json!({
            "data": {
                "captcha": "https://aweme.snssdk.com/passport/authentication/index/?ticket=test",
                "verify_center_decision_conf": "config-value"
            }
        });
        let challenge = challenge_from_response(&root).unwrap();
        match challenge {
            LoginChallenge::Web {
                url,
                decision_config,
            } => {
                assert!(url.contains("/passport/authentication/index/"));
                assert_eq!(decision_config.as_deref(), Some("config-value"));
            }
            LoginChallenge::TwoStep { .. } => panic!("expected web challenge"),
        }
    }

    #[test]
    fn two_step_challenge_keeps_tickets_internal_and_masks_mobile() {
        let root = serde_json::json!({
            "data": {
                "verify_ticket": "verify-ticket-secret",
                "user_name": "测试用户",
                "profile_key": "profile-key-secret",
                "sms_code_key": "sms-code-key-secret",
                "verify_ways": [
                    {
                        "verify_way": "face_verify",
                        "auth_ticket": "face-auth-ticket-secret"
                    },
                    {
                        "verify_way": "mobile_sms_verify",
                        "mobile": "13812341234"
                    },
                    {
                        "verify_way": "pwd_verify"
                    },
                    {
                        "verify_way": "mobile_up_sms_verify",
                        "mobile": "13812341234",
                        "sms_content": "up-sms-content",
                        "channel_mobile": "106900001234"
                    }
                ]
            }
        });
        let verification = LoginVerification::from_response(&root).unwrap();
        assert_eq!(verification.ticket(), Some("verify-ticket-secret"));
        assert_eq!(
            verification.sms_code_key.as_deref(),
            Some("sms-code-key-secret")
        );
        assert_eq!(
            verification.auth_ticket.as_deref(),
            Some("face-auth-ticket-secret")
        );
        let challenge = verification.challenge();
        let view = challenge.view();
        let serialized = serde_json::to_string(&view).unwrap();
        for secret in [
            "verify-ticket-secret",
            "profile-key-secret",
            "sms-code-key-secret",
            "face-auth-ticket-secret",
            "up-sms-content",
            "13812341234",
        ] {
            assert!(
                !serialized.contains(secret),
                "{secret} leaked: {serialized}"
            );
        }
        assert!(serialized.contains("138****1234"));
        assert!(serialized.contains("测试用户"));
        let LoginChallenge::TwoStep { ways, .. } = challenge else {
            panic!("expected two-step challenge");
        };
        assert_eq!(ways.len(), 4);
        assert!(
            ways.iter()
                .any(|way| way.kind == "face_verify" && !way.supported)
        );
        assert!(
            ways.iter()
                .any(|way| way.kind == "mobile_sms_verify" && way.supported)
        );
        assert!(
            ways.iter()
                .any(|way| way.kind == "pwd_verify" && way.supported)
        );
        assert!(
            ways.iter()
                .any(|way| way.kind == "mobile_up_sms_verify" && way.supported)
        );
        let up_sms = verification
            .ways
            .iter()
            .find(|way| way.public.kind == "mobile_up_sms_verify")
            .unwrap();
        assert_eq!(up_sms.sms_content.as_deref(), Some("up-sms-content"));
        assert_eq!(up_sms.channel_mobile.as_deref(), Some("106900001234"));
        assert_eq!(
            verification
                .up_sms_delivery()
                .and_then(|delivery| delivery.sms_content)
                .as_deref(),
            Some("up-sms-content")
        );

        let original_qr_expiry = Utc::now().timestamp() - 1;
        let session = LoginSession {
            id: "session-id".to_string(),
            account_id: "account-id".to_string(),
            alias: "alias".to_string(),
            qrcode: "data:image/png;base64,AA==".to_string(),
            expires_at: original_qr_expiry,
            token: "token".to_string(),
            device: NativeDevice::derive("account-id"),
            jar: Arc::new(Jar::default()),
            client: Client::builder().build().unwrap(),
            verification: Arc::new(Mutex::new(Some(verification))),
            scan_profile: Arc::new(Mutex::new(None)),
            seen_scan: Arc::new(AtomicBool::new(false)),
            busy_polls: Arc::new(AtomicU32::new(0)),
        };
        let now = Utc::now().timestamp();
        assert!(session.qr_expired(now));
        assert!(!session.is_expired(now));
        assert!(session.session_expires_at() > original_qr_expiry);
        assert!(!session.has_verification() || session.session_expires_at() > now);
    }

    #[test]
    fn numeric_pending_status_promotes_two_step_challenge() {
        let root = serde_json::json!({
            "error_code": 0,
            "data": {
                "status": 2,
                "verify_ticket": "verify-ticket-secret",
                "sms_code_key": "sms-code-key-secret",
                "verify_ways": [
                    { "verify_way": "mobile_sms_verify", "mobile": "13812341234" }
                ]
            }
        });
        assert_eq!(qr_response_status(&root), "2");
        let challenge = challenge_for_status("2", &root).expect("two-step challenge");
        let LoginChallenge::TwoStep { ways, .. } = challenge else {
            panic!("expected two-step challenge");
        };
        assert_eq!(ways.len(), 1);
        assert_eq!(ways[0].kind, "mobile_sms_verify");
    }

    #[test]
    fn direct_verifying_status_keeps_two_step_challenge() {
        let root = serde_json::json!({
            "error_code": 0,
            "data": {
                "status": "verifying",
                "verify_ticket": "verify-ticket-secret",
                "verify_ways": [
                    { "verify_way": "mobile_sms_verify", "mobile": "13812341234" }
                ]
            }
        });
        let challenge = challenge_for_status("verifying", &root).expect("two-step challenge");
        let LoginChallenge::TwoStep {
            ways, ticket_ready, ..
        } = challenge
        else {
            panic!("expected two-step challenge");
        };
        assert!(ticket_ready);
        assert_eq!(ways.len(), 1);
        assert!(ways[0].supported);
    }

    #[test]
    fn verification_ways_survive_without_ticket_and_are_not_submittable() {
        let root = serde_json::json!({
            "status": 2,
            "data": {
                "verify_ways": [
                    { "verify_way": "mobile_sms_verify", "mobile": "13812341234" },
                    { "verify_way": "identity_verify", "mobile": "13812341234" }
                ]
            }
        });
        let challenge = challenge_for_status("2", &root).expect("verification ways");
        let view = serde_json::to_value(challenge.view()).unwrap();
        assert_eq!(view["ticket_ready"], false);
        assert_eq!(view["ways"].as_array().unwrap().len(), 2);
        assert_eq!(view["ways"][0]["kind"], "mobile_sms_verify");
        assert_eq!(view["ways"][0]["supported"], false);
        assert_eq!(view["ways"][1]["kind"], "identity_verify");
        assert_eq!(view["ways"][1]["supported"], false);
        let serialized = view.to_string();
        assert!(!serialized.contains("13812341234"));
        assert!(!serialized.contains("verify-ticket-secret"));
    }

    #[test]
    fn verification_accepts_json_string_auth_ways_data() {
        let root = serde_json::json!({
            "status": "verifying",
            "data": {
                "verify_ticket": "verify-ticket-secret",
                "auth_ways_data": "[{\"verify_way\":\"pwd_verify\"},{\"verify_way\":\"face_verify\"}]"
            }
        });
        let challenge = challenge_for_status("verifying", &root).expect("two-step challenge");
        let LoginChallenge::TwoStep {
            ways, ticket_ready, ..
        } = challenge
        else {
            panic!("expected two-step challenge");
        };
        assert!(ticket_ready);
        assert_eq!(ways.len(), 2);
        assert!(ways[0].supported);
        assert_eq!(ways[1].kind, "face_verify");
        assert!(!ways[1].supported);
    }

    #[test]
    fn verification_accepts_nested_and_string_wrapped_payloads() {
        let nested = serde_json::json!({
            "data": {
                "data": {
                    "verify_ticket": "verify-ticket-secret",
                    "verify_ways": [
                        { "verify_way": "identity_verify" }
                    ]
                }
            }
        });
        let string_wrapped = serde_json::json!({
            "data": "{\"result\":{\"verify_ticket\":\"verify-ticket-secret\",\"verify_ways\":[{\"verify_way\":\"mobile_up_sms_verify\"}]}}"
        });
        for root in [nested, string_wrapped] {
            let verification =
                LoginVerification::from_response(&root).expect("verification payload");
            assert_eq!(verification.ticket(), Some("verify-ticket-secret"));
            assert_eq!(verification.ways.len(), 1);
        }
    }

    #[test]
    fn verification_accepts_client_field_names_and_nested_extra_payloads() {
        let first_way_level = serde_json::json!({
            "error_code": 2046,
            "data": {
                "verify_ticket": "verify-ticket-secret",
                "verify_scene_desc": "为保障账号安全，请先完成身份验证",
                "verify_ways": [
                    {
                        "verify_way": "face_verify",
                        "auth_ticket": "face-auth-ticket-secret",
                        "flow": "face-flow"
                    },
                    {
                        "verify_way": "mobile_sms_verify",
                        "mobile": "13812341234"
                    },
                    {
                        "verify_way": "pwd_verify"
                    },
                    {
                        "verify_way": "mobile_up_sms_verify",
                        "mobile": "13812341234"
                    }
                ]
            }
        });
        let extra = serde_json::json!({
            "data": {
                "extra": {
                    "verify_ticket": "verify-ticket-secret",
                    "verify_ways": [
                        {
                            "verify_way": "identity_verify",
                            "auth_ticket": "identity-auth-ticket-secret"
                        }
                    ]
                }
            }
        });
        for root in [first_way_level, extra] {
            let verification =
                LoginVerification::from_response(&root).expect("client verification payload");
            assert_eq!(verification.ticket(), Some("verify-ticket-secret"));
            assert!(!verification.ways.is_empty());
            assert!(verification.ways.iter().all(|way| {
                !way.public
                    .masked_mobile
                    .as_deref()
                    .is_some_and(|mobile| mobile.contains("13812341234"))
            }));
        }
    }

    #[test]
    fn stored_two_step_challenge_survives_scanned_polling() {
        let root = serde_json::json!({
            "error_code": 0,
            "data": {
                "status": 2,
                "verify_ticket": "verify-ticket-secret",
                "verify_ways": [
                    { "verify_way": "mobile_sms_verify", "mobile": "13812341234" }
                ]
            }
        });
        let verification = LoginVerification::from_response(&root).expect("two-step verification");
        let session = LoginSession {
            id: "session-id".to_string(),
            account_id: "account-id".to_string(),
            alias: "alias".to_string(),
            qrcode: "data:image/png;base64,AA==".to_string(),
            expires_at: Utc::now().timestamp() + LOGIN_SESSION_TTL_SECS,
            token: "token".to_string(),
            device: NativeDevice::derive("account-id"),
            jar: Arc::new(Jar::default()),
            client: Client::builder().build().unwrap(),
            verification: Arc::new(Mutex::new(None)),
            scan_profile: Arc::new(Mutex::new(None)),
            seen_scan: Arc::new(AtomicBool::new(false)),
            busy_polls: Arc::new(AtomicU32::new(0)),
        };
        session.store_verification(verification);

        let status = normalize_qr_status("2");
        assert_eq!(status, "scanned");
        assert!(matches!(
            session
                .verification_snapshot()
                .as_ref()
                .map(LoginChallenge::from_verification),
            Some(LoginChallenge::TwoStep { .. })
        ));
        assert!(session.session_expires_at() > session.expires_at);
    }

    #[test]
    fn minimal_poll_without_challenge_keeps_saved_verification() {
        let session = login_session_for_test();
        session.store_verification(
            LoginVerification::from_response(&serde_json::json!({
                "status": "verifying",
                "data": {
                    "verify_ticket": "verify-ticket-secret",
                    "verify_ways": [
                        { "verify_way": "mobile_sms_verify" }
                    ]
                }
            }))
            .expect("saved verification"),
        );

        let empty_payload = serde_json::json!({
            "status": "verifying"
        });
        assert!(challenge_for_status("verifying", &empty_payload).is_none());
        assert!(session.has_verification());
        assert!(matches!(
            session
                .verification_snapshot()
                .as_ref()
                .map(LoginChallenge::from_verification),
            Some(LoginChallenge::TwoStep { .. })
        ));
    }

    #[test]
    fn pending_verification_never_falls_back_to_terminal_status() {
        let session = login_session_for_test();
        session.store_verification(
            LoginVerification::from_response(&serde_json::json!({
                "status": "verifying",
                "data": {
                    "verify_ticket": "verify-ticket-secret",
                    "verify_ways": [
                        { "verify_way": "mobile_sms_verify" }
                    ]
                }
            }))
            .expect("saved verification"),
        );

        let compact_confirmed = serde_json::json!({
            "status": "confirmed",
            "data": { "status": "confirmed" }
        });
        let normalized = normalize_qr_status(&qr_response_status(&compact_confirmed));
        assert_eq!(normalized, "confirmed");
        assert!(session.has_verification());
        assert!(session.session_expires_at() > Utc::now().timestamp());
    }

    #[test]
    fn verification_merge_keeps_ticket_ways_and_official_up_sms_content() {
        let first = LoginVerification::from_response(&serde_json::json!({
            "status": "verifying",
            "data": {
                "verify_ticket": "verify-ticket-secret",
                "sms_code_key": "sms-code-key-secret",
                "verify_ways": [
                    {
                        "verify_way": "mobile_sms_verify",
                        "mobile": "13812341234"
                    },
                    {
                        "verify_way": "mobile_up_sms_verify",
                        "mobile": "13812341234",
                        "sms_content": "up-sms-content",
                        "channel_mobile": "106900001234"
                    }
                ]
            }
        }))
        .expect("first verification");
        let later = LoginVerification::from_response(&serde_json::json!({
            "status": "verifying",
            "data": {
                "verify_ways": [
                    { "verify_way": "pwd_verify" }
                ]
            }
        }))
        .expect("later verification");

        let merged = first.merge(later);
        assert_eq!(merged.ticket(), Some("verify-ticket-secret"));
        assert_eq!(merged.sms_code_key.as_deref(), Some("sms-code-key-secret"));
        assert_eq!(merged.ways.len(), 3);
        assert!(merged.can_submit("mobile_sms_verify"));
        assert!(merged.can_begin("mobile_up_sms_verify"));
        assert_eq!(
            merged
                .up_sms_delivery()
                .and_then(|delivery| delivery.sms_content)
                .as_deref(),
            Some("up-sms-content")
        );
    }

    #[test]
    fn response_error_codes_cover_nested_and_string_wrapped_payloads() {
        let nested = serde_json::json!({
            "error_code": 0,
            "data": {
                "result": {
                    "extra": {
                        "error_code": 2046
                    }
                }
            }
        });
        assert_eq!(response_error_codes(&nested).1, 2046);

        let wrapped = serde_json::json!({
            "error_code": 0,
            "data": "{\"result\":{\"response\":{\"status_code\":\"2085\"}}}"
        });
        assert_eq!(response_error_codes(&wrapped).1, 2085);

        let zero = serde_json::json!({
            "error_code": 0,
            "data": { "error_code": 0, "result": { "extra": { "code": 0 } } }
        });
        assert_eq!(response_error_codes(&zero), (0, 0));
    }

    #[test]
    fn terminal_status_mapping_keeps_deferred_confirmation_pending() {
        let unauthenticated = LoginSession {
            jar: Arc::new(Jar::default()),
            ..login_session_for_test()
        };
        let root = serde_json::json!({
            "status": "confirmed",
            "data": {
                "status": "confirmed"
            }
        });
        let headers = header::HeaderMap::new();
        let failure = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(build_confirmed_login(
                &unauthenticated,
                &root,
                &headers,
                "confirmed".to_string(),
            ));
        assert!(failure.is_err());
        assert!(!has_strong_auth_cookie(&cookie_snapshot(
            &unauthenticated.jar
        )));
    }

    #[test]
    fn terminal_status_is_not_overridden_by_stale_challenge_fields() {
        let root = serde_json::json!({
            "error_code": 0,
            "data": {
                "status": 3,
                "verify_ticket": "verify-ticket-secret",
                "verify_ways": [
                    { "verify_way": "mobile_sms_verify", "mobile": "13812341234" }
                ]
            }
        });
        assert_eq!(qr_response_status(&root), "3");
        assert!(challenge_for_status("3", &root).is_none());
    }

    #[test]
    fn confirmed_status_with_explicit_two_step_error_requires_verification() {
        for error_code in [2020, 2022, 2025, 2046, 2085, 40102, 40103] {
            let root = serde_json::json!({
                "error_code": 0,
                "data": {
                    "status": 3,
                    "error_code": error_code,
                    "verify_ticket": "verify-ticket-secret",
                    "verify_ways": [
                        { "verify_way": "mobile_sms_verify", "mobile": "13812341234" },
                        { "verify_way": "pwd_verify" }
                    ]
                }
            });
            let challenge = challenge_for_status("3", &root)
                .unwrap_or_else(|| panic!("error_code={error_code} should require verification"));
            let LoginChallenge::TwoStep {
                ways, ticket_ready, ..
            } = challenge
            else {
                panic!("expected two-step challenge for error_code={error_code}");
            };
            assert!(ticket_ready);
            assert_eq!(ways.len(), 2);
            assert!(ways.iter().all(|way| way.supported));
        }
    }

    #[test]
    fn two_step_error_without_official_ways_stays_terminal() {
        let root = serde_json::json!({
            "error_code": 0,
            "data": {
                "status": 3,
                "error_code": 2046,
                "verify_ticket": "verify-ticket-secret"
            }
        });
        assert!(challenge_for_status("3", &root).is_none());
    }

    #[test]
    fn up_sms_can_begin_with_auth_ticket_but_requires_verify_ticket_to_submit() {
        let root = serde_json::json!({
            "error_code": 2046,
            "data": {
                "verify_ways": [{
                    "verify_way": "mobile_up_sms_verify",
                    "auth_ticket": "auth-ticket-secret"
                }]
            }
        });
        let verification = LoginVerification::from_response(&root).unwrap();
        assert!(verification.can_begin("mobile_up_sms_verify"));
        assert!(!verification.can_submit("mobile_up_sms_verify"));
        let LoginChallenge::TwoStep {
            ways, ticket_ready, ..
        } = verification.challenge()
        else {
            panic!("expected two-step challenge");
        };
        assert!(ticket_ready);
        assert!(ways[0].supported);
    }

    #[test]
    fn qr_services_match_the_app_contract() {
        assert_eq!(QR_GET_SERVICE, "https://aweme.snssdk.com");
        assert_eq!(QR_CHECK_SERVICE, "https://aweme.snssdk.com");
    }

    #[test]
    fn login_expiry_preserves_longer_official_deadline() {
        let now = 1_800_000_000;
        assert_eq!(resolve_login_expiry(Some(now + 600), now), now + 600);
        assert_eq!(
            resolve_login_expiry(Some((now + 600) * 1000), now),
            now + 600
        );
        assert_eq!(
            resolve_login_expiry(Some(now - 1), now),
            now + LOGIN_SESSION_TTL_SECS
        );
        assert_eq!(
            resolve_login_expiry(None, now),
            now + LOGIN_SESSION_TTL_SECS
        );
    }

    #[test]
    fn phone_native_login_forms_use_mix_mode_and_plus86_mobile() {
        fn assert_send<T: Send>(_: T) {}
        assert_send(start_phone_login("acc", "alias", "13812345678"));
        let (digits, full) = normalize_cn_mobile("13812345678").unwrap();
        assert_eq!(digits, "13812345678");
        assert_eq!(full, "+8613812345678");
        let (digits2, full2) = normalize_cn_mobile("+86 138-1234-5678").unwrap();
        assert_eq!(digits2, "13812345678");
        assert_eq!(full2, "+8613812345678");
        assert!(normalize_cn_mobile("12345").is_err());
        assert_eq!(encode_d_ticket("+86 13812345678"), "2e3d332534363d343736313033323d");
        assert_eq!(encode_d_ticket("24"), "3731");
    }

    #[test]
    fn login_form_matches_official_app_flags() {
        let form = common_form(&NativeDevice::derive("acc-form"), None);
        for (key, value) in [
            ("use_new_token_expire_rule", "true"),
            ("passport_support_flow", "real_name_check"),
            ("multi_login", "1"),
            ("account_app_language", "zh"),
            ("auth_sdk_version", "4.4.0"),
            ("verify_sdk_version", "3.7.5"),
            ("ttnet_sdk_version", "4.2.223.13"),
            ("device_brand", DEVICE_BRAND),
            ("device_type", DEVICE_TYPE),
            ("os_version", DEVICE_OS_VERSION),
            ("resolution", DEVICE_RESOLUTION),
            ("version_code", APP_VERSION_CODE),
            ("version_name", APP_VERSION_NAME),
            ("channel", APP_CHANNEL),
            ("update_version_code", APP_UPDATE_VERSION_CODE),
            ("manifest_version_code", APP_PACKAGE_VERSION_CODE),
            ("package", "com.ss.android.ugc.aweme"),
            ("is_android_pad", IS_ANDROID_PAD),
        ] {
            assert!(
                form.iter()
                    .any(|(name, actual)| name == key && actual == value)
            );
        }
    }

    #[test]
    fn qr_forms_match_the_phone_app_contract() {
        let device = NativeDevice::derive("acc-qr-form");
        let get_form = qr_get_form(&device);
        assert!(
            get_form
                .iter()
                .any(|(name, value)| name == "service" && value == QR_GET_SERVICE)
        );
        assert!(
            get_form
                .iter()
                .any(|(name, value)| name == "source" && value == QR_SOURCE)
        );
        // 108 实测：source 为空会让 get_qrcode 返回 de=11/4044，登录入口直接消失。
        assert!(!QR_SOURCE.is_empty(), "source 为空会被 Passport 拒绝");
        // App 合同：body 只放协议字段，设备身份由 TTNet 层作为 query 透传。
        let query = device_query(&device);
        for required in [
            ("device_id", device.device_id.as_str()),
            ("iid", device.install_id.as_str()),
            ("channel", APP_CHANNEL),
            ("version_code", APP_VERSION_CODE),
        ] {
            assert!(
                query
                    .iter()
                    .any(|(name, value)| name == required.0 && value == required.1),
                "设备身份 query 缺少 {}",
                required.0
            );
            assert!(
                !get_form.iter().any(|(name, _)| name == required.0),
                "get_qrcode body 不应再携带设备字段 {}",
                required.0
            );
        }
        // UA 里放的是机型的展示名，公共参数里的 device_type 是 Build.MODEL 型号码。
        assert!(device.user_agent.contains(DEVICE_DISPLAY_MODEL));
        assert!(!DEVICE_TYPE.is_empty());

        let token = "qr-token-for-contract-test";
        let check_form = qr_check_form(&device, token);
        for required in [
            ("service", QR_CHECK_SERVICE),
            ("token", token),
            ("scene", "0"),
            ("user_api_need_combine", "1"),
        ] {
            assert!(
                check_form
                    .iter()
                    .any(|(name, value)| name == required.0 && value == required.1),
                "check_qrconnect 缺少 {}",
                required.0
            );
        }
        let bare = serde_json::json!({
            "message": "error",
            "data": { "error_code": 2156, "description": "系统繁忙", "captcha": "", "desc_url": "" }
        });
        assert!(bare_qr_busy(&bare));
        let challenged = serde_json::json!({
            "message": "error",
            "data": {
                "error_code": 2156,
                "desc_url": "https://www.douyin.com/passport/verify/?ticket=test"
            }
        });
        assert!(!bare_qr_busy(&challenged));
        assert_eq!(
            check_form
                .iter()
                .filter(|(name, _)| name == "scene")
                .count(),
            1
        );
    }

    #[test]
    fn qr_login_initialization_headers_match_ticket_guard_contract() {
        let key = crate::douyin::pcim_guard::GuardKey::generate();
        let headers = key.android_initialization_headers().unwrap();
        assert_eq!(headers["bd-ticket-guard-version"], "3");
        assert_eq!(headers["bd-ticket-guard-iteration-version"], "2");
        assert_eq!(headers["bd-ticket-guard-tee-status"], "0");
        assert_eq!(
            headers["bd-ticket-guard-display-os-version"],
            "UP1A.231005.007"
        );
        assert_eq!(
            headers["bd-ticket-guard-ree-public-key"],
            key.public_key_base64()
        );
        assert!(!headers.contains_key("bd-ticket-guard-web-version"));
        assert!(!headers.contains_key("bd-ticket-guard-web-sign-type"));
        assert!(!headers.contains_key("bd-ticket-guard-client-data"));
    }

    #[test]
    fn login_requires_a_strong_auth_cookie() {
        assert!(!has_strong_auth_cookie(""));
        assert!(!has_strong_auth_cookie("reg-store-region=cn; odin_tt="));
        assert!(!has_strong_auth_cookie("sessionid=; sid_tt="));
        for cookie in [
            "sessionid=session-value",
            "sessionid_ss=session-value",
            "sid_guard=session-value",
            "sid_tt=session-value",
            "reg-store-region=cn; sid_tt=session-value",
        ] {
            assert!(has_strong_auth_cookie(cookie), "{cookie}");
        }
    }

    #[test]
    fn passport_csrf_prefers_primary_cookie_and_falls_back() {
        let url = reqwest::Url::parse("https://aweme.snssdk.com/").unwrap();
        let jar = Jar::default();
        let cookies = [header::HeaderValue::from_static(
            "passport_csrf_token_default=fallback; Path=/; Secure",
        )];
        let mut cookies = cookies.iter();
        CookieStore::set_cookies(&jar, &mut cookies, &url);
        assert_eq!(
            passport_csrf_token(&jar).as_deref(),
            Some("fallback"),
            "应回退到 passport_csrf_token_default"
        );

        let cookies = [header::HeaderValue::from_static(
            "passport_csrf_token=primary; Path=/; Secure",
        )];
        let mut cookies = cookies.iter();
        CookieStore::set_cookies(&jar, &mut cookies, &url);
        assert_eq!(
            passport_csrf_token(&jar).as_deref(),
            Some("primary"),
            "应优先使用 passport_csrf_token"
        );
    }

    #[test]
    fn login_redirects_are_limited_to_official_hosts() {
        for url in [
            "https://www.douyin.com/",
            "https://sso.douyin.com/passport/login/",
            "https://aweme.snssdk.com/passport/mobile/check_qrconnect/",
            "https://www.iesdouyin.com/",
        ] {
            assert!(is_official_login_url(&reqwest::Url::parse(url).unwrap()));
        }
        for url in [
            "http://www.douyin.com/",
            "https://douyin.com.example.org/",
            "https://example.org/?next=https://www.douyin.com/",
        ] {
            assert!(!is_official_login_url(&reqwest::Url::parse(url).unwrap()));
        }
    }

    #[test]
    fn qr_status_other_errors_still_fail() {
        let root = serde_json::json!({
            "error_code": 0,
            "message": "error",
            "data": { "error_code": 1001, "message": "error" }
        });
        let error = ensure_success(&root, "二维码状态").unwrap_err();
        assert!(error.to_string().contains("data_error=1001"));
    }

    #[test]
    fn record_debug_never_prints_secrets() {
        let record = NativeSessionRecord {
            device: NativeDevice::derive("acc-debug"),
            cookie: "sessionid=very-secret-cookie".to_string(),
            uid: "123".to_string(),
            sec_uid: "sec-secret".to_string(),
            nickname: "nick".to_string(),
            avatar_url: String::new(),
            mobile: "13800000000".to_string(),
            session_key: Some("session-key-secret".to_string()),
            d_ticket: Some("d-ticket-secret".to_string()),
            x_tt_token: Some("token-secret".to_string()),
            token_encrypted: None,
            ts_sign: None,
            attest_ts_sign: None,
            mfa_token: None,
            guard_key_hex: None,
            guard_server_data: None,
            dtrait_pk1_pem: None,
            dtrait_version: None,
            logged_in_at: 1,
            last_verified_at: None,
            last_beat_at: None,
        };
        let debug = format!("{record:?}");
        for secret in [
            "very-secret-cookie",
            "sec-secret",
            "session-key-secret",
            "d-ticket-secret",
            "token-secret",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn device_register_rejects_local_or_empty_ids() {
        assert!(!accepted_device_id(""));
        assert!(!accepted_device_id("0"));
        assert!(!accepted_device_id("0000000000"));
        assert!(!accepted_device_id("123456789"));
        assert!(!accepted_device_id("12345678901a"));
        assert!(accepted_device_id("7123456789012345"));
    }

    #[test]
    fn device_register_request_does_not_send_a_fake_device_id() {
        let device = NativeDevice::derive("acc-register");
        let query = device_register_query(&device, 1_700_000_000_000);
        assert!(
            query
                .iter()
                .all(|(name, _)| { !matches!(name.as_str(), "device_id" | "iid" | "install_id") })
        );
        assert!(
            query
                .iter()
                .any(|(name, value)| name == "openudid" && value == &device.openudid)
        );
        let body = device_register_body(&device, 1_700_000_000_000);
        assert_eq!(body["magic_tag"], "ss_app_log");
        assert_eq!(body["_gen_time"], 1_700_000_000_000_i64);
        assert_eq!(body["header"]["display_name"], DEVICE_DISPLAY_NAME);
        assert_eq!(body["header"]["version_code"], APP_VERSION_CODE_INT);
        assert_eq!(
            body["header"]["manifest_version_code"],
            APP_PACKAGE_VERSION_CODE_INT
        );
        assert_eq!(
            body["header"]["update_version_code"],
            APP_UPDATE_VERSION_CODE_INT
        );
        assert_eq!(body["header"]["channel"], APP_CHANNEL);
        assert_eq!(device.version_code, APP_VERSION_CODE);
        assert_eq!(PASSPORT_SDK_VERSION, "60760");
        assert_eq!(body["header"]["device_model"], DEVICE_TYPE);
        assert_eq!(body["header"]["model_display_name"], DEVICE_DISPLAY_MODEL);
        assert_eq!(body["header"]["device_category"], "phone");
        assert_eq!(body["header"]["device_manufacturer"], DEVICE_MANUFACTURER);
        assert_eq!(body["header"]["is_android_pad"], 0);
        assert_eq!(body["header"]["openudid"], device.openudid);
        // 官方未登记值是 0，不能带本地编造的非零设备号。
        assert_eq!(body["header"]["device_id"], 0);
        assert_eq!(body["header"]["install_id"], 0);
        assert!(
            query
                .iter()
                .any(|(name, value)| name == "tt_data" && value == "a")
        );
        let mac = body["header"]["mc"].as_str().expect("mc");
        assert_eq!(mac, stable_mac(&device.openudid));
        assert!(matches!(mac.as_bytes()[1], b'2' | b'6' | b'A' | b'E'));
        let plain = serde_json::to_vec(&body).unwrap();
        let sealed = super::super::applog_wire::seal_register_body(&plain).unwrap();
        assert!(sealed.starts_with(&[0x74, 0x63, 0x05, 0x10, 0x00, 0x00]));
        assert!(serde_json::from_slice::<Value>(&sealed).is_err());
        assert_ne!(&sealed[38..], plain.as_slice());
    }

    #[tokio::test]
    async fn device_register_live_probe_is_opt_in() {
        if std::env::var("SPARKLIGHT_DEVICE_REGISTER_PROBE")
            .ok()
            .as_deref()
            != Some("1")
        {
            return;
        }
        unsafe {
            std::env::remove_var("SPARK_DATA_DIR");
        }
        let device = NativeDevice::derive("probe-register-once");
        let client = Client::builder()
            .user_agent(device.user_agent.clone())
            .timeout(Duration::from_secs(20))
            .retry(reqwest::retry::never())
            .build()
            .expect("client");
        let registered = register_login_device(&client, device)
            .await
            .expect("register");
        assert!(accepted_device_id(&registered.device_id));
        assert!(accepted_device_id(&registered.install_id));
        eprintln!(
            "register_ok did_len={} iid_len={}",
            registered.device_id.len(),
            registered.install_id.len()
        );
    }

    #[tokio::test]
    async fn qr_get_live_probe_is_opt_in() {
        if std::env::var("SPARKLIGHT_QR_GET_PROBE").ok().as_deref() != Some("1") {
            return;
        }
        unsafe {
            std::env::remove_var("SPARK_DATA_DIR");
            for key in [
                "http_proxy",
                "https_proxy",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "all_proxy",
            ] {
                std::env::remove_var(key);
            }
        }
        match start("probe-qr-once", "probe").await {
            Ok(session) => {
                assert!(session.qrcode.starts_with("data:image/"));
                eprintln!("qr_ok image_len={}", session.qrcode.len());
            }
            Err(err) => panic!("qr_get_failed {err}"),
        }
    }

    #[test]
    fn device_register_response_accepts_official_string_or_number_ids() {
        let nested = serde_json::json!({
            "message": "success",
            "data": {
                "device_id_str": "7123456789012345",
                "install_id": 7123456789012346_u64,
                "new_user": 1
            }
        });
        assert_eq!(
            registered_ids_from_response(&nested)
                .as_ref()
                .map(|(did, iid)| (did.as_str(), iid.as_str())),
            Some(("7123456789012345", "7123456789012346"))
        );
        let empty = serde_json::json!({
            "device_id": 0,
            "install_id": 0,
            "new_user": 0
        });
        assert!(registered_ids_from_response(&empty).is_none());
    }

    #[test]
    fn registered_device_cache_requires_the_current_profile() {
        let profile = current_device_profile();
        let current = RegisteredDevice {
            device_id: "7123456789012345".to_string(),
            install_id: "7123456789012346".to_string(),
            profile: profile.clone(),
            device_token: "AAAQdt".to_string(),
            ..Default::default()
        };
        assert!(registered_device_matches_profile(&current, &profile));

        let legacy = RegisteredDevice {
            device_id: current.device_id.clone(),
            install_id: current.install_id.clone(),
            profile: String::new(),
            device_token: current.device_token.clone(),
            ..Default::default()
        };
        assert!(
            !registered_device_matches_profile(&legacy, &profile),
            "缺少 profile 的旧缓存不能复用"
        );

        let tablet = RegisteredDevice {
            profile: "old-pixel-tablet-profile".to_string(),
            ..current
        };
        assert!(
            !registered_device_matches_profile(&tablet, &profile),
            "平板登记身份不能复用于手机声明"
        );
    }

    #[test]
    fn upgrade_prompt_4044_rejects_the_misleading_version_claim() {
        let root = serde_json::json!({
            "message": "error",
            "data": {
                "error_code": 4044,
                "description": "请将应用升级至最新版本后重试，升级后如仍操作失败，请联系客服处理。",
                "message": "error"
            }
        });
        let message = qr_error_message(&root);
        assert!(message.contains("4044"));
        // 108 实测 4044 由 Passport 请求合同缺陷（body 缺 is_from_ttaccountsdk）触发，
        // 与版本、设备型号、TicketGuard 证书无关，所以文案不得再声称“请升级应用”。
        assert!(message.contains("请求合同"));
        assert!(!message.contains("请将应用升级"));
        let error = ensure_success(&root, "抖音二维码").unwrap_err().to_string();
        assert!(error.contains("请求合同"));
        assert!(!error.contains("请将应用升级"));
    }

    #[test]
    fn web_passport_abogus_and_challenge_helpers_work_in_rquickjs() {
        let signed = sign_web_passport_url(
            "https://www.douyin.com/passport/web/send_code/?aid=6383",
            "is6Digits=1&mix_mode=1",
        )
        .unwrap();
        assert!(signed.contains("a_bogus="));
        let signed_get = sign_web_passport_request(
            "GET",
            "https://www.douyin.com/passport/web/validate_code/?aid=6383&code=1234",
            None,
        )
        .unwrap();
        assert!(signed_get.contains("a_bogus="));
        assert_ne!(signed, signed_get);
        let fp = generate_web_verify_fp("acc_test");
        assert!(fp.starts_with("verify_"));
        let central = web_dtrait_central_string();
        assert!(!central.is_empty() && central != "IAAAAAAA");
        let (p_in, e_in) = run_web_challenge_template("", 1700000000, "test_iv").unwrap();
        assert_eq!(p_in.len(), 64);
        assert_eq!(
            e_in.get("bit_protocol").and_then(Value::as_str),
            Some("false")
        );
    }

    #[tokio::test]
    async fn web_2046_second_verify_parses_decision_and_preserves_sms_code_key() {
        let session = PhoneLoginSession {
            id: "test_phone_id".to_string(),
            account_id: "acc_test".to_string(),
            alias: "测试账号".to_string(),
            expires_at: Utc::now().timestamp() + 600,
            mobile: "13800138000".to_string(),
            web_mobile: "+86 13800138000".to_string(),
            csrf_token: "csrf123".to_string(),
            verify_fp: generate_web_verify_fp("acc_test"),
            guard_key_hex: super::super::pcim_guard::GuardKey::generate().to_hex(),
            dtrait_bytes: Vec::new(),
            browser_info_enc: String::new(),
            sms_code_key: None,
            ticket: None,
            second_verify: Arc::new(Mutex::new(None)),
            device: NativeDevice::derive("acc_test"),
            jar: Arc::new(Jar::default()),
            client: Client::builder().build().unwrap(),
        };
        let decision_conf = serde_json::json!({
            "code": "20000",
            "subtype": "mobile_up_sms_verify",
            "verify_ticket": "vt_2046_abc",
            "sms_content": "DY1234",
            "channel_mobile": "106900001234",
            "replay_data": {
                "x-tt-passport-replay-params": "{\"pass\":1}"
            }
        })
        .to_string();
        let root = serde_json::json!({
            "message": "error",
            "data": {
                "error_code": 2046,
                "description": "当前设备存在安全风险，请完成身份验证",
                "sms_code_key": "sck_secret_123",
                "verify_center_decision_conf": decision_conf
            }
        });
        let state = build_web_second_verify_state(
            &session,
            &root,
            &header::HeaderMap::new(),
            "portrait-uuid.login",
            PendingWebLoginAction::Sms {
                code: "654321".to_string(),
            },
        )
        .await;
        assert_eq!(state.verify_ticket.as_deref(), Some("vt_2046_abc"));
        assert_eq!(state.sms_code_key.as_deref(), Some("sck_secret_123"));
        assert_eq!(state.replay_headers.len(), 1);
        assert!(
            state
                .ways
                .iter()
                .any(|w| w.public.kind == "mobile_up_sms_verify" && w.public.supported)
        );
    }

    #[tokio::test]
    async fn web_2046_uc_second_verify_extracts_common_params_and_prioritizes_qr_code() {
        let session = PhoneLoginSession {
            id: "test_phone_id".to_string(),
            account_id: "acc_test".to_string(),
            alias: "测试账号".to_string(),
            expires_at: Utc::now().timestamp() + 600,
            mobile: "13800138000".to_string(),
            web_mobile: "+86 13800138000".to_string(),
            csrf_token: "csrf123".to_string(),
            verify_fp: generate_web_verify_fp("acc_test"),
            guard_key_hex: super::super::pcim_guard::GuardKey::generate().to_hex(),
            dtrait_bytes: Vec::new(),
            browser_info_enc: String::new(),
            sms_code_key: None,
            ticket: None,
            second_verify: Arc::new(Mutex::new(None)),
            device: NativeDevice::derive("acc_test"),
            jar: Arc::new(Jar::default()),
            client: Client::builder().build().unwrap(),
        };
        let root = serde_json::json!({
            "message": "error",
            "data": {
                "error_code": 2046,
                "account_flow": "verify",
                "encrypt_uid": "enc_uid_test_123",
                "pack_verify_way": true,
                "passport_scene": "account_login",
                "sms_code_key": "sck_secret_456",
                "url": "https://auth.zijieapi.com/ucenter_web/app/second_verification_web/dist/index.umd.production.js?error_code=2046&std_verify_flow_id=flow-123.login&std_verify_scene=account_login&std_verify_template=ato_without_sms_upsms_pwd&std_verify_token=tok-456_lq&std_verify_type=MFA&std_verify_way=&verify_ways=face_verify%2Cqr_code_verify",
                "common_params": {
                    "std_verify_flow_id": "flow-123.login",
                    "std_verify_scene": "account_login",
                    "std_verify_template": "ato_without_sms_upsms_pwd",
                    "std_verify_token": "tok-456_lq",
                    "std_verify_type": "MFA",
                    "copywriting": "{}"
                },
                "biz_params": {
                    "sms_code_key": "sck_secret_456",
                    "sms_code_key_not_mix": 1,
                    "std_verify_flow_id": "flow-123.login",
                    "std_verify_token": "tok-456_lq",
                    "std_verify_way": ""
                },
                "event_params": {
                    "verify_scene": "account_login",
                    "verify_reason": "risk_device"
                },
                "verify_ways": [
                    {
                        "verify_way": "face_verify",
                        "auth_ticket": "face_ticket_789",
                        "cert_app_id": 6383,
                        "flow": "check_multi_panel",
                        "scene": "account_scan_face_verify"
                    },
                    {
                        "verify_way": "qr_code_verify"
                    }
                ]
            }
        });
        let state = build_web_second_verify_state(
            &session,
            &root,
            &header::HeaderMap::new(),
            "flow-123.login",
            PendingWebLoginAction::Sms {
                code: "654321".to_string(),
            },
        )
        .await;
        assert_eq!(state.encrypt_uid.as_deref(), Some("enc_uid_test_123"));
        assert_eq!(state.verify_scene.as_deref(), Some("account_login"));
        assert_eq!(state.verify_reason.as_deref(), Some("risk_device"));
        assert_eq!(state.ways.len(), 2);
        assert_eq!(state.ways[0].public.kind, "qr_code_verify");
        assert_eq!(state.ways[1].public.kind, "face_verify");
        assert_eq!(state.ways[1].auth_ticket.as_deref(), Some("face_ticket_789"));
        assert_eq!(state.ways[1].cert_app_id.as_deref(), Some("6383"));
        let common_pairs = state.common_form_pairs();
        assert!(common_pairs.iter().any(|(k, v)| k == "encrypt_uid" && v == "enc_uid_test_123"));
        assert!(common_pairs.iter().any(|(k, v)| k == "std_verify_token" && v == "tok-456_lq"));

        let qr_data_url = render_qr_svg_data_url(
            "aweme://aweme/cert/verify?scene=account_scan_face_verify&cert_app_id=6383&flow=check_multi_panel&ticket=face_ticket_789&ignore_result=true",
        )
        .expect("should render SVG QR code");
        assert!(qr_data_url.starts_with("data:image/svg+xml;base64,"));

        let mut identity = serde_json::json!({
            "user_id": 0,
            "user_id_str": "0",
            "sec_user_id": "MS4wLjABAAAA_test"
        })
        .as_object()
        .cloned()
        .unwrap();
        assert_eq!(first_positive_uid(&identity), None);
        let profile = serde_json::json!({
            "user_id": 55696816245u64,
            "user_id_str": "55696816245",
            "nickname": "测试昵称"
        })
        .as_object()
        .cloned()
        .unwrap();
        merge_identity_fields(&mut identity, Some(&profile));
        assert_eq!(first_positive_uid(&identity).as_deref(), Some("55696816245"));

        let gk1 = crate::douyin::pcim_guard::GuardKey::derive_for_account("acc-test-1");
        let gk2 = crate::douyin::pcim_guard::GuardKey::derive_for_account("acc-test-1");
        assert_eq!(gk1.to_hex(), gk2.to_hex());
    }
}
