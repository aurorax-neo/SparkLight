//! 原生 PCIM 初始化公钥发送；账号、目标、模板均来自调度快照并在提交前原子复查。
//! 不读取浏览器签名/私钥，不将 cmd610 ticket 误称为完整发送授权。
use super::*;
use crate::douyin::pcim_guard::GuardKey;

#[derive(Clone)]
pub(crate) enum GuardSendAuth {
    Signed { key: GuardKey, material: crate::douyin::pcim_guard::BoundGuardMaterial },
    Initial(GuardKey),
}
impl GuardSendAuth {
    pub(crate) fn key(&self) -> &GuardKey {
        match self {
            Self::Signed { key, .. } => key,
            Self::Initial(key) => key,
        }
    }
}

impl ConversationTicket {
    pub async fn pcim_initial_history_precheck(&self, client: &DouyinClient) -> Result<bool> {
        anyhow::ensure!(self.is_current(client), "PCIM_INIT_CONTEXT");
        client.check_i_sent_message_today(self.uid,&self.conversation_id,self.conversation_type,self.short_id).await
    }
    /// 调用方须在发送前持久化单次记录并执行身份/历史后检。
    pub fn build_pcim_initial_request(&self, client: &DouyinClient, key: &GuardKey, client_id: &str, text: &str) -> Result<reqwest::Request> {
        self.build_pcim_auth_request(client, &GuardSendAuth::Initial(GuardKey::from_slice(&key.to_bytes())?), client_id, text)
    }
    pub(crate) fn build_pcim_auth_request(&self, client: &DouyinClient, auth: &GuardSendAuth, client_id: &str, text: &str) -> Result<reqwest::Request> {
        anyhow::ensure!(!text.trim().is_empty() && text.len()<=4096, "PCIM_INIT_TEXT");
        anyhow::ensure!(self.is_current(client) && !client.sending_blocked(), "PCIM_INIT_CONTEXT");
        anyhow::ensure!(uuid::Uuid::parse_str(client_id).is_ok_and(|u|u.get_version_num()==4 && u.to_string()==client_id), "PCIM_INIT_UUID");
        let current_cookie = client.get_current_cookie();
        let mut send=Vec::new();
        encode_field_bytes(1,self.conversation_id.as_bytes(),&mut send);
        encode_field_varint(2,self.conversation_type as u64,&mut send);encode_field_varint(3,self.short_id,&mut send);
        #[derive(serde::Serialize)]
        struct Content<'a> { #[serde(rename="aweType")] awe_type:u16, #[serde(rename="type")] kind:u8, #[serde(rename="richTextInfos")] rich_text_infos:Vec<()>, text:&'a str }
        encode_field_bytes(4,&serde_json::to_vec(&Content{awe_type:700,kind:0,rich_text_infos:vec![],text})?,&mut send);
        let seed = client_id.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
        let base_sec: i64 = 1792137000 + ((seed >> 24) % 86400) as i64;
        let millis = base_sec * 1000 + (seed % 1000) as i64;
        let stime = format!("{millis}.{:04}", (seed >> 16) % 10000);
        for (k,v) in [("s:mentioned_users",""),("s:client_message_id",client_id),("s:stime",&stime)] { let mut item=Vec::new();encode_field_bytes(1,k.as_bytes(),&mut item);encode_field_bytes(2,v.as_bytes(),&mut item);encode_field_bytes(5,&item,&mut send); }
        encode_field_varint(6,7,&mut send);encode_field_bytes(7,self.ticket.as_bytes(),&mut send);encode_field_bytes(8,client_id.as_bytes(),&mut send);
        let mut body=Vec::new();encode_field_bytes(100,&send,&mut body);
        let envelope=initial_envelope(&self.context.envelope,&body)?;
        let verify_fp = client.extract_cookie_val("s_v_web_id").unwrap_or_else(|| "verify_mv69zog3_NcigV1kI_GBcB_4sG5_AwoJ_mOfsHf5wxNsb".into());
        let ms_token = client.extract_cookie_val("msToken").unwrap_or_else(|| derive_ms_token(client_id));
        let send_url = format!("https://imapi.douyin.com/v1/message/send?verifyFp={verify_fp}&fp={verify_fp}&msToken={ms_token}");
        let mut request=client.web_request(Method::POST,&send_url)?
            .header(header::CONTENT_TYPE,"application/x-protobuf").header(header::ACCEPT,"application/x-protobuf")
            .header("sec-ch-ua", "\"Brave\";v=\"155\", \"Chromium\";v=\"155\", \"Not(A:Brand\";v=\"24\"")
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"macOS\"")
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-site")
            .header(header::ACCEPT_LANGUAGE, "zh-CN,zh;q=0.8")
            .body(envelope).build()?;
        match auth {
            GuardSendAuth::Signed { key, material } => {
                let now = chrono::Utc::now().timestamp();
                let headers = key.sign_send(material, self.uid, &current_cookie, now, crate::douyin::pcim_guard::GuardMode::Ecdsa)?;
                for (name, value) in headers {
                    if let Some(n) = name { request.headers_mut().insert(n, value); }
                }
                let mut val = header::HeaderValue::from_str(&current_cookie)?;
                val.set_sensitive(true);
                request.headers_mut().insert(header::COOKIE, val);
            }
            GuardSendAuth::Initial(key) => {
                for (name, value) in key.initialization_headers()? {
                    if let Some(n) = name { request.headers_mut().insert(n, value); }
                }
                let cookie = strip_old_guard(&current_cookie);
                let declaration=format!("{cookie}; bd_ticket_guard_client_data={}; bd_ticket_guard_client_web_domain=2",key.initialization_cookie_value()?);
                let mut val = header::HeaderValue::from_str(&declaration)?;
                val.set_sensitive(true);
                request.headers_mut().insert(header::COOKIE, val);
            }
        }
        if let Ok(Some(cipher)) = client.web_context.lock().unwrap().as_ref().map_or(Ok(None), |c| c.get_dtrait_cipher()) {
            let mut protocol = crate::douyin::pcim_features::FeatureProtocol::new();
            protocol.add_bool("bool_1", true);
            protocol.add_hash("str_1", crate::douyin::pcim_features::murmur3("douyin_web"));
            let (central, _) = protocol.result();
            if let Ok(hdr) = cipher.central_header(&central, "/v1/message/send", &[], chrono::Utc::now().timestamp()) {
                request.headers_mut().insert("x-tt-session-dtrait", hdr);
            }
        }
        Ok(request)
    }
}
fn initial_envelope(context:&[u8],body:&[u8])->Result<Vec<u8>> {
    let mut envelope=Vec::new();
    encode_field_varint(1,100,&mut envelope);encode_field_varint(2,10001,&mut envelope);
    for (n,v) in [(3,"0.1.8"),(4,""),(7,"0d50935:feat/pc-im-group"),(11,"douyin_pc"),(21,"douyin_web"),(22,"web_sdk")] {encode_field_bytes(n,v.as_bytes(),&mut envelope);}
    for (n,v) in [(5,3),(6,0),(18,1)]{encode_field_varint(n,v,&mut envelope);}
    encode_field_bytes(8,body,&mut envelope);
    let mut found=std::collections::BTreeSet::new();
    let mut identity_fields = std::collections::BTreeMap::new();
    for (n,w,b) in parse_protobuf_fields(context) {
        if n!=15||w!=2{continue}
        let f=parse_protobuf_fields(&b);let name=std::str::from_utf8(unique_field(&f,1,2)?)?;
        if !["identity_security_token","identity_security_device_id","identity_security_aid","session_aid","user_agent"].contains(&name){continue}
        anyhow::ensure!(found.insert(name.to_owned()),"PCIM_INIT_DUPLICATE_IDENTITY");
        let value=unique_field(&f,2,2)?;
        identity_fields.insert(name.to_owned(), value.to_vec());
    }
    anyhow::ensure!(found.len()==5,"PCIM_INIT_MISSING_IDENTITY");
    let empty = Vec::new();
    let token_val = identity_fields.get("identity_security_token").unwrap_or(&empty);
    let device_val = identity_fields.get("identity_security_device_id").unwrap_or(&empty);
    let ua_val = identity_fields.get("user_agent").unwrap_or(&empty);
    let full_ext: Vec<(&str, &[u8])> = vec![
        ("identity_security_token", token_val),
        ("identity_security_device_id", device_val),
        ("identity_security_aid", b""),
        ("session_aid", b"6383"),
        ("session_did", b"0"),
        ("app_name", b"douyin_pc"),
        ("priority_region", b"cn"),
        ("user_agent", ua_val),
        ("cookie_enabled", b"true"),
        ("browser_language", b"zh-CN"),
        ("browser_platform", b"MacIntel"),
        ("browser_name", b"Mozilla"),
        ("browser_version", ua_val),
        ("browser_online", b"true"),
        ("screen_width", b"2560"),
        ("screen_height", b"1440"),
        ("referer", b"https://www.douyin.com/user/self"),
        ("timezone_name", b"Asia/Shanghai"),
        ("deviceId", b"0"),
        ("is-retry", b"0"),
    ];
    for (name, val) in full_ext {
        let mut h = Vec::new();
        encode_field_bytes(1, name.as_bytes(), &mut h);
        encode_field_bytes(2, val, &mut h);
        encode_field_bytes(15, &h, &mut envelope);
    }
    Ok(envelope)
}
fn derive_ms_token(client_id: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(client_id.as_bytes());
    hasher.update(b"ms_token_salt_pcim");
    let h1 = hasher.finalize_reset();
    hasher.update(&h1);
    hasher.update(b"second_pass_salt");
    let h2 = hasher.finalize_reset();
    hasher.update(&h2);
    hasher.update(b"third_pass_salt");
    let h3 = hasher.finalize();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([h1.as_slice(), h2.as_slice(), h3.as_slice()].concat());
    b64[..176.min(b64.len())].to_string()
}
/// 仅当命令、外层/内层状态、check_code、UUID、消息ID和账号全部明确匹配才接受。
pub fn parse_pcim_initial_ack(bytes:&[u8],client_id:&str)->Result<String> {
    parse_pcim_initial_ack_for(bytes,client_id,99191692311)
}
/// 研究 API 的兼容包装仍绑定研究身份；生产使用本动态解析器。
pub fn parse_pcim_initial_ack_for(bytes:&[u8],client_id:&str,uid:u64)->Result<String> {
    let f=parse_protobuf_fields(bytes);let int=|a:&[(u32,u8,Vec<u8>)],n|->Result<u64>{let b=unique_field(a,n,0)?;let (v,l)=read_varint(b,0).context("PCIM_ACK_INTEGER")?;anyhow::ensure!(l==b.len(),"PCIM_ACK_INTEGER");Ok(v)};
    anyhow::ensure!(uid>0 && int(&f,1)?==100&&int(&f,3)?==0&&int(&f,13)?==uid,"PCIM_ACK_REJECTED");
    let body=parse_protobuf_fields(unique_field(&f,6,2)?);let s=parse_protobuf_fields(unique_field(&body,100,2)?);
    anyhow::ensure!(int(&s,3)?==0&&int(&s,5)?==0&&unique_field(&s,4,2)?==client_id.as_bytes(),"PCIM_ACK_MISMATCH");
    let id=int(&s,1)?;anyhow::ensure!(id>0,"PCIM_ACK_ID");Ok(id.to_string())
}
fn safe_ack_summary(bytes: &[u8], client_id: &str, uid: u64) -> serde_json::Value {
    let fields=parse_protobuf_fields(bytes);
    let number=|f:&[(u32,u8,Vec<u8>)],n| unique_field(f,n,0).ok().and_then(|b|read_varint(b,0)).map(|v|v.0);
    let body=unique_field(&fields,6,2).ok().map(parse_protobuf_fields).unwrap_or_default();
    let inner=unique_field(&body,100,2).ok().map(parse_protobuf_fields).unwrap_or_default();
    serde_json::json!({"bytes":bytes.len(),"command":number(&fields,1),"outer_status":number(&fields,3),
        "sender_matches":number(&fields,13).map(|v|v==uid),"inner_status":number(&inner,3),
        "check_code":number(&inner,5),"uuid_matches":unique_field(&inner,4,2).ok().map(|b|b==client_id.as_bytes()),
        "positive_message_id":number(&inner,1).map(|v|v>0)})
}

#[cfg(test)]mod tests {
 use super::*;
 const ID:&str="84fd7313-e4c5-4dc5-8cf5-307417d2bbe2";
 fn ack()->Vec<u8>{let mut s=Vec::new();for(n,v)in[(1,7696916217378948657),(3,0),(5,0)]{encode_field_varint(n,v,&mut s)}encode_field_bytes(4,ID.as_bytes(),&mut s);let mut b=Vec::new();encode_field_bytes(100,&s,&mut b);let mut e=Vec::new();for(n,v)in[(1,100),(3,0),(13,99191692311)]{encode_field_varint(n,v,&mut e)}encode_field_bytes(6,&b,&mut e);e}
 #[test]fn strict_ack(){let a=ack();assert_eq!(parse_pcim_initial_ack(&a,ID).unwrap(),"7696916217378948657");assert!(parse_pcim_initial_ack(&a,"other").is_err());let mut dup=a.clone();encode_field_varint(3,0,&mut dup);assert!(parse_pcim_initial_ack(&dup,ID).is_err());for i in 0..a.len(){assert!(parse_pcim_initial_ack(&a[..i],ID).is_err())}}
 #[test]
 fn ack_summary_is_bounded_and_contains_no_response_text() {
     let mut a=ack();
     encode_field_bytes(99,b"secret-cookie-token-fixture",&mut a);
     let summary=safe_ack_summary(&a,ID,99191692311);
     assert_eq!(summary["command"],100);
     assert_eq!(summary["outer_status"],0);
     assert_eq!(summary["sender_matches"],true);
     assert_eq!(summary["uuid_matches"],true);
     assert_eq!(summary["positive_message_id"],true);
     let serialized=summary.to_string();
     assert!(!serialized.contains("secret") && !serialized.contains(ID));
     assert!(serialized.len()<256);
     encode_field_varint(3,7,&mut a);
     assert!(safe_ack_summary(&a,ID,99191692311)["outer_status"].is_null());
     assert_eq!(safe_ack_summary(&ack(),"other",777)["sender_matches"],false);
     assert_eq!(safe_ack_summary(&ack(),"other",777)["uuid_matches"],false);
     for end in 0..a.len() {assert!(safe_ack_summary(&a[..end],ID,99191692311).to_string().len()<256);}
 }
 #[test]fn envelope_uses_observed_branch_not_old_read_version(){let mut c=Vec::new();for(k,v)in[("identity_security_token","{\"token\":\"fixture\"}"),("identity_security_device_id","fixture-device"),("identity_security_aid","6383"),("session_aid","6383"),("user_agent","fixture-UA")]{let mut h=Vec::new();encode_field_bytes(1,k.as_bytes(),&mut h);encode_field_bytes(2,v.as_bytes(),&mut h);encode_field_bytes(15,&h,&mut c)}let e=initial_envelope(&c,b"fixture").unwrap();let f=parse_protobuf_fields(&e);assert_eq!(unique_field(&f,3,2).unwrap(),b"0.1.8");assert_eq!(read_varint(unique_field(&f,6,0).unwrap(),0).unwrap().0,0);let h=f.iter().filter(|(n,_,_)|*n==15).map(|(_,_,b)|parse_protobuf_fields(b)).find(|h|unique_field(h,1,2).unwrap()==b"identity_security_aid").unwrap();assert_eq!(unique_field(&h,2,2).unwrap(),b"");assert!(initial_envelope(b"",b"x").is_err());let duplicate=[c.clone(),c].concat();assert!(initial_envelope(&duplicate,b"x").is_err())}
}

#[cfg(test)] pub(crate) const ACCOUNT: &str = "acc_37094b76c50f4e0aa1da3848c3e12534";
#[cfg(test)] pub(crate) const TARGET: &str = "tgt_2e614530f19d4723a2820e7daaac5ee9";
#[cfg(test)] pub(crate) const CID: &str = "0:1:55696816245:99191692311";

fn target_binding(account: &crate::model::Account, target: &crate::model::SparkTarget, force: bool) -> Result<(u64,String)> {
    anyhow::ensure!(account.status=="ACTIVE" && (target.is_enabled || force) && target.account_id==account.id,"PCIM_INIT_TARGET_STATE");
    let uid=account.uid.as_deref().context("PCIM_INIT_UID")?.parse::<u64>()?;
    let cid=match target.conversation_type {
        1=>{
            let peer=target.target_uid.as_deref().context("PCIM_INIT_PEER")?.parse::<u64>()?;
            anyhow::ensure!(peer>0 && peer!=uid,"PCIM_INIT_PEER");
            let cid=format!("0:1:{}:{}",uid.min(peer),uid.max(peer));
            anyhow::ensure!(target.conversation_id.as_deref().is_none_or(|v|v==cid),"PCIM_INIT_CID");cid
        },
        2=>target.conversation_id.clone().unwrap_or_else(||target.target_sec_uid.clone()),
        _=>anyhow::bail!("PCIM_INIT_TYPE"),
    };
    validate_conversation(uid,&cid,target.conversation_type)?;
    anyhow::ensure!(!target.message_template.trim().is_empty() && target.message_template.len()<=4096,"PCIM_INIT_TEXT");
    Ok((uid,cid))
}
pub(crate) fn old_guard(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    name.contains("ticket_guard") || name.starts_with("_bd_ticket") || name.starts_with("__security")
}
pub(crate) fn strip_old_guard(cookie: &str) -> String {
    cookie.split(';').map(str::trim).filter(|part| !part.is_empty()
        && !old_guard(part.split('=').next().unwrap_or(""))).collect::<Vec<_>>().join("; ")
}
pub(crate) fn beijing_day() -> chrono::NaiveDate {
    chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive()
}

#[derive(Clone)]
pub(crate) struct InitialBinding {
    pool: sqlx::SqlitePool,
    encrypted_cookie: Vec<u8>,
    started: Arc<AtomicBool>,
    account_id: String,
    uid: u64,
    target_id: String,
    cid: String,
    kind: i32,
    peer: Option<String>,
    target_sec_uid: String,
    template: String,
    pub(crate) force: bool,
}
impl InitialBinding {
    fn new(pool:sqlx::SqlitePool, encrypted_cookie:Vec<u8>, account:&crate::model::Account, target:&crate::model::SparkTarget, force: bool)->Result<Self> {
        let (uid,cid)=target_binding(account,target,force)?;
        Ok(Self {pool,encrypted_cookie,started:Arc::new(AtomicBool::new(false)),account_id:account.id.clone(),uid,target_id:target.id.clone(),cid,kind:target.conversation_type,peer:target.target_uid.clone(),target_sec_uid:target.target_sec_uid.clone(),template:target.message_template.clone(),force})
    }
    async fn has_day_claim(&self, day: chrono::NaiveDate) -> Result<bool> {
        Ok(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM im_send_attempts WHERE account_id=?1 AND conversation_id=?2 AND beijing_day=?3")
            .bind(&self.account_id).bind(&self.cid).bind(day.to_string()).fetch_one(&self.pool).await? > 0)
    }
    // 单条 INSERT SELECT 在同一 SQLite 写操作中校验状态并占用当天；不覆盖任何旧行。
    async fn claim(&self, client_id: &str, day: chrono::NaiveDate) -> Result<()> {
        let sql = if self.force {
            "INSERT INTO im_send_attempts(account_id,conversation_id,beijing_day,client_message_id,state) SELECT ?1,?2,?3,?4,'UNKNOWN' FROM accounts a JOIN spark_targets t ON t.account_id=a.id WHERE a.id=?1 AND a.uid=?7 AND a.status='ACTIVE' AND a.encrypted_cookie=?5 AND t.id=?6 AND t.conversation_type=?8 AND t.target_uid IS ?9 AND t.target_sec_uid=?10 AND ((?8=1 AND (t.conversation_id IS NULL OR t.conversation_id=?2)) OR (?8=2 AND COALESCE(t.conversation_id,t.target_sec_uid)=?2)) AND t.message_template=?11 ON CONFLICT(account_id,conversation_id,beijing_day) DO UPDATE SET client_message_id=excluded.client_message_id, state='UNKNOWN', message_id=NULL"
        } else {
            "INSERT INTO im_send_attempts(account_id,conversation_id,beijing_day,client_message_id,state) SELECT ?1,?2,?3,?4,'UNKNOWN' FROM accounts a JOIN spark_targets t ON t.account_id=a.id WHERE a.id=?1 AND a.uid=?7 AND a.status='ACTIVE' AND a.encrypted_cookie=?5 AND t.id=?6 AND t.conversation_type=?8 AND t.target_uid IS ?9 AND t.target_sec_uid=?10 AND ((?8=1 AND (t.conversation_id IS NULL OR t.conversation_id=?2)) OR (?8=2 AND COALESCE(t.conversation_id,t.target_sec_uid)=?2)) AND t.is_enabled=1 AND t.message_template=?11 AND NOT COALESCE(t.last_status='SUCCESS' AND date(t.last_sent_at,'+8 hours')=?3 AND julianday(t.last_sent_at)<=julianday('now'),0)"
        };
        let changed = sqlx::query(sql)
            .bind(&self.account_id).bind(&self.cid).bind(day.to_string()).bind(client_id).bind(&self.encrypted_cookie).bind(&self.target_id)
            .bind(self.uid.to_string()).bind(self.kind).bind(&self.peer).bind(&self.target_sec_uid).bind(&self.template)
            .execute(&self.pool).await.context("PCIM_INIT_DAY_ALREADY_CLAIMED")?;
        anyhow::ensure!(changed.rows_affected() == 1, "PCIM_INIT_STATE_CHANGED");
        Ok(())
    }
    async fn accept(&self, client_id: &str, day: chrono::NaiveDate, message_id: &str) -> Result<()> {
        let changed = sqlx::query("UPDATE im_send_attempts SET state='ACCEPTED',message_id=?1 WHERE account_id=?2 AND conversation_id=?3 AND beijing_day=?4 AND client_message_id=?5 AND state='UNKNOWN' AND message_id IS NULL")
            .bind(message_id).bind(&self.account_id).bind(&self.cid).bind(day.to_string()).bind(client_id).execute(&self.pool).await?;
        anyhow::ensure!(changed.rows_affected() == 1, "PCIM_INIT_OUTCOME_CAS");
        Ok(())
    }
}

/// 仅存在于一次 execute_web 调用栈；不能从 HTTP 头伪造该提交许可。
pub(crate) struct InitialSubmission<'a> {
    ticket: &'a ConversationTicket,
    binding: &'a InitialBinding,
    auth: &'a GuardSendAuth,
    client_id: &'a str,
    day: chrono::NaiveDate,
}
impl InitialSubmission<'_> {
    pub(crate) fn refresh_request(&self, client: &DouyinClient, request: &mut reqwest::Request) -> Result<()> {
        anyhow::ensure!(self.ticket.is_current(client) && !client.sending_blocked(), "PCIM_INIT_QUEUE_CONTEXT");
        anyhow::ensure!(self.ticket.uid==self.binding.uid && self.ticket.conversation_id==self.binding.cid && self.ticket.conversation_type==self.binding.kind,"PCIM_INIT_TICKET_BINDING");
        // 排队后用同一新钥重建声明，绝不回填原 Cookie 中的旧证书/签名。
        let expected = self.ticket.build_pcim_auth_request(client,self.auth,self.client_id,&self.binding.template)?;
        anyhow::ensure!(request.url()==expected.url() && request.method()==expected.method()
            && request.body().and_then(|b|b.as_bytes())==expected.body().and_then(|b|b.as_bytes()), "PCIM_INIT_REQUEST_CHANGED");
        *request = expected;
        Ok(())
    }
    pub(crate) async fn claim(&self) -> Result<()> { self.binding.claim(self.client_id,self.day).await }
}

impl DouyinClient {
    pub(crate) fn configure_pcim_initial(&self, pool: sqlx::SqlitePool, encrypted_cookie: Vec<u8>, account:&crate::model::Account, target:&crate::model::SparkTarget) -> Result<()> {
        self.clear_send_credential();
        anyhow::ensure!(!self.sending_blocked(),"PCIM_INIT_CLIENT_STOPPED");
        self.configure_pcim_initial_force(pool,encrypted_cookie,account,target,false)
    }
    pub(crate) fn configure_pcim_initial_force(&self, pool: sqlx::SqlitePool, encrypted_cookie: Vec<u8>, account:&crate::model::Account, target:&crate::model::SparkTarget, force: bool) -> Result<()> {
        self.clear_send_credential();
        anyhow::ensure!(!self.sending_blocked(),"PCIM_INIT_CLIENT_STOPPED");
        let binding = InitialBinding::new(pool,encrypted_cookie,account,target,force)?;
        *self.pcim_initial.lock().unwrap() = Some(binding);
        Ok(())
    }
    pub(crate) async fn send_pcim_initial(&self, cid: Option<&str>, kind: i32, sec_uid:&str, peer: Option<&str>, text: &str) -> SendSparkResult {
        let binding = self.pcim_initial.lock().unwrap().clone();
        let mut stage = "BINDING";
        let result: Result<String> = async {
            anyhow::ensure!(!self.sending_blocked(), "PCIM_INIT_CONSUMED");
            let binding = binding.context("PCIM_INIT_NOT_CONFIGURED")?;
            anyhow::ensure!(kind==binding.kind && cid.is_none_or(|c|c==binding.cid) && sec_uid==binding.target_sec_uid && peer==binding.peer.as_deref() && text==binding.template,"PCIM_INIT_BINDING");
            anyhow::ensure!(!binding.started.swap(true,Ordering::SeqCst), "PCIM_INIT_CONSUMED");
            stage = "DAY_CLAIM";
            if !binding.force {
                anyhow::ensure!(!binding.has_day_claim(beijing_day()).await?, "PCIM_INIT_DAY_ALREADY_CLAIMED");
            }
            stage = "TICKET";
            let ticket = self.acquire_conversation_ticket_for(&binding.uid.to_string(),&binding.cid,binding.kind).await?;
            let day = beijing_day();
            let already_sent = ticket.pcim_initial_history_precheck(self).await?;
            if !binding.force {
                anyhow::ensure!(!already_sent, "PCIM_INIT_ALREADY_SENT_TODAY");
            }
            anyhow::ensure!(matches!(self.check_cookie().await,CheckCookieResult::Valid(_)) && ticket.is_current(self), "PCIM_INIT_PREFLIGHT");
            let auth = match self.ensure_guard_bound().await {
                Ok((key, material)) => GuardSendAuth::Signed { key, material },
                Err(_) => {
                    let key = self.web_context.lock().unwrap().as_mut()
                        .and_then(|c| c.get_or_create_guard_key().ok())
                        .unwrap_or_else(GuardKey::generate);
                    GuardSendAuth::Initial(key)
                }
            };
            let client_id = uuid::Uuid::new_v4().to_string();
            stage = "BUILD";
            let request = ticket.build_pcim_auth_request(self,&auth,&client_id,text)?;
            let submission = InitialSubmission { ticket:&ticket,binding:&binding,auth:&auth,client_id:&client_id,day };
            let auth_kind = match &auth {
                GuardSendAuth::Signed { key, material } => format!("Signed(pub={},mat_age={})", &key.public_key_base64()[..8], chrono::Utc::now().timestamp() - material.acquired_at()),
                GuardSendAuth::Initial(key) => format!("Initial(pub={})", &key.public_key_base64()[..8]),
            };
            let hdr_keys: Vec<_> = request.headers().keys().map(|k| k.as_str()).collect();
            tracing::warn!(account_id=%binding.account_id, auth=%auth_kind, headers=?hdr_keys, "PCIM 即将发送 /v1/message/send 请求");
            stage = "SUBMIT";
            let response = self.execute_web_initial(request,&submission).await;
            let (headers,bytes,guard) = response?;
            tracing::info!(account_id=%binding.account_id, response_len=bytes.len(), response_hex=%hex::encode(&bytes), "收到 /v1/message/send 原始响应字节");
            stage = "ACK";
            let message_id = match parse_pcim_initial_ack_for(&bytes,&client_id,binding.uid) {
                Ok(id) => id,
                Err(error) => {
                    tracing::warn!(account_id=%binding.account_id,target_id=%binding.target_id,client_message_id=%client_id,
                        ack=%safe_ack_summary(&bytes,&client_id,binding.uid),"PCIM 回执校验失败；不重试");
                    return Err(error);
                }
            };
            if let Some(new_mat) = auth.key().bind_response_headers(&headers, binding.uid, &self.get_current_cookie(), chrono::Utc::now().timestamp())? {
                if let Some(mut ctx) = self.web_context.lock().unwrap().clone() {
                    ctx.set_guard_material(&new_mat)?;
                    self.set_web_context(ctx)?;
                }
            }
            // 严格ACK通过才接受普通Cookie更新；绝不导入Guard签名或证书。
            self.merge_response_headers(&headers);
            drop(guard);
            stage = "IDENTITY_POSTCHECK";
            anyhow::ensure!(matches!(self.check_cookie().await,CheckCookieResult::Valid(_)) && ticket.is_current(self), "PCIM_INIT_POST_IDENTITY");
            stage = "HISTORY_POSTCHECK";
            anyhow::ensure!(ticket.verify_initial_history(self,&client_id,&message_id,text,day).await?, "PCIM_INIT_HISTORY_UNCONFIRMED");
            anyhow::ensure!(ticket.is_current(self), "PCIM_INIT_HISTORY_CONTEXT_CHANGED");
            stage = "ACCEPT_CAS";
            binding.accept(&client_id,day,&message_id).await?;
            Ok(message_id)
        }.await;
        // 所有失败均为 fatal，UNKNOWN 不重试；预检失败也不能切换到捕获凭证分支。
        if result.is_err() && stage != "DAY_CLAIM" { self.send_blocked.store(true,Ordering::Relaxed); }
        match result {
            Ok(id) => SendSparkResult {success:true,message:format!("续火消息已确认送达，消息ID: {id}"),spark_days:None,raw_response:Some(format!("MsgID: {id}"))},
            Err(_) => SendSparkResult::failure(&format!("PCIM_INIT_{stage}: {}；禁止发送重试", match stage {
                "DAY_CLAIM" => "当日已有发送占用，未再次提交；UNKNOWN 须保持未知",
                "TICKET" => "当前账号的目标会话票据未确认，未提交",
                "HISTORY_PRECHECK" => "今日历史未确认完整或今日已发送，未提交",
                "IDENTITY_PRECHECK" => "提交前身份未确认，未提交",
                "SUBMIT" => "提交门禁或网络响应未确认，保留日占用",
                "ACK" => "服务端回执未通过严格校验，保留 UNKNOWN",
                "IDENTITY_POSTCHECK" => "回执已通过，但发送后身份未确认，保留 UNKNOWN",
                "HISTORY_POSTCHECK" => "回执已通过，但精确消息历史未确认，保留 UNKNOWN",
                "ACCEPT_CAS" => "回执和历史已通过，但确认状态保存失败，禁止重发",
                _ => "发送绑定或请求构建未通过，未提交",
            })), 
        }
    }
}
impl ConversationTicket {
    async fn verify_initial_history(&self, client: &DouyinClient, client_id: &str, message_id: &str, text:&str, day: chrono::NaiveDate) -> Result<bool> {
        let mut query=Vec::new();encode_field_bytes(1,self.conversation_id.as_bytes(),&mut query);
        for (field,value) in [(2,self.conversation_type as u64),(3,self.short_id),(4,1),(6,50)] { encode_field_varint(field,value,&mut query); }
        let mut body=Vec::new();encode_field_bytes(301,&query,&mut body);
        let bytes=client.web_im("https://imapi.douyin.com/v1/message/get_by_conversation",301,&body).await?;
        exact_history(&bytes,client_id,message_id.parse()?,self.uid,&self.conversation_id,self.conversation_type,text,day)
    }
}
fn exact_history(bytes: &[u8], client_id: &str, message_id: u64, uid:u64, cid:&str, kind:i32, text:&str, day: chrono::NaiveDate) -> Result<bool> {
    let env=parse_protobuf_fields(bytes);
    for (n,v) in [(1,301),(3,0)] { anyhow::ensure!(read_varint(unique_field(&env,n,0)?,0).map(|x|x.0)==Some(v),"PCIM_INIT_HISTORY_STATUS"); }
    let body=parse_protobuf_fields(unique_field(&env,6,2)?);
    let history=parse_protobuf_fields(unique_field(&body,301,2)?);
    let mut matching=0;
    for (_,_,raw) in history.iter().filter(|(n,w,_)|*n==1 && *w==2) {
        let message=parse_protobuf_fields(raw);
        if read_varint(unique_field(&message,3,0)?,0).map(|x|x.0)!=Some(message_id) { continue; }
        matching+=1;
        if read_varint(unique_field(&message,2,0)?,0).map(|x|x.0)!=Some(kind as u64) {return Ok(false);}
        let mut ids=Vec::new();
        for (_,_,entry) in message.iter().filter(|(n,w,_)|*n==9 && *w==2) {
            let entry=parse_protobuf_fields(entry);
            if unique_field(&entry,1,2)?==b"s:client_message_id" { ids.push(unique_field(&entry,2,2)?.to_vec()); }
        }
        if ids.len()!=1 || ids[0]!=client_id.as_bytes() { return Ok(false); }
    }
    Ok(matching==1 && verify_history_message(bytes,uid,cid,message_id,text,day,chrono::Utc::now())?)
}

#[cfg(test)]
mod production_gate_tests {
    use super::*;
    async fn binding() -> InitialBinding {
        let pool=sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        crate::db::schema::init_schema(&pool).await.unwrap();
        sqlx::query("INSERT INTO accounts(id,alias,uid,encrypted_cookie,status,created_at,updated_at) VALUES(?1,'fixture','99191692311',X'01','ACTIVE','fixture','fixture')").bind(ACCOUNT).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO spark_targets(id,account_id,target_sec_uid,target_uid,target_nickname,message_template,created_at,updated_at) VALUES(?1,?2,'fixture','55696816245','fixture','🔥','fixture','fixture')").bind(TARGET).bind(ACCOUNT).execute(&pool).await.unwrap();
        let a=crate::db::get_account(&pool,ACCOUNT).await.unwrap().unwrap();let t=crate::db::get_target(&pool,TARGET).await.unwrap().unwrap();
        InitialBinding::new(pool,vec![1],&a,&t,false).unwrap()
    }
    #[tokio::test]
    async fn concurrent_day_claim_and_outcome_cas_are_single_winner() {
        let b=binding().await;let day=beijing_day();let id1=uuid::Uuid::new_v4().to_string();let id2=uuid::Uuid::new_v4().to_string();
        let (a,c)=tokio::join!(b.claim(&id1,day),b.claim(&id2,day));assert_ne!(a.is_ok(),c.is_ok());
        let (winner,loser)=if a.is_ok(){(&id1,&id2)}else{(&id2,&id1)};
        assert!(b.accept(loser,day,"123").await.is_err());
        let (a,c)=tokio::join!(b.accept(winner,day,"123"),b.accept(winner,day,"456"));assert_ne!(a.is_ok(),c.is_ok());
        assert!(b.claim(&uuid::Uuid::new_v4().to_string(),day).await.is_err());
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM im_send_attempts").fetch_one(&b.pool).await.unwrap();assert_eq!(count,1);
    }
    #[tokio::test]
    async fn previous_unknown_is_untouched_and_does_not_block_another_day() {
        let b=binding().await;let day=beijing_day();
        sqlx::query("INSERT INTO im_send_attempts VALUES(?1,?2,?3,'old-unknown','UNKNOWN',NULL)").bind(ACCOUNT).bind(CID).bind(day.pred_opt().unwrap().to_string()).execute(&b.pool).await.unwrap();
        b.claim(&uuid::Uuid::new_v4().to_string(),day).await.unwrap();
        let old:(String,Option<String>)=sqlx::query_as("SELECT state,message_id FROM im_send_attempts WHERE client_message_id='old-unknown'").fetch_one(&b.pool).await.unwrap();assert_eq!(old,("UNKNOWN".into(),None));
        assert!(b.claim(&uuid::Uuid::new_v4().to_string(),day.pred_opt().unwrap()).await.is_err());
    }
}

#[cfg(test)]
mod queued_gate_tests {
    use super::*;
    #[tokio::test]
    async fn queued_initial_request_rechecks_cookie_identity_and_history_before_claim() {
        for change in ["cookie","identity","history"] {
            let pool=sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
            crate::db::schema::init_schema(&pool).await.unwrap();
            let client=DouyinClient::new(&format!("sessionid=offline-queue-{change}"),"offline queue").unwrap();
            *client.verified_uid.lock().unwrap()=Some(99191692311);
            let context=crate::douyin::im_auth::WebSessionContext::from_session(99191692311,&client.get_current_cookie(),DEFAULT_USER_AGENT).unwrap()
                .with_identity(&serde_json::json!({"message":"success","data":{"identity_security_token":"offline-token","device_id":"offline-device"}})).unwrap();
            client.set_web_context(context.clone()).unwrap();
            let ticket=ConversationTicket {uid:99191692311,conversation_id:CID.into(),conversation_type:1,short_id:123,ticket:"offline-ticket".into(),context};
            client.send_history.lock().unwrap().insert(CID.into(),(99191692311,1,beijing_day(),false));
            let binding=InitialBinding {pool:pool.clone(),encrypted_cookie:vec![1],started:Arc::new(AtomicBool::new(true)),account_id:ACCOUNT.into(),uid:99191692311,target_id:TARGET.into(),cid:CID.into(),kind:1,peer:Some("55696816245".into()),target_sec_uid:"fixture".into(),template:"🔥".into(),force:false};
            let key=GuardKey::generate();let id=uuid::Uuid::new_v4().to_string();
            let request=ticket.build_pcim_initial_request(&client,&key,&id,"🔥").unwrap();
            let auth=GuardSendAuth::Initial(key);
            let submission=InitialSubmission {ticket:&ticket,binding:&binding,auth:&auth,client_id:&id,day:beijing_day()};
            let guard=client.test_lock_web_session().await;
            let send=client.execute_web_initial(request,&submission);tokio::pin!(send);
            tokio::select! { biased; _=&mut send=>panic!("request bypassed session queue"), _=tokio::time::sleep(Duration::from_millis(5))=>{} }
            match change {
                "cookie"=>*client.current_cookie.lock().unwrap()="sessionid=changed-offline".into(),
                "identity"=>client.web_context.lock().unwrap().as_mut().unwrap().identity_acquired_at=Some(0),
                _=>{client.send_history.lock().unwrap().insert(CID.into(),(99191692311,1,beijing_day(),true));}
            }
            drop(guard);assert!(send.await.is_err());
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(count,0);
        }
    }
}

#[cfg(test)]
mod dynamic_gate_tests {
    use super::*;
    fn history(uid:u64,cid:&str,kind:i32,text:&str,id:&str,message_id:u64,time:i64)->Vec<u8> {
        let mut m=Vec::new();encode_field_bytes(1,cid.as_bytes(),&mut m);
        for(n,v)in[(2,kind as u64),(3,message_id),(6,7),(7,uid),(10,time as u64)] {encode_field_varint(n,v,&mut m)}
        encode_field_bytes(8,&serde_json::to_vec(&serde_json::json!({"text":text})).unwrap(),&mut m);
        let mut ext=Vec::new();encode_field_bytes(1,b"s:client_message_id",&mut ext);encode_field_bytes(2,id.as_bytes(),&mut ext);encode_field_bytes(9,&ext,&mut m);
        let mut l=Vec::new();encode_field_bytes(1,&m,&mut l);let mut b=Vec::new();encode_field_bytes(301,&l,&mut b);
        let mut e=Vec::new();encode_field_varint(1,301,&mut e);encode_field_varint(3,0,&mut e);encode_field_bytes(6,&b,&mut e);e
    }
    #[test]
    fn dynamic_history_rejects_wrong_sender_cid_type_content_uuid_id_day() {
        let time=chrono::Utc::now().timestamp();let day=beijing_day();
        for (uid,cid,kind) in [(55696816245,"0:1:123:55696816245",1),(777,"998877",2)] {
            let good=history(uid,cid,kind,"任意模板","uuid",123,time);
            assert!(exact_history(&good,"uuid",123,uid,cid,kind,"任意模板",day).unwrap());
            for bytes in [history(uid+1,cid,kind,"任意模板","uuid",123,time),history(uid,"123",kind,"任意模板","uuid",123,time),history(uid,cid,3,"任意模板","uuid",123,time),history(uid,cid,kind,"wrong","uuid",123,time),history(uid,cid,kind,"任意模板","wrong",123,time),history(uid,cid,kind,"任意模板","uuid",456,time),history(uid,cid,kind,"任意模板","uuid",123,time-86400)] {
                assert!(!exact_history(&bytes,"uuid",123,uid,cid,kind,"任意模板",day).unwrap_or(false));
            }
        }
    }
    #[tokio::test]
    async fn generic_group_claim_cas_binds_account_cookie_target_and_template() {
        let pool=sqlx::sqlite::SqlitePoolOptions::new().max_connections(2).connect("sqlite::memory:").await.unwrap();
        crate::db::schema::init_schema(&pool).await.unwrap();
        for (id,uid) in [("a",777),("b",888)] {
            sqlx::query("INSERT INTO accounts(id,alias,uid,encrypted_cookie,created_at,updated_at) VALUES(?1,'offline',?2,X'01',datetime('now'),datetime('now'))").bind(id).bind(uid.to_string()).execute(&pool).await.unwrap();
            sqlx::query("INSERT INTO spark_targets(id,account_id,target_sec_uid,conversation_id,conversation_type,target_nickname,message_template,created_at,updated_at) VALUES(?1,?1,'group','998877',2,'offline','群消息',datetime('now'),datetime('now'))").bind(id).execute(&pool).await.unwrap();
        }
        let a=crate::db::get_account(&pool,"a").await.unwrap().unwrap();let t=crate::db::get_target(&pool,"a").await.unwrap().unwrap();
        let binding=InitialBinding::new(pool.clone(),vec![1],&a,&t,false).unwrap();let day=beijing_day();
        for sql in ["UPDATE accounts SET encrypted_cookie=X'02' WHERE id='a'","UPDATE accounts SET status='DISABLED' WHERE id='a'","UPDATE accounts SET uid='999' WHERE id='a'","UPDATE spark_targets SET account_id='b' WHERE id='a'","UPDATE spark_targets SET conversation_id='112233' WHERE id='a'","UPDATE spark_targets SET is_enabled=0 WHERE id='a'","UPDATE spark_targets SET message_template='changed' WHERE id='a'","UPDATE spark_targets SET conversation_type=1 WHERE id='a'"] {
            sqlx::query(sql).execute(&pool).await.unwrap();assert!(binding.claim(&uuid::Uuid::new_v4().to_string(),day).await.is_err());
            sqlx::query("UPDATE accounts SET uid='777',status='ACTIVE',encrypted_cookie=X'01' WHERE id='a'").execute(&pool).await.unwrap();
            sqlx::query("UPDATE spark_targets SET account_id='a',conversation_id='998877',conversation_type=2,is_enabled=1,message_template='群消息' WHERE id='a'").execute(&pool).await.unwrap();
        }
        let id1=uuid::Uuid::new_v4().to_string();let id2=uuid::Uuid::new_v4().to_string();let (one,two)=tokio::join!(binding.claim(&id1,day),binding.claim(&id2,day));assert_ne!(one.is_ok(),two.is_ok());
        let b=crate::db::get_account(&pool,"b").await.unwrap().unwrap();let t=crate::db::get_target(&pool,"b").await.unwrap().unwrap();
        InitialBinding::new(pool.clone(),vec![1],&b,&t,false).unwrap().claim(&uuid::Uuid::new_v4().to_string(),day).await.unwrap();
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(count,2);
    }
}
