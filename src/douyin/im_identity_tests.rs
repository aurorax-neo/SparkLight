//! 离线响应队列：仅测试构建，绝不回退真实网络。
use super::*;
use std::{cell::RefCell, collections::VecDeque};
type Reply = (&'static str, Result<Vec<u8>, &'static str>);
thread_local! { static STATE: RefCell<Option<(VecDeque<Reply>, Vec<String>)>> = const { RefCell::new(None) }; }
thread_local! { static REQUESTS: RefCell<Vec<reqwest::Request>> = const { RefCell::new(Vec::new()) }; }
pub(super) fn observe(request: &reqwest::Request) {
    REQUESTS.with(|s|s.borrow_mut().push(request.try_clone().expect("mock request must clone")));
    pcim_production_tests::prepare_reply(request);
}
pub(super) fn active() -> bool { STATE.with(|s| s.borrow().is_some()) }
pub(super) fn response_headers(path: &str) -> header::HeaderMap {
    pcim_production_tests::response_headers(path)
}
pub(super) fn respond(path: &str) -> Result<Vec<u8>> {
    STATE.with(|s| {
        let mut state=s.borrow_mut(); let (queue,seen)=state.as_mut().unwrap();
        seen.push(path.into());
        let (expected,reply)=queue.pop_front().expect("unexpected mock request; network forbidden");
        assert_eq!(expected,path); reply.map_err(anyhow::Error::msg)
    })
}
fn init(replies: Vec<Reply>) {
    STATE.with(|s| *s.borrow_mut()=Some((replies.into(),vec![])));
    REQUESTS.with(|s|s.borrow_mut().clear());
}
fn seen() -> Vec<String> { STATE.with(|s|s.borrow().as_ref().unwrap().1.clone()) }
const UID: u64=99191692311;
const CID: &str="0:1:55696816245:99191692311";
const TOKEN: &str="/passport/safe/get_identity_security_token/";
const PROFILE: &str="/passport/account/info/v2/";
fn token() -> Vec<u8> { serde_json::json!({"message":"success","data":{"identity_security_token":"public-new-token","device_id":"public-device"}}).to_string().into_bytes() }
fn profile(uid:u64) -> Vec<u8> { serde_json::json!({"message":"success","data":{"user_id_str":uid.to_string(),"sec_user_id":"public-sec","screen_name":"offline identity"}}).to_string().into_bytes() }
fn client(case:&str) -> DouyinClient {
    let c=DouyinClient::new(&format!("sessionid=public-identity-{case}"),"offline mock").unwrap();
    *c.verified_uid.lock().unwrap()=Some(UID);
    let mut context=super::super::im_auth::WebSessionContext::from_session(UID,&c.get_current_cookie(),DEFAULT_USER_AGENT).unwrap()
        .with_identity(&serde_json::json!({"message":"success","data":{"identity_security_token":"public-expired","device_id":"public-device"}})).unwrap();
    context.identity_acquired_at=Some(chrono::Utc::now().timestamp()-601);
    c.set_web_context(context).unwrap();
    // 合成的完整历史结论，仅用于离线发送门禁测试。
    c.send_history.lock().unwrap().insert(CID.into(),(UID,1,chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive(),false));
    c
}
fn success() -> Vec<u8> {
    let mut response=Vec::new();encode_field_varint(3,0,&mut response);
    let mut send=Vec::new();encode_field_varint(1,123456,&mut send);
    let mut body=Vec::new();encode_field_bytes(100,&send,&mut body);encode_field_bytes(6,&body,&mut response);response
}
/// 合成授权明确来自测试，不能证明平台授权可生成。
fn fixture_for(c:&DouyinClient) -> super::super::im_auth::ImSendCredential {
    let mut credential=super::super::im_auth::test_credential(&c.get_current_cookie(),CID,1);
    let context=c.web_context.lock().unwrap().clone().unwrap();
    let mut envelope=context.envelope.clone();
    encode_field_varint(1,100,&mut envelope);
    let mut body=Vec::new();encode_field_bytes(100,&credential.send_body,&mut body);
    encode_field_bytes(8,&body,&mut envelope);
    credential.envelope=envelope;credential.user_agent=context.user_agent;credential
}
#[tokio::test]
async fn expired_identity_refetches_once_then_matching_fixture_can_send_once() {
    init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID))),("/v1/message/send",Ok(success()))]);
    let c=client("success");c.prepare_im_identity(Some(&UID.to_string())).await.unwrap();
    assert!(c.web_context.lock().unwrap().as_ref().unwrap().identity_is_current(UID,&c.get_current_cookie(),chrono::Utc::now().timestamp()));
    c.set_send_credential(fixture_for(&c)).unwrap();
    let r=c.send_spark_message(Some(CID),1,"public-peer",Some("55696816245"),"public mock").await;
    assert!(r.success);assert!(r.raw_response.unwrap().contains("123456"));
    let second=c.send_spark_message(Some(CID),1,"public-peer",Some("55696816245"),"public mock").await;
    assert!(!second.success);assert_eq!(seen(),vec![TOKEN,PROFILE,"/v1/message/send"]);
}
#[tokio::test]
async fn fetch_failure_blocks_even_if_caller_attempts_to_continue() {
    init(vec![(TOKEN,Err("PUBLIC_MOCK_FETCH_FAILURE"))]);let c=client("failure");
    assert!(c.prepare_im_identity(Some(&UID.to_string())).await.unwrap_err().to_string().contains("未发送"));
    assert!(c.sending_blocked());
    assert!(!c.send_spark_message(Some(CID),1,"public-peer",Some("55696816245"),"test").await.success);
    assert_eq!(seen(),vec![TOKEN]);
}
#[tokio::test]
async fn changed_identity_stops_before_sending() {
    init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(777)))]);let c=client("changed");
    assert!(c.prepare_im_identity(Some(&UID.to_string())).await.is_err());
    assert!(c.sending_blocked());assert!(c.verified_sender_uid(Some(&UID.to_string())).is_err());
    assert!(!c.send_spark_message(Some(CID),1,"public-peer",Some("55696816245"),"test").await.success);
    assert_eq!(seen(),vec![TOKEN,PROFILE]);
}
#[tokio::test]
async fn new_identity_does_not_create_or_rebind_send_authorization() {
    init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID)))]);let c=client("mismatch");
    let old=super::super::im_auth::test_credential(&c.get_current_cookie(),CID,1);
    c.prepare_im_identity(Some(&UID.to_string())).await.unwrap();
    assert!(c.set_send_credential(old).is_err());assert!(c.send_credential.lock().unwrap().is_none());
    assert!(!c.send_spark_message(Some(CID),1,"public-peer",Some("55696816245"),"test").await.success);
    assert_eq!(seen(),vec![TOKEN,PROFILE]);
}
#[test]
fn legacy_unknown_expired_future_and_cookie_changed_identity_are_not_current() {
    let c=client("age");let mut context=c.web_context.lock().unwrap().clone().unwrap();let now=chrono::Utc::now().timestamp();
    for time in [None,Some(now-601),Some(now+1)] {context.identity_acquired_at=time;assert!(!context.identity_is_current(UID,&c.get_current_cookie(),now));}
    context.identity_acquired_at=Some(now);assert!(context.identity_is_current(UID,&c.get_current_cookie(),now));
    assert!(!context.identity_is_current(777,&c.get_current_cookie(),now));assert!(!context.identity_is_current(UID,"sessionid=changed",now));
    let mut value=serde_json::to_value(&context).unwrap();value.as_object_mut().unwrap().remove("identity_acquired_at");
    let legacy:super::super::im_auth::WebSessionContext=serde_json::from_value(value).unwrap();assert!(!legacy.identity_is_current(UID,&c.get_current_cookie(),now));
}

#[tokio::test]
async fn send_entry_automatically_refetches_expired_identity_before_one_mock_send() {
    init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID))),("/v1/message/send",Ok(success()))]);
    let c=client("direct");
    // 预装独立的合成匹配授权；不从旧授权改写或延长时间。
    let fresh=super::super::im_auth::WebSessionContext::from_session(UID,&c.get_current_cookie(),DEFAULT_USER_AGENT).unwrap()
        .with_identity(&serde_json::json!({"message":"success","data":{"identity_security_token":"public-new-token","device_id":"public-device"}})).unwrap();
    let expired=c.web_context.lock().unwrap().clone().unwrap();
    c.set_web_context(fresh).unwrap();let fixture=fixture_for(&c);c.set_send_credential(fixture).unwrap();
    c.set_web_context(expired).unwrap();
    let r=c.send_spark_message(Some(CID),1,"public-peer",Some("55696816245"),"public mock").await;
    assert!(r.success);assert_eq!(seen(),vec![TOKEN,PROFILE,"/v1/message/send"]);
}

#[tokio::test]
async fn failed_refetch_does_not_consume_existing_authorization() {
    init(vec![(TOKEN,Err("PUBLIC_MOCK_FETCH_FAILURE"))]);let c=client("retained");
    let expired=c.web_context.lock().unwrap().clone().unwrap();
    let fresh=super::super::im_auth::WebSessionContext::from_credential(&super::super::im_auth::test_credential(&c.get_current_cookie(),CID,1));
    c.set_web_context(fresh).unwrap();let fixture=fixture_for(&c);c.set_send_credential(fixture).unwrap();c.set_web_context(expired).unwrap();
    assert!(!c.send_spark_message(Some(CID),1,"public-peer",Some("55696816245"),"mock").await.success);
    assert!(c.send_credential.lock().unwrap().is_some());assert!(c.sending_blocked());assert_eq!(seen(),vec![TOKEN]);
}

#[tokio::test]
async fn final_gate_rejects_missing_stale_or_already_sent_history_without_claiming() {
    init(vec![]);let c=client("history-gate");
    let context=super::super::im_auth::WebSessionContext::from_credential(&super::super::im_auth::test_credential(&c.get_current_cookie(),CID,1));
    c.set_web_context(context).unwrap();
    let now=chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive();
    for entry in [None,Some((UID,1,now.pred_opt().unwrap(),false)),Some((UID,1,now,true)),Some((777,1,now,false))] {
        c.send_history.lock().unwrap().clear();
        if let Some(entry)=entry {c.send_history.lock().unwrap().insert(CID.into(),entry);}
        c.set_send_credential(fixture_for(&c)).unwrap();
        let req=c.build_send_request("https://imapi.douyin.com/v1/message/send",UID,Some(CID),1,"public-peer",55696816245,"mock").unwrap();
        assert!(c.validate_send_history(&req).is_err());
    }
    assert!(seen().is_empty());
}

#[tokio::test]
async fn database_claim_is_conditional_once_only_and_preserves_replacement() {
    let pool=sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::query("CREATE TABLE account_im_credentials(account_id TEXT,conversation_id TEXT,encrypted_credential BLOB)").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO account_im_credentials VALUES('public-account',?1,?2)").bind(CID).bind(vec![2u8]).execute(&pool).await.unwrap();
    let c=client("claim");c.bind_send_claim(pool.clone(),"public-account",CID,vec![1]);
    assert!(c.claim_send_authorization().await.is_err());
    let remaining:(Vec<u8>,)=sqlx::query_as("SELECT encrypted_credential FROM account_im_credentials").fetch_one(&pool).await.unwrap();assert_eq!(remaining.0,vec![2]);
    c.bind_send_claim(pool.clone(),"public-account",CID,vec![2]);c.claim_send_authorization().await.unwrap();
    c.bind_send_claim(pool.clone(),"public-account",CID,vec![2]);assert!(c.claim_send_authorization().await.is_err());
}

async fn browser_sync_db() -> (sqlx::SqlitePool, crate::crypto::SecretBox) {
    let pool=sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
    for sql in [
        "CREATE TABLE accounts(id TEXT PRIMARY KEY, encrypted_cookie BLOB, uid TEXT, status TEXT, last_checked_at TEXT, updated_at TEXT)",
        "CREATE TABLE account_im_credentials(account_id TEXT, encrypted_credential BLOB)",
        "CREATE TABLE account_web_contexts(account_id TEXT PRIMARY KEY, encrypted_context BLOB)",
        "INSERT INTO accounts VALUES('public-account',X'01','99191692311','EXPIRED',NULL,NULL)",
        "INSERT INTO accounts VALUES('other-account',X'02','777','ACTIVE',NULL,NULL)",
        "INSERT INTO account_im_credentials VALUES('public-account',X'03'),('other-account',X'04')",
        "INSERT INTO account_web_contexts VALUES('public-account',X'05')",
    ] { sqlx::query(sql).execute(&pool).await.unwrap(); }
    (pool,crate::crypto::SecretBox::new(&[42;32]))
}
async fn assert_browser_sync_unchanged(pool:&sqlx::SqlitePool) {
    let row:(Vec<u8>,String,Option<String>)=sqlx::query_as("SELECT encrypted_cookie,status,last_checked_at FROM accounts WHERE id='public-account'").fetch_one(pool).await.unwrap();
    assert_eq!(row,(vec![1],"EXPIRED".into(),None));
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_im_credentials").fetch_one(pool).await.unwrap();assert_eq!(count,2);
    let old:Vec<u8>=sqlx::query_scalar("SELECT encrypted_context FROM account_web_contexts WHERE account_id='public-account'").fetch_one(pool).await.unwrap();assert_eq!(old,vec![5]);
}
#[tokio::test]
async fn browser_sync_commits_identity_and_cookie_but_never_authorizes_send() {
    init(vec![(PROFILE,Ok(profile(UID))),(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID)))]);
    let (pool,secret)=browser_sync_db().await;
    let c=DouyinClient::new("sessionid=public-browser-sync-success","offline").unwrap();
    c.sync_browser_session(&pool,&secret,"public-account",&[1],&UID.to_string()).await.unwrap();
    let encrypted:Vec<u8>=sqlx::query_scalar("SELECT encrypted_cookie FROM accounts WHERE id='public-account'").fetch_one(&pool).await.unwrap();
    assert_eq!(secret.decrypt(&encrypted).unwrap(),c.get_current_cookie().as_bytes());
    let encrypted:Vec<u8>=sqlx::query_scalar("SELECT encrypted_context FROM account_web_contexts WHERE account_id='public-account'").fetch_one(&pool).await.unwrap();
    let ctx:super::super::im_auth::WebSessionContext=serde_json::from_slice(&secret.decrypt(&encrypted).unwrap()).unwrap();
    assert!(ctx.identity_is_current(UID,&c.get_current_cookie(),chrono::Utc::now().timestamp()));
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_im_credentials WHERE account_id='public-account'").fetch_one(&pool).await.unwrap();assert_eq!(count,0);
    let other:Vec<u8>=sqlx::query_scalar("SELECT encrypted_cookie FROM accounts WHERE id='other-account'").fetch_one(&pool).await.unwrap();assert_eq!(other,vec![2]);
    let other:Vec<u8>=sqlx::query_scalar("SELECT encrypted_credential FROM account_im_credentials WHERE account_id='other-account'").fetch_one(&pool).await.unwrap();assert_eq!(other,vec![4]);
    assert_eq!(seen(),vec![PROFILE,TOKEN,PROFILE]);assert!(c.send_credential.lock().unwrap().is_none());
}
#[tokio::test]
async fn browser_sync_failures_leave_original_session_intact() {
    for (case,replies) in [
        ("wrong-uid",vec![(PROFILE,Ok(profile(777)))]),
        ("token-failed",vec![(PROFILE,Ok(profile(UID))),(TOKEN,Err("PUBLIC_FAILURE"))]),
        ("postcheck-changed",vec![(PROFILE,Ok(profile(UID))),(TOKEN,Ok(token())),(PROFILE,Ok(profile(777)))]),
    ] {
        init(replies);let (pool,secret)=browser_sync_db().await;
        let c=DouyinClient::new(&format!("sessionid=public-browser-{case}"),"offline").unwrap();
        assert!(c.sync_browser_session(&pool,&secret,"public-account",&[1],&UID.to_string()).await.is_err());
        assert_browser_sync_unchanged(&pool).await;
        assert!(!seen().iter().any(|path|path.contains("message/send")));
    }
}
#[tokio::test]
async fn browser_sync_cas_and_transaction_failure_preserve_original() {
    for fail_transaction in [false,true] {
        init(vec![(PROFILE,Ok(profile(UID))),(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID)))]);
        let (pool,secret)=browser_sync_db().await;
        if fail_transaction {sqlx::query("CREATE TRIGGER reject_context BEFORE UPDATE ON account_web_contexts BEGIN SELECT RAISE(ABORT,'public fixture'); END").execute(&pool).await.unwrap();}
        let c=DouyinClient::new(&format!("sessionid=public-browser-cas-{fail_transaction}"),"offline").unwrap();
        let original=if fail_transaction {vec![1]}else{vec![9]};
        assert!(c.sync_browser_session(&pool,&secret,"public-account",&original,&UID.to_string()).await.is_err());
        assert_browser_sync_unchanged(&pool).await;
        assert_eq!(seen(),vec![PROFILE,TOKEN,PROFILE]);
    }
}

#[tokio::test]
async fn browser_sync_does_not_reenable_disabled_account() {
    init(vec![(PROFILE,Ok(profile(UID))),(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID)))]);
    let (pool,secret)=browser_sync_db().await;
    sqlx::query("UPDATE accounts SET status='DISABLED' WHERE id='public-account'").execute(&pool).await.unwrap();
    let c=DouyinClient::new("sessionid=public-browser-disabled","offline").unwrap();
    assert!(c.sync_browser_session(&pool,&secret,"public-account",&[1],&UID.to_string()).await.is_err());
    let row:(Vec<u8>,String)=sqlx::query_as("SELECT encrypted_cookie,status FROM accounts WHERE id='public-account'").fetch_one(&pool).await.unwrap();
    assert_eq!(row,(vec![1],"DISABLED".into()));
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_im_credentials").fetch_one(&pool).await.unwrap();assert_eq!(count,2);
}

fn conversation_ticket_response(cid:&str, ticket:&[u8], member:bool) -> Vec<u8> {
    let mut conv=Vec::new();encode_field_bytes(1,cid.as_bytes(),&mut conv);
    encode_field_varint(2,7300427740086387237,&mut conv);encode_field_varint(3,1,&mut conv);
    encode_field_bytes(4,ticket,&mut conv);encode_field_varint(8,u64::from(member),&mut conv);
    let mut list=Vec::new();encode_field_bytes(1,&conv,&mut list);
    let mut body=Vec::new();encode_field_bytes(610,&list,&mut body);
    let mut env=Vec::new();encode_field_varint(1,610,&mut env);encode_field_varint(3,0,&mut env);encode_field_bytes(6,&body,&mut env);env
}
#[tokio::test]
async fn conversation_ticket_uses_bound_server_field_without_get_ticket_or_send() {
    const INFO:&str="/v2/conversation/get_info_list";
    init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID))),(INFO,Ok(conversation_ticket_response(CID,b"public-ticket",true))),(PROFILE,Ok(profile(UID)))]);
    let c=client("conversation-ticket");
    let material=c.acquire_conversation_ticket(&UID.to_string(),55696816245).await.unwrap();
    assert!(material.is_current(&c));assert!(c.send_credential.lock().unwrap().is_none());
    assert_eq!(seen(),vec![TOKEN,PROFILE,INFO,PROFILE]);
}
#[tokio::test]
async fn conversation_ticket_rejects_missing_mismatched_and_nonmember_without_fallback() {
    const INFO:&str="/v2/conversation/get_info_list";
    for (index,response) in [conversation_ticket_response(CID,b"",true),conversation_ticket_response("0:1:777:99191692311",b"public-ticket",true),conversation_ticket_response(CID,b"public-ticket",false),conversation_ticket_response(CID,&[255],true)].into_iter().enumerate() {
        init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID))),(INFO,Ok(response))]);
        let c=client(&format!("bad-ticket-{index}"));
        let error=c.acquire_conversation_ticket(&UID.to_string(),55696816245).await.err().unwrap();
        assert_eq!(error.to_string(),"CONVERSATION_TICKET_PARSE");
        assert_eq!(seen(),vec![TOKEN,PROFILE,INFO]);assert!(c.send_credential.lock().unwrap().is_none());
    }
}
#[tokio::test]
async fn conversation_ticket_postcheck_identity_change_stops_material_return() {
    const INFO:&str="/v2/conversation/get_info_list";
    init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID))),(INFO,Ok(conversation_ticket_response(CID,b"public-ticket",true))),(PROFILE,Ok(profile(777)))]);
    let c=client("ticket-changed");
    assert!(c.acquire_conversation_ticket(&UID.to_string(),55696816245).await.is_err());
    assert_eq!(seen(),vec![TOKEN,PROFILE,INFO,PROFILE]);
}

#[path = "session_candidate_tests.rs"]
mod session_candidate_tests;

#[path = "pcim_production_tests.rs"]
mod pcim_production_tests;

#[tokio::test]
async fn partial_conversation_sync_preserves_unknown_but_send_lookup_is_strict() {
    let mut core=Vec::new();encode_field_bytes(5,b"fixture",&mut core);
    let mut conv=Vec::new();encode_field_bytes(1,CID.as_bytes(),&mut conv);encode_field_varint(2,123,&mut conv);encode_field_bytes(50,&core,&mut conv);
    let mut list=Vec::new();encode_field_bytes(1,&conv,&mut list);
    let mut body=Vec::new();encode_field_bytes(610,&list,&mut body);
    let mut response=Vec::new();encode_field_varint(1,610,&mut response);encode_field_varint(3,0,&mut response);encode_field_bytes(6,&body,&mut response);
    let c=client("partial-sync");
    init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID))),("/v2/conversation/get_info_list",Ok(response.clone())),("/v2/conversation/get_info_list",Ok(response))]);
    c.prepare_im_identity(Some(&UID.to_string())).await.unwrap();
    let targets=vec![DouyinTargetParam{conv_id:CID.into(),conv_type:1,short_id:None},DouyinTargetParam{conv_id:format!("0:1:777:{UID}"),conv_type:1,short_id:None}];
    let partial=c.fetch_available_conversation_spark_status(&targets).await.unwrap();
    assert_eq!(partial.len(),1);assert!(partial.contains_key(CID));assert!(!partial.contains_key(&targets[1].conv_id));
    assert!(c.fetch_batch_conversation_spark_status(&targets).await.is_err());
    assert!(!seen().iter().any(|p|p=="/v1/message/send"));
}

#[tokio::test]
async fn friend_sync_keeps_contacts_when_no_im_conversations_exist() {
    let c=client("friend-partial");
    let relation=serde_json::json!({"status_code":0,"followings":[{"uid":"55696816245","sec_uid":"public-peer","nickname":"friend","remark_name":"remark"}],"recent_share_groups":[]}).to_string().into_bytes();
    let following=serde_json::json!({"status_code":0,"followings":[],"has_more":0}).to_string().into_bytes();
    let mut body=Vec::new();encode_field_bytes(610,&[],&mut body);let mut empty=Vec::new();encode_field_varint(1,610,&mut empty);encode_field_varint(3,0,&mut empty);encode_field_bytes(6,&body,&mut empty);
    init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID))),("/aweme/v1/web/im/spotlight/relation/",Ok(relation)),("/aweme/v1/web/user/following/list/",Ok(following)),("/v2/conversation/get_info_list",Ok(empty))]);
    c.prepare_im_identity(Some(&UID.to_string())).await.unwrap();
    let friends=c.fetch_following_friends(&UID.to_string(),"public-sec").await.unwrap();
    assert_eq!(friends.len(),1);assert_eq!(friends[0].nickname,"friend");assert!(friends[0].spark_days.is_none());assert!(friends[0].is_sparked_today.is_none());
    assert!(!seen().iter().any(|p|p=="/v1/message/send"));
}
