//! 生产初始化分支的闭合离线测试；响应只能取自显式队列。
use super::*;
use super::super::session_auth::pcim_init::{ACCOUNT,TARGET,beijing_day};
const INFO:&str="/v2/conversation/get_info_list";
const HISTORY:&str="/v1/message/get_by_conversation";
const SEND:&str="/v1/message/send";
thread_local! { static MODE: RefCell<Option<&'static str>> = const { RefCell::new(None) }; }
thread_local! { static DYNAMIC: RefCell<Option<(u64,String,i32,String)>> = const { RefCell::new(None) }; }
fn bytes_field(bytes:&[u8],n:u32)->Vec<u8>{parse_protobuf_fields(bytes).into_iter().find(|(k,w,_)|*k==n&&*w==2).unwrap().2}
fn history(id:Option<&str>)->Vec<u8>{
    let mut list=Vec::new();
    if let Some(id)=id {
        let mut m=Vec::new();encode_field_bytes(1,CID.as_bytes(),&mut m);
        encode_field_varint(2,1,&mut m);
        for(n,v)in[(3,123456),(6,7),(7,UID),(10,chrono::Utc::now().timestamp() as u64)]{encode_field_varint(n,v,&mut m)}
        encode_field_bytes(8,"{\"text\":\"🔥\"}".as_bytes(),&mut m);
        let mut ext=Vec::new();encode_field_bytes(1,b"s:client_message_id",&mut ext);encode_field_bytes(2,id.as_bytes(),&mut ext);encode_field_bytes(9,&ext,&mut m);
        encode_field_bytes(1,&m,&mut list);
    }
    encode_field_varint(3,0,&mut list);
    let mut body=Vec::new();encode_field_bytes(301,&list,&mut body);
    let mut e=Vec::new();encode_field_varint(1,301,&mut e);encode_field_varint(3,0,&mut e);encode_field_bytes(6,&body,&mut e);e
}
fn ack(id:&str)->Vec<u8>{
    let mut send=Vec::new();for(n,v)in[(1,123456),(3,0),(5,0)]{encode_field_varint(n,v,&mut send)}encode_field_bytes(4,id.as_bytes(),&mut send);
    let mut body=Vec::new();encode_field_bytes(100,&send,&mut body);
    let mut e=Vec::new();for(n,v)in[(1,100),(3,0),(13,UID)]{encode_field_varint(n,v,&mut e)}encode_field_bytes(6,&body,&mut e);e
}
pub(super) fn response_headers(path: &str) -> header::HeaderMap {
    let mut headers=header::HeaderMap::new();
    if path==SEND {
        match MODE.with(|s|*s.borrow()) {
            Some("cookie-success" | "cookie-bad-ack") => {
                headers.append(header::SET_COOKIE,header::HeaderValue::from_static("ttwid=rotated-fixture; Path=/"));
                headers.append(header::SET_COOKIE,header::HeaderValue::from_static("bd_ticket_guard_server_data=forbidden-fixture; Path=/"));
            }
            Some("cookie-session") => {
                headers.append(header::SET_COOKIE,header::HeaderValue::from_static("sessionid=rotated-session-fixture; Path=/"));
            }
            _ => {}
        }
    }
    headers
}
pub(super) fn prepare_reply(request:&reqwest::Request){
    if let Some((uid,cid,kind,text))=DYNAMIC.with(|s|s.borrow().clone()) {
        if request.url().path()!=SEND {return;}
        let send=bytes_field(&bytes_field(request.body().unwrap().as_bytes().unwrap(),8),100);
        assert_eq!(bytes_field(&send,1),cid.as_bytes());assert_eq!(int_field(&send,2),kind as u64);
        assert_eq!(bytes_field(&send,7),format!("ticket-{cid}").as_bytes());
        let content:serde_json::Value=serde_json::from_slice(&bytes_field(&send,4)).unwrap();assert_eq!(content["text"],text);
        let id=String::from_utf8(bytes_field(&send,8)).unwrap();
        STATE.with(|s|{let mut s=s.borrow_mut();let q=&mut s.as_mut().unwrap().0;assert_eq!(q.front().unwrap().0,SEND);
            q.front_mut().unwrap().1=Ok(dynamic_ack(uid,&id));q.push_back((PROFILE,Ok(profile(uid))));q.push_back((HISTORY,Ok(dynamic_history(uid,&cid,kind,&text,Some(&id)))));
        });return;
    }
    let mode=MODE.with(|s|*s.borrow());
    let Some(mode)=mode else{return};
    if request.url().path()!=SEND{return}
    let body=bytes_field(&bytes_field(request.body().unwrap().as_bytes().unwrap(),8),100);
    let id=String::from_utf8(bytes_field(&body,8)).unwrap();
    STATE.with(|s|{
        let mut state=s.borrow_mut();let queue=&mut state.as_mut().unwrap().0;
        assert_eq!(queue.front().unwrap().0,SEND);
        if mode=="network" {return}
        queue.front_mut().unwrap().1=Ok(if matches!(mode,"bad-ack"|"cookie-bad-ack") {ack("wrong")}else{ack(&id)});
        if !matches!(mode,"bad-ack"|"cookie-bad-ack"|"cookie-session") {
            queue.push_back((PROFILE,Ok(profile(if mode=="identity"{777}else{UID}))));
            if mode!="identity" {queue.push_back((HISTORY,Ok(history(Some(if mode=="wrong-uuid"{"wrong"}else{&id})))));}
        }
    });
}
async fn database()->sqlx::SqlitePool{
    let pool=sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
    crate::db::schema::init_schema(&pool).await.unwrap();
    sqlx::query("INSERT INTO accounts(id,alias,uid,encrypted_cookie,status,created_at,updated_at) VALUES(?1,'public',?2,X'01','ACTIVE',datetime('now'),datetime('now'))")
        .bind(ACCOUNT).bind(UID.to_string()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO spark_targets(id,account_id,target_sec_uid,target_uid,conversation_type,target_nickname,message_template,created_at,updated_at) VALUES(?1,?2,'public','55696816245',1,'public','🔥',datetime('now'),datetime('now'))")
        .bind(TARGET).bind(ACCOUNT).execute(&pool).await.unwrap();pool
}
async fn configure(c:&DouyinClient,pool:&sqlx::SqlitePool) {
    let has_guard = c.web_context.lock().unwrap().as_ref().and_then(|ctx| ctx.guard_secret_hex.as_ref()).is_some();
    if !has_guard {
        let key = crate::douyin::pcim_guard::GuardKey::generate();
        let data = serde_json::to_vec(&serde_json::json!({
            "ticket": "official-bound-ticket",
            "ts_sign": "ts.2.test",
            "client_cert": format!("pub.{}", key.public_key_base64()),
        })).unwrap();
        let uid = (*c.verified_uid.lock().unwrap()).unwrap_or(UID);
        let material = key.bind_response(&data, uid, &c.get_current_cookie(), chrono::Utc::now().timestamp()).unwrap();
        let old_ctx = c.web_context.lock().unwrap().clone();
        if let Some(mut ctx) = old_ctx {
            ctx.guard_secret_hex = Some(key.to_hex());
            ctx.set_guard_material(&material).unwrap();
            c.set_web_context(ctx).unwrap();
        }
    }
    let a=crate::db::get_account(pool,ACCOUNT).await.unwrap().unwrap();let t=crate::db::get_target(pool,TARGET).await.unwrap().unwrap();
    c.configure_pcim_initial(pool.clone(),crate::crypto::SecretBox::new(&[1;32]),vec![1],&a,&t).unwrap();
}
fn prefix()->Vec<Reply>{vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID))),(INFO,Ok(conversation_ticket_response(CID,b"public-real-ticket",true))),(PROFILE,Ok(profile(UID))),(HISTORY,Ok(history(None))),(PROFILE,Ok(profile(UID)))]}
async fn run(c:&DouyinClient)->SendSparkResult{c.send_spark_message(Some(CID),1,"public",Some("55696816245"),"🔥").await}
#[tokio::test]
async fn initial_success_requires_exact_ack_identity_uuid_history_and_preserves_cookie(){
    MODE.with(|s|*s.borrow_mut()=Some("success"));let mut replies=prefix();replies.push((SEND,Ok(vec![])));init(replies);
    let pool=database().await;let c=client("initial-success");
    c.current_cookie.lock().unwrap().push_str("; bd_ticket_guard_server_data=old-cert; _bd_ticket_crypt=old-key; __security_server_data=old-sign; ttwid=keep");
    let original=c.get_current_cookie();configure(&c,&pool).await;
    assert!(run(&c).await.success);assert!(!c.sending_blocked());assert!(!run(&c).await.success);
    assert_eq!(c.get_current_cookie(),original);assert!(!c.is_cookie_changed());
    let mut headers=header::HeaderMap::new();headers.append(header::SET_COOKIE,header::HeaderValue::from_static("bd_ticket_guard_server_data=new-key-material; Path=/"));
    c.merge_response_headers(&headers);assert_eq!(c.get_current_cookie(),original);assert!(!c.is_cookie_changed());
    let row:(String,String)=sqlx::query_as("SELECT state,message_id FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(row,("ACCEPTED".into(),"123456".into()));
    assert_eq!(seen().iter().filter(|p|p.as_str()==SEND).count(),1);
    REQUESTS.with(|s|{
        let requests=s.borrow();let r=requests.iter().find(|r|r.url().path()==SEND).unwrap();
        let cookie=r.headers()[header::COOKIE].to_str().unwrap();assert!(cookie.contains("ttwid=keep"));
        assert!(r.headers().contains_key("bd-ticket-guard-client-data"));
        assert!(r.headers().contains_key("bd-ticket-guard-ree-public-key"));
        let send=bytes_field(&bytes_field(r.body().unwrap().as_bytes().unwrap(),8),100);
        assert_eq!(bytes_field(&send,1),CID.as_bytes());assert_eq!(bytes_field(&send,7),b"public-real-ticket");
        let content:serde_json::Value=serde_json::from_slice(&bytes_field(&send,4)).unwrap();assert_eq!(content,serde_json::json!({"aweType":700,"type":0,"richTextInfos":[],"text":"🔥"}));
        let id=String::from_utf8(bytes_field(&send,8)).unwrap();assert_eq!(uuid::Uuid::parse_str(&id).unwrap().get_version_num(),4);
        let ext=parse_protobuf_fields(&send).into_iter().filter(|(n,_,_)|*n==5).map(|(_,_,b)|b).find(|b|bytes_field(b,1)==b"s:client_message_id").unwrap();assert_eq!(bytes_field(&ext,2),id.as_bytes());
    });
    MODE.with(|s|*s.borrow_mut()=None);
}
#[tokio::test]
async fn initial_unknown_never_retries_or_reports_success(){
    for mode in ["network","bad-ack","wrong-uuid","identity"] {
        MODE.with(|s|*s.borrow_mut()=Some(mode));let mut replies=prefix();replies.push((SEND,Err("offline network failure")));init(replies);
        let pool=database().await;let c=client(&format!("initial-{mode}"));configure(&c,&pool).await;
        let r=run(&c).await;assert!(!r.success);assert!(r.is_fatal_failure());assert!(!run(&c).await.success);
        let stage=match mode {"network"=>"SUBMIT","bad-ack"=>"ACK","identity"=>"IDENTITY_POSTCHECK",_=>"HISTORY_POSTCHECK"};
        assert!(r.message.starts_with(&format!("PCIM_INIT_{stage}:")));
        let state:String=sqlx::query_scalar("SELECT state FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(state,"UNKNOWN");
        assert_eq!(seen().iter().filter(|p|p.as_str()==SEND).count(),1);
    }
    MODE.with(|s|*s.borrow_mut()=None);
}
#[tokio::test]
async fn initial_old_unknown_and_changed_state_reject_without_send(){
    for change in ["old","cookie","disabled","template","binding","cid","account","today"] {
        MODE.with(|s|*s.borrow_mut()=None);init(prefix());let pool=database().await;let c=client(&format!("initial-state-{change}"));configure(&c,&pool).await;
        match change {
            "old"=>{sqlx::query("INSERT INTO im_send_attempts VALUES(?1,?2,?3,'old-unknown','UNKNOWN',NULL)").bind(ACCOUNT).bind(CID).bind(beijing_day().to_string()).execute(&pool).await.unwrap();},
            "cookie"=>{sqlx::query("UPDATE accounts SET encrypted_cookie=X'02'").execute(&pool).await.unwrap();},
            "account"=>{sqlx::query("UPDATE accounts SET status='DISABLED'").execute(&pool).await.unwrap();},
            _=>{let sql=match change {"disabled"=>"UPDATE spark_targets SET is_enabled=0","template"=>"UPDATE spark_targets SET message_template='other'","binding"=>"UPDATE spark_targets SET target_uid='777'","cid"=>"UPDATE spark_targets SET conversation_id='other'",_=>"UPDATE spark_targets SET last_status='SUCCESS',last_sent_at=datetime('now')"};sqlx::query(sql).execute(&pool).await.unwrap();}
        }
        assert!(run(&c).await.is_fatal_failure());assert!(!seen().iter().any(|p|p==SEND));
        if change=="old" { assert!(seen().is_empty(),"旧UNKNOWN必须在平台请求前阻止"); }
        let rows:Vec<(String,String)>=sqlx::query_as("SELECT client_message_id,state FROM im_send_attempts").fetch_all(&pool).await.unwrap();
        assert_eq!(rows,if change=="old"{vec![("old-unknown".into(),"UNKNOWN".into())]}else{vec![]});
    }
}
#[tokio::test]
async fn initial_today_history_consumes_nothing(){
    MODE.with(|s|*s.borrow_mut()=None);let mut replies=prefix();replies.truncate(5);replies[4]=(HISTORY,Ok(history(Some("previous"))));init(replies);
    let pool=database().await;let c=client("initial-today");configure(&c,&pool).await;assert!(run(&c).await.is_fatal_failure());
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(count,0);assert!(!seen().iter().any(|p|p==SEND));
}
#[tokio::test]
async fn initial_binding_accepts_dynamic_accounts_but_rejects_invalid_targets(){
    let pool=database().await;let a=crate::db::get_account(&pool,ACCOUNT).await.unwrap().unwrap();let t=crate::db::get_target(&pool,TARGET).await.unwrap().unwrap();
    for case in 0..6 {let a=a.clone();let mut t=t.clone();match case {0=>t.account_id="other".into(),1=>t.target_uid=None,2=>t.conversation_type=3,3=>t.conversation_id=Some("other".into()),4=>t.message_template="".into(),_=>t.is_enabled=false};let c=client(&format!("invalid-{case}"));assert!(c.configure_pcim_initial(pool.clone(),crate::crypto::SecretBox::new(&[1;32]),vec![1],&a,&t).is_err());}
}

#[tokio::test]
async fn initial_incomplete_history_or_failed_identity_cannot_fallback() {
    for failed_identity in [true,false] {
        MODE.with(|s|*s.borrow_mut()=None);
        let mut replies=prefix();
        if failed_identity { replies=vec![(TOKEN,Err("offline identity failure"))]; }
        else {
            let mut list=Vec::new();encode_field_varint(3,1,&mut list);
            let mut body=Vec::new();encode_field_bytes(301,&list,&mut body);
            let mut env=Vec::new();encode_field_varint(1,301,&mut env);encode_field_varint(3,0,&mut env);encode_field_bytes(6,&body,&mut env);
            replies.truncate(5);replies[4]=(HISTORY,Ok(env));
        }
        init(replies);let pool=database().await;let c=client(&format!("initial-incomplete-{failed_identity}"));configure(&c,&pool).await;
        assert!(run(&c).await.is_fatal_failure());assert!(!run(&c).await.success);
        assert!(!seen().iter().any(|p|p==SEND));
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(count,0);
    }
}

fn int_field(bytes:&[u8],n:u32)->u64 {let f=parse_protobuf_fields(bytes).into_iter().find(|(k,w,_)|*k==n&&*w==0).unwrap();read_varint(&f.2,0).unwrap().0}
fn dynamic_ack(uid:u64,id:&str)->Vec<u8>{
    let mut s=Vec::new();for(n,v)in[(1,123456),(3,0),(5,0)]{encode_field_varint(n,v,&mut s)}encode_field_bytes(4,id.as_bytes(),&mut s);
    let mut b=Vec::new();encode_field_bytes(100,&s,&mut b);let mut e=Vec::new();for(n,v)in[(1,100),(3,0),(13,uid)]{encode_field_varint(n,v,&mut e)}encode_field_bytes(6,&b,&mut e);e
}
fn dynamic_ticket(cid:&str,kind:i32,member:bool)->Vec<u8>{
    let mut c=Vec::new();encode_field_bytes(1,cid.as_bytes(),&mut c);encode_field_bytes(4,format!("ticket-{cid}").as_bytes(),&mut c);
    for(n,v)in[(2,123),(3,kind as u64),(8,member as u64)]{encode_field_varint(n,v,&mut c)}
    let mut l=Vec::new();encode_field_bytes(1,&c,&mut l);let mut b=Vec::new();encode_field_bytes(610,&l,&mut b);
    let mut e=Vec::new();encode_field_varint(1,610,&mut e);encode_field_varint(3,0,&mut e);encode_field_bytes(6,&b,&mut e);e
}
fn dynamic_history(uid:u64,cid:&str,kind:i32,text:&str,id:Option<&str>)->Vec<u8>{
    let mut l=Vec::new();
    if let Some(id)=id {let mut m=Vec::new();encode_field_bytes(1,cid.as_bytes(),&mut m);
        for(n,v)in[(2,kind as u64),(3,123456),(6,7),(7,uid),(10,chrono::Utc::now().timestamp() as u64)]{encode_field_varint(n,v,&mut m)}
        encode_field_bytes(8,&serde_json::to_vec(&serde_json::json!({"text":text})).unwrap(),&mut m);
        let mut ext=Vec::new();encode_field_bytes(1,b"s:client_message_id",&mut ext);encode_field_bytes(2,id.as_bytes(),&mut ext);encode_field_bytes(9,&ext,&mut m);encode_field_bytes(1,&m,&mut l);
    }
    encode_field_varint(3,0,&mut l);let mut b=Vec::new();encode_field_bytes(301,&l,&mut b);let mut e=Vec::new();encode_field_varint(1,301,&mut e);encode_field_varint(3,0,&mut e);encode_field_bytes(6,&b,&mut e);e
}
#[tokio::test]
async fn multiple_accounts_targets_and_groups_use_fresh_tickets_and_dynamic_history() {
    MODE.with(|s|*s.borrow_mut()=None);let pool=database().await;
    let base=crate::db::get_account(&pool,ACCOUNT).await.unwrap().unwrap();let target=crate::db::get_target(&pool,TARGET).await.unwrap().unwrap();
    for uid in [55696816245u64,777777] {
        let mut a=base.clone();a.id=format!("offline-{uid}");a.uid=Some(uid.to_string());crate::db::insert_account(&pool,&a).await.unwrap();
        let c=DouyinClient::new(&format!("sessionid=generic-{uid}"),"offline").unwrap();*c.verified_uid.lock().unwrap()=Some(uid);
        let key = crate::douyin::pcim_guard::GuardKey::generate();
        let data = serde_json::to_vec(&serde_json::json!({
            "ticket": "official-bound-ticket",
            "ts_sign": "ts.2.test",
            "client_cert": format!("pub.{}", key.public_key_base64()),
        })).unwrap();
        let material = key.bind_response(&data, uid, &c.get_current_cookie(), chrono::Utc::now().timestamp()).unwrap();
        let mut ctx = crate::douyin::im_auth::WebSessionContext::from_session(uid, &c.get_current_cookie(), DEFAULT_USER_AGENT).unwrap();
        ctx.guard_secret_hex = Some(key.to_hex());
        ctx.set_guard_material(&material).unwrap();
        c.set_web_context(ctx).unwrap();
        for (index,kind) in [1,2,1].into_iter().enumerate() {
            let peer=888888u64+index as u64;let cid=if kind==1 {format!("0:1:{}:{}",uid.min(peer),uid.max(peer))}else{"987654321".into()};
            let mut t=target.clone();t.id=format!("target-{uid}-{index}");t.account_id=a.id.clone();t.conversation_type=kind;t.conversation_id=Some(cid.clone());t.target_uid=if kind==1{Some(peer.to_string())}else{None};t.message_template=format!("目标 {index} 文本");
            crate::db::insert_target(&pool,&t).await.unwrap();
            let mut replies=if index==0 {vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(uid)))]}else{vec![]};
            replies.extend([(INFO,Ok(dynamic_ticket(&cid,kind,true))),(PROFILE,Ok(profile(uid))),(HISTORY,Ok(dynamic_history(uid,&cid,kind,&t.message_template,None))),(PROFILE,Ok(profile(uid))),(SEND,Ok(vec![]))]);init(replies);
            DYNAMIC.with(|s|*s.borrow_mut()=Some((uid,cid.clone(),kind,t.message_template.clone())));
            c.configure_pcim_initial(pool.clone(),crate::crypto::SecretBox::new(&[1;32]),vec![1],&a,&t).unwrap();
            let result=c.send_spark_message(t.conversation_id.as_deref(),kind,&t.target_sec_uid,t.target_uid.as_deref(),&t.message_template).await;
            assert!(result.success,"uid={uid} target={index}: {}",result.message);assert!(!c.sending_blocked());
            assert_eq!(seen().iter().filter(|p|p.as_str()==SEND).count(),1);
            let row:(String,String)=sqlx::query_as("SELECT state,message_id FROM im_send_attempts WHERE account_id=?1 AND conversation_id=?2").bind(&a.id).bind(&cid).fetch_one(&pool).await.unwrap();assert_eq!(row,("ACCEPTED".into(),"123456".into()));
            DYNAMIC.with(|s|*s.borrow_mut()=None);
        }
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(count,6);
}
#[tokio::test]
async fn group_ticket_requires_exact_cid_type_and_membership() {
    MODE.with(|s|*s.borrow_mut()=None);DYNAMIC.with(|s|*s.borrow_mut()=None);
    for (index,cid,kind,member) in [(0,"987654321",2,false),(1,"wrong",2,true),(2,"987654321",1,true)] {
        let uid=1234567;let c=DouyinClient::new(&format!("sessionid=group-denied-{index}"),"offline").unwrap();*c.verified_uid.lock().unwrap()=Some(uid);
        init(vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(uid))),(INFO,Ok(dynamic_ticket(cid,kind,member)))]);
        assert!(c.acquire_conversation_ticket_for(&uid.to_string(),"987654321",2).await.is_err());assert!(!seen().iter().any(|p|p==SEND));
    }
}

#[tokio::test]
async fn initial_response_cookie_requires_ack_and_session_rotation_stops_followups() {
    for mode in ["cookie-success","cookie-bad-ack","cookie-session"] {
        MODE.with(|s|*s.borrow_mut()=Some(mode));
        let mut replies=prefix();replies.push((SEND,Ok(vec![])));init(replies);
        let pool=database().await;let c=client(mode);configure(&c,&pool).await;
        let original=c.get_current_cookie();
        let result=run(&c).await;
        assert_eq!(result.success,mode=="cookie-success");
        let cookie=c.get_current_cookie();
        assert!(!cookie.contains("forbidden-fixture"));
        let state:String=sqlx::query_scalar("SELECT state FROM im_send_attempts").fetch_one(&pool).await.unwrap();
        assert_eq!(state,if mode=="cookie-success"{"ACCEPTED"}else{"UNKNOWN"});
        match mode {
            "cookie-success" => {assert!(cookie.contains("ttwid=rotated-fixture"));assert!(c.is_cookie_changed());},
            "cookie-bad-ack" => {assert_eq!(cookie,original);assert!(!c.is_cookie_changed());assert!(result.message.starts_with("PCIM_INIT_ACK:"));},
            _ => {assert!(cookie.contains("sessionid=rotated-session-fixture"));assert!(c.sending_blocked());assert!(result.message.starts_with("PCIM_INIT_IDENTITY_POSTCHECK:"));},
        }
        let paths=seen();let sent=paths.iter().position(|p|p==SEND).unwrap();
        if mode!="cookie-success" {assert_eq!(paths.len(),sent+1,"拒绝回执或会话轮换后不得继续请求");}
        assert!(!run(&c).await.success);
        assert_eq!(seen().iter().filter(|p|p.as_str()==SEND).count(),1);
    }
    MODE.with(|s|*s.borrow_mut()=None);
}

#[tokio::test]
async fn full_chain_signed_send_with_guard_signature_and_dtrait() {
    MODE.with(|s|*s.borrow_mut()=Some("success"));
    let mut replies=prefix();replies.push((SEND,Ok(vec![])));init(replies);
    let pool=database().await;let c=client("full-chain-signed");
    let key = crate::douyin::pcim_guard::GuardKey::generate();
    let data = serde_json::to_vec(&serde_json::json!({
        "ticket": "official-bound-ticket",
        "ts_sign": "ts.2.test",
        "client_cert": format!("pub.{}", key.public_key_base64()),
    })).unwrap();
    let material = key.bind_response(&data, UID, &c.get_current_cookie(), chrono::Utc::now().timestamp()).unwrap();
    
    use rsa::{pkcs8::{EncodePublicKey, LineEnding}, RsaPrivateKey};
    let rsa_priv = RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
    let pem = rsa_priv.to_public_key().to_public_key_pem(LineEnding::LF).unwrap();
    
    {
        let mut ctx = c.web_context.lock().unwrap().clone().unwrap();
        ctx.guard_secret_hex = Some(key.to_hex());
        ctx.set_guard_material(&material).unwrap();
        ctx.set_dtrait_config(&pem, "test-dtrait-v1");
        c.set_web_context(ctx).unwrap();
    }
    
    configure(&c, &pool).await;
    let result = run(&c).await;
    assert!(result.success, "发送应成功: {}", result.message);
    
    REQUESTS.with(|s| {
        let requests = s.borrow();
        let r = requests.iter().find(|r| r.url().path() == SEND).unwrap();
        
        assert!(r.headers().contains_key("bd-ticket-guard-client-data"));
        assert_eq!(r.headers()["bd-ticket-guard-web-version"], "2");
        assert_eq!(r.headers()["bd-ticket-guard-web-sign-type"], "0");
        assert_eq!(r.headers()["bd-ticket-guard-ree-public-key"].to_str().unwrap(), key.public_key_base64().as_str());
        
        use base64::Engine;
        let client_data_b64 = r.headers()["bd-ticket-guard-client-data"].to_str().unwrap();
        let client_data: serde_json::Value = serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(client_data_b64).unwrap()).unwrap();
        assert_eq!(client_data["ts_sign"], "ts.2.test");
        assert_eq!(client_data["req_content"], "ticket,path,timestamp");
        
        assert!(r.headers().contains_key("x-tt-session-dtrait"));
        let dtrait_hdr = r.headers()["x-tt-session-dtrait"].to_str().unwrap();
        assert!(dtrait_hdr.starts_with("test-dtrait-v1_"));
    });
    
    let state: String = sqlx::query_scalar("SELECT state FROM im_send_attempts").fetch_one(&pool).await.unwrap();
    assert_eq!(state, "ACCEPTED");
    MODE.with(|s|*s.borrow_mut()=None);
}
