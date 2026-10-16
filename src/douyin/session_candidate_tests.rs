//! 候选 SESSION_AUTH 提交的封闭离线验证，不允许真实网络。
use super::*;
const INFO:&str="/v2/conversation/get_info_list";
const HISTORY:&str="/v1/message/get_by_conversation";
const SEND:&str="/v1/message/send";
fn history(sent:bool)->Vec<u8>{
    let mut payload=Vec::new();
    if sent {let mut message=Vec::new();encode_field_bytes(1,CID.as_bytes(),&mut message);encode_field_varint(3,123456,&mut message);encode_field_varint(6,7,&mut message);encode_field_bytes(8,br#"{"text":"public text"}"#,&mut message);encode_field_varint(7,UID,&mut message);encode_field_varint(10,chrono::Utc::now().timestamp() as u64,&mut message);encode_field_bytes(1,&message,&mut payload);}
    encode_field_varint(3,0,&mut payload);
    let mut body=Vec::new();encode_field_bytes(301,&payload,&mut body);
    let mut env=Vec::new();encode_field_varint(1,301,&mut env);encode_field_varint(3,0,&mut env);encode_field_bytes(6,&body,&mut env);env
}
async fn database()->sqlx::SqlitePool{
    let pool=sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
    crate::db::schema::init_schema(&pool).await.unwrap();
    sqlx::query("INSERT INTO accounts(id,alias,uid,encrypted_cookie,status,created_at,updated_at) VALUES('acc_37094b76c50f4e0aa1da3848c3e12534','public',?1,X'01','ACTIVE','public','public')").bind(UID.to_string()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO spark_targets(id,account_id,target_sec_uid,target_uid,conversation_type,target_nickname,message_template,created_at,updated_at) VALUES('tgt_2e614530f19d4723a2820e7daaac5ee9','acc_37094b76c50f4e0aa1da3848c3e12534','public','55696816245',1,'public','public text','public','public')").execute(&pool).await.unwrap();pool
}
fn marker()->std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("PI_SCRATCH_DIR").unwrap_or_else(|_|std::env::temp_dir().display().to_string())).join(format!("public-candidate-test-{}.json",uuid::Uuid::new_v4()))
}
fn prefix()->Vec<Reply>{vec![(TOKEN,Ok(token())),(PROFILE,Ok(profile(UID))),(INFO,Ok(conversation_ticket_response(CID,b"public-ticket",true))),(PROFILE,Ok(profile(UID)))]}
#[tokio::test]
async fn session_candidate_success_is_once_and_postchecked(){
    let mut replies=prefix();let mut accepted=success();encode_field_varint(1,100,&mut accepted);
    replies.extend([(HISTORY,Ok(history(false))),(PROFILE,Ok(profile(UID))),(SEND,Ok(accepted)),(PROFILE,Ok(profile(UID))),(HISTORY,Ok(history(true)))]);init(replies);
    let c=client("candidate-success");let pool=database().await;let path=marker();
    let material=c.acquire_conversation_ticket(&UID.to_string(),55696816245).await.unwrap();
    let result=material.submit_candidate(&c,"public text",&path,&pool,&[1]).await.unwrap();
    assert_eq!(result.state,"ACCEPTED");assert_eq!(result.message_id.as_deref(),Some("123456"));assert!(result.identity_postcheck&&result.history_postcheck);
    assert!(c.sending_blocked());assert_eq!(seen().iter().filter(|s|s.as_str()==SEND).count(),1);
    let state:String=sqlx::query_scalar("SELECT state FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(state,"ACCEPTED");assert!(path.exists());std::fs::remove_file(path).unwrap();
}
#[tokio::test]
async fn session_candidate_unknown_is_persisted_without_postcheck_or_retry(){
    let mut replies=prefix();replies.extend([(HISTORY,Ok(history(false))),(PROFILE,Ok(profile(UID))),(SEND,Err("PUBLIC_NETWORK_UNKNOWN"))]);init(replies);
    let c=client("candidate-unknown");let pool=database().await;let path=marker();
    let material=c.acquire_conversation_ticket(&UID.to_string(),55696816245).await.unwrap();
    let result=material.submit_candidate(&c,"public text",&path,&pool,&[1]).await.unwrap();assert_eq!(result.state,"UNKNOWN");assert!(c.sending_blocked());
    let state:String=sqlx::query_scalar("SELECT state FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(state,"UNKNOWN");assert_eq!(seen().iter().filter(|s|s.as_str()==SEND).count(),1);std::fs::remove_file(path).unwrap();
}
#[tokio::test]
async fn session_candidate_today_skip_consumes_no_attempt(){
    let mut replies=prefix();replies.push((HISTORY,Ok(history(true))));init(replies);
    let c=client("candidate-skip");let pool=database().await;let path=marker();
    let material=c.acquire_conversation_ticket(&UID.to_string(),55696816245).await.unwrap();
    let result=material.submit_candidate(&c,"public text",&path,&pool,&[1]).await.unwrap();assert_eq!(result.state,"SKIPPED_TODAY");assert!(!path.exists());
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM im_send_attempts").fetch_one(&pool).await.unwrap();assert_eq!(count,0);assert!(!seen().iter().any(|s|s==SEND));
}
#[tokio::test]
async fn session_candidate_existing_day_claim_and_changed_cookie_block_send(){
    for existing in [true,false] {
        let mut replies=prefix();replies.extend([(HISTORY,Ok(history(false))),(PROFILE,Ok(profile(UID)))]);init(replies);
        let c=client(&format!("candidate-claim-{existing}"));let pool=database().await;let path=marker();
        if existing {sqlx::query("INSERT INTO im_send_attempts VALUES('acc_37094b76c50f4e0aa1da3848c3e12534',?1,?2,'public-old','UNKNOWN',NULL)").bind(CID).bind(chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive().to_string()).execute(&pool).await.unwrap();}
        let material=c.acquire_conversation_ticket(&UID.to_string(),55696816245).await.unwrap();
        assert!(material.submit_candidate(&c,"public text",&path,&pool,if existing{&[1]}else{&[2]}).await.is_err());
        assert!(!seen().iter().any(|s|s==SEND));if path.exists(){std::fs::remove_file(path).unwrap();}
    }
}

#[tokio::test]
async fn session_candidate_ambiguous_outer_status_is_unknown() {
    for (case,values) in [[0,0],[0,9],[9,0]].into_iter().enumerate() {
        let mut bytes=Vec::new();encode_field_varint(1,100,&mut bytes);
        for value in values {encode_field_varint(3,value,&mut bytes);}
        let mut send=Vec::new();encode_field_varint(1,123456,&mut send);let mut body=Vec::new();encode_field_bytes(100,&send,&mut body);encode_field_bytes(6,&body,&mut bytes);
        let mut replies=prefix();replies.extend([(HISTORY,Ok(history(false))),(PROFILE,Ok(profile(UID))),(SEND,Ok(bytes))]);init(replies);
        let c=client(&format!("duplicate-status-{case}"));let pool=database().await;let path=marker();
        let material=c.acquire_conversation_ticket(&UID.to_string(),55696816245).await.unwrap();
        let result=material.submit_candidate(&c,"public text",&path,&pool,&[1]).await.unwrap();
        assert_eq!(result.state,"UNKNOWN");assert!(!result.identity_postcheck);assert_eq!(seen().iter().filter(|s|s.as_str()==SEND).count(),1);std::fs::remove_file(path).unwrap();
    }
}
#[test]
fn session_candidate_exact_history_content_and_submission_day() {
    let sent=chrono::DateTime::parse_from_rfc3339("2026-10-15T23:59:59+08:00").unwrap().with_timezone(&chrono::Utc);
    let now=sent+chrono::Duration::seconds(2);let day=chrono::NaiveDate::from_ymd_opt(2026,10,15).unwrap();
    for (content,kind,time,expected) in [(Some(br#"{"text":"public text"}"#.as_slice()),7,sent,true),(None,7,sent,false),(Some(b"bad".as_slice()),7,sent,false),(Some(br#"{"text":"wrong"}"#.as_slice()),7,sent,false),(Some(br#"{"text":"public text"}"#.as_slice()),8,sent,false),(Some(br#"{"text":"public text"}"#.as_slice()),7,now,false)] {
        let mut message=Vec::new();encode_field_bytes(1,CID.as_bytes(),&mut message);encode_field_varint(3,123456,&mut message);encode_field_varint(6,kind,&mut message);encode_field_varint(7,UID,&mut message);encode_field_varint(10,time.timestamp() as u64,&mut message);
        if let Some(content)=content{encode_field_bytes(8,content,&mut message);}
        let mut list=Vec::new();encode_field_bytes(1,&message,&mut list);let mut body=Vec::new();encode_field_bytes(301,&list,&mut body);let mut env=Vec::new();encode_field_bytes(6,&body,&mut env);
        assert_eq!(super::super::session_auth::verify_history_message(&env,UID,CID,123456,"public text",day,now).unwrap_or(false),expected);
    }
}

#[tokio::test]
async fn session_candidate_reconciliation_is_read_only_and_matches_client_id() {
    for found in [true,false] {
        let mut message=Vec::new();encode_field_bytes(1,CID.as_bytes(),&mut message);encode_field_varint(3,123456,&mut message);encode_field_varint(6,7,&mut message);encode_field_varint(7,UID,&mut message);encode_field_bytes(8,br#"{"text":"public text"}"#,&mut message);encode_field_varint(10,chrono::Utc::now().timestamp() as u64,&mut message);
        let mut entry=Vec::new();encode_field_bytes(1,b"s:client_message_id",&mut entry);encode_field_bytes(2,if found {b"public-client"}else{b"different-id"},&mut entry);encode_field_bytes(9,&entry,&mut message);
        let mut list=Vec::new();encode_field_bytes(1,&message,&mut list);let mut body=Vec::new();encode_field_bytes(301,&list,&mut body);let mut env=Vec::new();encode_field_varint(1,301,&mut env);encode_field_varint(3,0,&mut env);encode_field_bytes(6,&body,&mut env);
        let mut replies=prefix();replies.push((HISTORY,Ok(env)));init(replies);
        let c=client(&format!("reconcile-{found}"));let ticket=c.acquire_conversation_ticket(&UID.to_string(),55696816245).await.unwrap();
        assert_eq!(ticket.reconcile_candidate(&c,"public-client","public text").await.unwrap(),if found{Some("123456".into())}else{None});
        assert!(!seen().iter().any(|s|s==SEND));
    }
}
