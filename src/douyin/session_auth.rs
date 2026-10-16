//! SESSION_AUTH 会话 ticket 的独立获取。不是证书签名，也不复用捕获请求。
//! 协议来源：官方 SDK GetTicket / protobuf GET_TICKET=2005，Web ticket_type=3。
use super::*;

/// 当前客户端内存内的服务端材料；不提供 Debug/Serialize 或原始 ticket 读取接口。
pub struct SessionSendAuthorization {
    uid: u64,
    conversation_id: String,
    conversation_type: i32,
    short_id: u64,
    target_uid: u64,
    context: super::super::im_auth::WebSessionContext,
    ticket: String,
    acquired_at: i64,
}
impl SessionSendAuthorization {
    pub fn is_current(&self,client:&DouyinClient) -> bool {
        let now=chrono::Utc::now().timestamp();
        client.verified_sender_uid(Some(&self.uid.to_string())).is_ok()
            && now.checked_sub(self.acquired_at).is_some_and(|age|(0..=600).contains(&age))
            && self.context.identity_is_current(self.uid,&client.get_current_cookie(),now)
    }
}

impl DouyinClient {
    /// 只获取当前目标会话 ticket；不发送消息，不把 ticket 等同于证书签名。
    pub async fn acquire_session_send_authorization(&self,expected_uid:&str,conversation_id:&str,
        conversation_type:i32,target_uid:u64) -> Result<SessionSendAuthorization> {
        let uid=self.verified_sender_uid(Some(expected_uid))?;
        validate_conversation(uid,conversation_id,conversation_type)?;
        anyhow::ensure!(conversation_type==1 && target_uid>0 && uid!=target_uid
            && conversation_id==format!("0:1:{}:{}",uid.min(target_uid),uid.max(target_uid)),
            "独立会话授权仅支持已确认双方身份的单聊，未请求服务器");
        self.prepare_im_identity(Some(expected_uid)).await.context("SESSION_TICKET_IDENTITY")?;
        let context=self.web_context.lock().unwrap().clone().context("SESSION_TICKET_CONTEXT_MISSING")?;
        let conversations=self.fetch_batch_conversation_spark_status(&[DouyinTargetParam {
            conv_id:conversation_id.into(),conv_type:conversation_type,short_id:None,
        }]).await.context("SESSION_TICKET_CONVERSATION_FETCH")?;
        let short_id=conversations.get(conversation_id).map(|v|v.short_id).filter(|v|*v>0)
            .context("SESSION_TICKET_SHORT_ID_MISSING")?;
        let mut ticket_request=Vec::new();
        encode_field_varint(1,3,&mut ticket_request);
        encode_field_varint(2,conversation_type as u64,&mut ticket_request);
        encode_field_varint(4,target_uid,&mut ticket_request);
        encode_field_varint(5,short_id,&mut ticket_request);
        let mut body=Vec::new();encode_field_bytes(2005,&ticket_request,&mut body);
        let response=self.web_im("https://imapi.douyin.com/v1/conversation/get_ticket",2005,&body).await.context("SESSION_TICKET_FETCH")?;
        let ticket=parse_ticket_response(&response).context("SESSION_TICKET_PARSE")?;
        anyhow::ensure!(matches!(self.check_cookie().await,CheckCookieResult::Valid(_)),"SESSION_TICKET_POSTCHECK");
        self.verified_sender_uid(Some(expected_uid)).context("SESSION_TICKET_UID_CHANGED")?;
        context.validate_session(uid,&self.get_current_cookie()).context("SESSION_TICKET_SESSION_CHANGED")?;
        let authorization=SessionSendAuthorization {uid,conversation_id:conversation_id.into(),conversation_type,
            short_id,target_uid,context,ticket,acquired_at:chrono::Utc::now().timestamp()};
        anyhow::ensure!(authorization.is_current(self),"会话授权获取期间身份上下文过期，停止");
        Ok(authorization)
    }
}

/// 来自 cmd610 的目标会话材料；不是完整发送授权。
pub struct ConversationTicket {
    uid: u64,
    conversation_id: String,
    conversation_type: i32,
    short_id: u64,
    ticket: String,
    context: super::super::im_auth::WebSessionContext,
}
impl ConversationTicket {
    pub fn is_current(&self, client: &DouyinClient) -> bool {
        client.verified_sender_uid(Some(&self.uid.to_string())).is_ok()
            && self.context.identity_is_current(self.uid, &client.get_current_cookie(), chrono::Utc::now().timestamp())
            && client.web_context.lock().unwrap().as_ref().is_some_and(|current|current.envelope==self.context.envelope && current.user_agent==self.context.user_agent && current.identity_acquired_at==self.context.identity_acquired_at)
            && !self.ticket.is_empty() && self.short_id > 0
            && validate_conversation(self.uid, &self.conversation_id, self.conversation_type).is_ok()
    }
}
impl DouyinClient {
    pub async fn acquire_conversation_ticket(&self, expected_uid: &str, target_uid: u64) -> Result<ConversationTicket> {
        let uid = self.verified_sender_uid(Some(expected_uid)).context("CONVERSATION_TICKET_UID")?;
        anyhow::ensure!(target_uid > 0 && target_uid != uid, "CONVERSATION_TICKET_TARGET");
        let cid = format!("0:1:{}:{}", uid.min(target_uid), uid.max(target_uid));
        self.acquire_conversation_ticket_for(expected_uid,&cid,1).await
    }
    /// 私聊/群聊共用 cmd610；仅接受服务端明确确认当前账号为参与者的会话。
    pub async fn acquire_conversation_ticket_for(&self, expected_uid: &str, cid: &str, kind: i32) -> Result<ConversationTicket> {
        let uid = self.verified_sender_uid(Some(expected_uid)).context("CONVERSATION_TICKET_UID")?;
        validate_conversation(uid,cid,kind)?;
        self.prepare_im_identity(Some(expected_uid)).await.context("CONVERSATION_TICKET_IDENTITY")?;
        let context = self.web_context.lock().unwrap().clone().context("CONVERSATION_TICKET_CONTEXT")?;
        let mut query = Vec::new();
        encode_field_bytes(1, cid.as_bytes(), &mut query);
        encode_field_varint(3, kind as u64, &mut query);
        for field in [4, 5, 7] { encode_field_varint(field, 1, &mut query); }
        let mut list = Vec::new(); encode_field_bytes(1, &query, &mut list);
        let mut body = Vec::new(); encode_field_bytes(610, &list, &mut body);
        let bytes = self.web_im("https://imapi.douyin.com/v2/conversation/get_info_list", 610, &body)
            .await.context("CONVERSATION_TICKET_FETCH")?;
        let (short_id, ticket) = parse_conversation_ticket_for(&bytes, cid, kind).context("CONVERSATION_TICKET_PARSE")?;
        anyhow::ensure!(matches!(self.check_cookie().await, CheckCookieResult::Valid(_)), "CONVERSATION_TICKET_POSTCHECK");
        self.verified_sender_uid(Some(expected_uid)).context("CONVERSATION_TICKET_UID_CHANGED")?;
        let material = ConversationTicket { uid, conversation_id: cid.into(), conversation_type:kind, short_id, ticket, context };
        anyhow::ensure!(material.is_current(self), "CONVERSATION_TICKET_CONTEXT_CHANGED");
        Ok(material)
    }
}
fn unique_field(fields: &[(u32,u8,Vec<u8>)], number: u32, wire: u8) -> Result<&[u8]> {
    let mut found = fields.iter().filter(|(n,_,_)| *n == number);
    let (_, actual_wire, bytes) = found.next().context("TICKET_FIELD_MISSING")?;
    anyhow::ensure!(*actual_wire == wire && found.next().is_none(), "TICKET_FIELD_INVALID");
    Ok(bytes)
}
fn parse_conversation_ticket(bytes: &[u8], cid: &str) -> Result<(u64,String)> {
    parse_conversation_ticket_for(bytes,cid,1)
}
fn parse_conversation_ticket_for(bytes: &[u8], cid: &str, kind: i32) -> Result<(u64,String)> {
    anyhow::ensure!(matches!(kind,1|2),"TICKET_TYPE_INVALID");
    let env = parse_protobuf_fields(bytes);
    anyhow::ensure!(read_varint(unique_field(&env,1,0)?,0).map(|v|v.0)==Some(610)
        && read_varint(unique_field(&env,3,0)?,0).map(|v|v.0)==Some(0), "TICKET_RESPONSE_INVALID");
    let body = parse_protobuf_fields(unique_field(&env,6,2)?);
    let list = parse_protobuf_fields(unique_field(&body,610,2)?);
    let conv = parse_protobuf_fields(unique_field(&list,1,2)?);
    anyhow::ensure!(unique_field(&conv,1,2)? == cid.as_bytes(), "TICKET_CONVERSATION_MISMATCH");
    anyhow::ensure!(read_varint(unique_field(&conv,3,0)?,0).map(|v|v.0)==Some(kind as u64), "TICKET_TYPE_MISMATCH");
    anyhow::ensure!(read_varint(unique_field(&conv,8,0)?,0).map(|v|v.0)==Some(1), "TICKET_NOT_PARTICIPANT");
    let short_id = read_varint(unique_field(&conv,2,0)?,0).map(|v|v.0).filter(|v|*v>0).context("TICKET_SHORT_ID_INVALID")?;
    let ticket = std::str::from_utf8(unique_field(&conv,4,2)?).context("TICKET_UTF8_INVALID")?;
    anyhow::ensure!(!ticket.trim().is_empty() && ticket.len()<=16384, "TICKET_VALUE_INVALID");
    Ok((short_id,ticket.to_owned()))
}

fn parse_ticket_response(bytes:&[u8]) -> Result<String> {
    fn unique(fields:&[(u32,u8,Vec<u8>)],n:u32,w:u8) -> Result<Vec<u8>> {
        let matches:Vec<_>=fields.iter().filter(|(k,_,_)|*k==n).collect();
        anyhow::ensure!(matches.len()==1&&matches[0].1==w,"会话授权响应字段不完整或重复");
        Ok(matches[0].2.clone())
    }
    let fields=parse_protobuf_fields(bytes);
    let cmd=unique(&fields,1,0)?;let status=unique(&fields,3,0)?;
    anyhow::ensure!(read_varint(&cmd,0).map(|v|v.0)==Some(2005)
        && read_varint(&status,0).map(|v|v.0)==Some(0),"会话授权命令或状态未确认成功");
    let body=unique(&fields,6,2)?;let body=parse_protobuf_fields(&body);
    let result=unique(&body,2005,2)?;let result=parse_protobuf_fields(&result);
    let ticket=String::from_utf8(unique(&result,1,2)?).context("会话 ticket 非文本")?;
    anyhow::ensure!(!ticket.trim().is_empty()&&ticket.len()<=16384,"会话 ticket 为空或超长");
    Ok(ticket)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(ticket:&[u8])->Vec<u8> {
        let mut result=Vec::new();encode_field_bytes(1,ticket,&mut result);
        let mut body=Vec::new();encode_field_bytes(2005,&result,&mut body);
        let mut response=Vec::new();encode_field_varint(1,2005,&mut response);
        encode_field_varint(3,0,&mut response);encode_field_bytes(6,&body,&mut response);response
    }
    #[test]
    fn ticket_response_requires_unique_success_and_bounded_ticket() {
        assert_eq!(parse_ticket_response(&response(b"public-ticket")).unwrap(),"public-ticket");
        for bytes in [vec![],response(b""),response(&vec![b'a';16385]),response(&[255])] {assert!(parse_ticket_response(&bytes).is_err());}
        let mut duplicate=response(b"public-ticket");encode_field_varint(3,0,&mut duplicate);assert!(parse_ticket_response(&duplicate).is_err());
        let mut malformed=response(b"public-ticket");malformed.push(128);assert!(parse_ticket_response(&malformed).is_err());
    }
}

/// 显式验收入口的结果；候选路径尚未自动接入调度。
#[derive(serde::Serialize)]
pub struct SessionCandidateResult {
    pub state: &'static str,
    pub message_id: Option<String>,
    pub status: Option<i64>,
    pub identity_postcheck: bool,
    pub history_postcheck: bool,
}
impl ConversationTicket {
    /// 消费当前真实会话材料，仅用于显式受控验收；不使用捕获签名。
    #[cfg(test)]
    pub async fn submit_candidate(self, client: &DouyinClient, text: &str, journal: &std::path::Path, pool: &sqlx::SqlitePool, original_cookie: &[u8]) -> Result<SessionCandidateResult> {
        anyhow::ensure!(self.uid==99191692311 && self.conversation_id=="0:1:55696816245:99191692311", "CANDIDATE_SCOPE");
        anyhow::ensure!(self.is_current(client) && !client.sending_blocked(), "CANDIDATE_CONTEXT");
        anyhow::ensure!(client.get_current_cookie().split(';').all(|part| {
            let name=part.trim().split('=').next().unwrap_or("").to_ascii_lowercase();
            !name.starts_with("bd_ticket_guard") && !name.starts_with("_bd_ticket") && !name.starts_with("__security_server")
        }), "CANDIDATE_CAPTURED_GUARD_COOKIE_FORBIDDEN");
        let day=chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive();
        if client.check_i_sent_message_today(self.uid,&self.conversation_id,1,self.short_id).await.context("CANDIDATE_HISTORY")? {
            return Ok(SessionCandidateResult {state:"SKIPPED_TODAY",message_id:None,status:None,identity_postcheck:false,history_postcheck:true});
        }
        anyhow::ensure!(matches!(client.check_cookie().await,CheckCookieResult::Valid(_)), "CANDIDATE_PREFLIGHT");
        anyhow::ensure!(self.is_current(client), "CANDIDATE_PREFLIGHT_CHANGED");
        let client_id=uuid::Uuid::new_v4().to_string();
        let original_text=text;
        let text=if text.trim().is_empty(){"🔥"}else{text.trim()};
        anyhow::ensure!(text.len()<=4096, "CANDIDATE_MESSAGE_SIZE");
        let mut send=Vec::new();
        encode_field_bytes(1,self.conversation_id.as_bytes(),&mut send);
        encode_field_varint(2,1,&mut send);encode_field_varint(3,self.short_id,&mut send);
        let content=serde_json::json!({"text":text,"aweType":700,"richTextInfos":[],"mentionIds":[]});
        encode_field_bytes(4,content.to_string().as_bytes(),&mut send);
        encode_field_varint(6,7,&mut send);encode_field_bytes(7,self.ticket.as_bytes(),&mut send);
        encode_field_bytes(8,client_id.as_bytes(),&mut send);
        let mut body=Vec::new();encode_field_bytes(100,&send,&mut body);
        let mut envelope=self.context.envelope.clone();
        anyhow::ensure!(!parse_protobuf_fields(&envelope).iter().any(|(n,_,_)|matches!(n,1|2|8)), "CANDIDATE_ENVELOPE");
        encode_field_varint(1,100,&mut envelope);encode_field_varint(2,chrono::Utc::now().timestamp_millis() as u64,&mut envelope);
        encode_field_bytes(8,&body,&mut envelope);
        let request=client.web_request(Method::POST,"https://imapi.douyin.com/v1/message/send")?
            .header(header::CONTENT_TYPE,"application/x-protobuf").header(header::ACCEPT,"application/x-protobuf").body(envelope).build()?;
        client.validate_send_history(&request)?;
        anyhow::ensure!(day==chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive(), "CANDIDATE_DAY_CHANGED");
        // create_new 持久化标记在任何提交之前创建，成功、失败、未知均不移除。
        use std::io::Write;
        #[cfg(unix)] use std::os::unix::fs::OpenOptionsExt;
        let mut options=std::fs::OpenOptions::new();options.write(true).create_new(true);
        #[cfg(unix)] options.mode(0o600);
        let mut marker=options.open(journal).context("CANDIDATE_ALREADY_ATTEMPTED")?;
        let account="acc_37094b76c50f4e0aa1da3848c3e12534";
        let target="tgt_2e614530f19d4723a2820e7daaac5ee9";
        let mut tx=pool.begin().await?;
        let changed=sqlx::query("UPDATE accounts SET encrypted_cookie=encrypted_cookie WHERE id=?1 AND uid='99191692311' AND status='ACTIVE' AND encrypted_cookie=?2")
            .bind(account).bind(original_cookie).execute(&mut *tx).await?;
        anyhow::ensure!(changed.rows_affected()==1,"CANDIDATE_ACCOUNT_CHANGED");
        let valid:i64=sqlx::query_scalar("SELECT COUNT(*) FROM spark_targets WHERE id=?1 AND account_id=?2 AND target_uid='55696816245' AND conversation_type=1 AND is_enabled=1 AND message_template=?3")
            .bind(target).bind(account).bind(original_text).fetch_one(&mut *tx).await?;
        anyhow::ensure!(valid==1,"CANDIDATE_TARGET_CHANGED");
        sqlx::query("INSERT INTO im_send_attempts(account_id,conversation_id,beijing_day,client_message_id,state) VALUES(?1,?2,?3,?4,'CLAIMED')")
            .bind(account).bind(&self.conversation_id).bind(day.to_string()).bind(&client_id).execute(&mut *tx).await.context("CANDIDATE_DAY_ALREADY_CLAIMED")?;
        tx.commit().await?;
        marker.write_all(serde_json::json!({"uid":self.uid,"conversation_id":self.conversation_id,"day":day.to_string(),"client_message_id":client_id,"state":"CLAIMED"}).to_string().as_bytes())?;
        marker.sync_all()?;
        let mut submission=pool.begin().await?;
        let unchanged=sqlx::query("UPDATE accounts SET encrypted_cookie=encrypted_cookie WHERE id=?1 AND uid='99191692311' AND status='ACTIVE' AND encrypted_cookie=?2 AND EXISTS(SELECT 1 FROM spark_targets WHERE id=?3 AND account_id=?1 AND target_uid='55696816245' AND conversation_type=1 AND is_enabled=1 AND message_template=?4)")
            .bind(account).bind(original_cookie).bind(target).bind(original_text).execute(&mut *submission).await?;
        anyhow::ensure!(unchanged.rows_affected()==1 && self.is_current(client),"CANDIDATE_FINAL_STATE_CHANGED");
        let response=client.execute_web(request).await;
        client.send_blocked.store(true,Ordering::Relaxed);
        let mut outcome=SessionCandidateResult {state:"UNKNOWN",message_id:None,status:None,identity_postcheck:false,history_postcheck:false};
        if let Ok((headers,bytes,guard))=response {
            drop(guard);
            let fields=parse_protobuf_fields(&bytes);
            let command=unique_field(&fields,1,0).ok().and_then(|v|read_varint(v,0)).map(|v|v.0);
            let status=unique_field(&fields,3,0).ok().and_then(|v|read_varint(v,0)).map(|v|v.0 as i32 as i64);
            if command==Some(100) {
                outcome.status=status;
                let (success,_,_,id)=parse_im_send_response(&bytes);
                if success && status==Some(0) {
                    let body=unique_field(&fields,6,2).ok().map(parse_protobuf_fields).unwrap_or_default();
                    let send=unique_field(&body,100,2).ok().map(parse_protobuf_fields).unwrap_or_default();
                    let unique_id=unique_field(&send,1,0).ok().and_then(|v|read_varint(v,0)).is_some_and(|v|v.0>0);
                    let consistent=send.iter().filter(|(n,_,_)|matches!(n,3|4|5)).all(|(n,w,v)|{
                        send.iter().filter(|(k,_,_)|k==n).count()==1 && if *n==4 {*w==2 && v==client_id.as_bytes()}else{*w==0 && read_varint(v,0).is_some_and(|x|x.0==0)}
                    });
                    if unique_id && consistent {outcome.state="ACCEPTED";outcome.message_id=Some(id);client.merge_response_headers(&headers);}
                } else if status.is_some_and(|v|v!=0) {outcome.state="REJECTED";}
            }
        }
        sqlx::query("UPDATE im_send_attempts SET state=?1,message_id=?2 WHERE account_id=?3 AND conversation_id=?4 AND beijing_day=?5 AND client_message_id=?6 AND state='CLAIMED'")
            .bind(outcome.state).bind(&outcome.message_id).bind(account).bind(&self.conversation_id).bind(day.to_string()).bind(&client_id).execute(&mut *submission).await?;
        submission.commit().await?;
        if outcome.state=="ACCEPTED" {
            outcome.identity_postcheck=matches!(client.check_cookie().await,CheckCookieResult::Valid(_)) && client.verified_sender_uid(Some(&self.uid.to_string())).is_ok();
            if outcome.identity_postcheck {outcome.history_postcheck=self.verify_message(client,outcome.message_id.as_deref().unwrap_or(""),text,day).await.unwrap_or(false);}
        }
        Ok(outcome)
    }
}

impl ConversationTicket {
    async fn verify_message(&self,client:&DouyinClient,message_id:&str,text:&str,day:chrono::NaiveDate)->Result<bool> {
        let expected=message_id.parse::<u64>()?;
        let mut query=Vec::new();encode_field_bytes(1,self.conversation_id.as_bytes(),&mut query);
        for (field,value) in [(2,1),(3,self.short_id),(4,1),(6,50)]{encode_field_varint(field,value,&mut query);}
        let mut body=Vec::new();encode_field_bytes(301,&query,&mut body);
        let bytes=client.web_im("https://imapi.douyin.com/v1/message/get_by_conversation",301,&body).await?;
        verify_history_message(&bytes,self.uid,&self.conversation_id,expected,text,day,chrono::Utc::now())
    }
}
pub(super) fn verify_history_message(bytes:&[u8],uid:u64,cid:&str,expected:u64,text:&str,day:chrono::NaiveDate,now:chrono::DateTime<chrono::Utc>)->Result<bool> {
    let env=parse_protobuf_fields(bytes);let body=parse_protobuf_fields(unique_field(&env,6,2)?);
    let history=parse_protobuf_fields(unique_field(&body,301,2)?);
    let cst=chrono::FixedOffset::east_opt(8*3600).unwrap();
    for (_,_,bytes) in history.iter().filter(|(n,w,_)|*n==1&&*w==2) {
        let message=parse_protobuf_fields(bytes);
        let int=|n|unique_field(&message,n,0).ok().and_then(|b|read_varint(b,0)).map(|v|v.0);
        if int(3)!=Some(expected){continue;}
        let time=int(10).context("POSTCHECK_TIME_MISSING")?;
        let time=if time>10_000_000_000 {time/1000}else{time};
        let date=i64::try_from(time).ok().and_then(|time|chrono::DateTime::from_timestamp(time,0)).context("POSTCHECK_TIME_INVALID")?;
        let content:serde_json::Value=serde_json::from_slice(unique_field(&message,8,2)?).context("POSTCHECK_CONTENT_INVALID")?;
        return Ok(int(7)==Some(uid) && int(6)==Some(7) && unique_field(&message,1,2)?==cid.as_bytes()
            && content.get("text").and_then(|v|v.as_str())==Some(text)
            && date<=now && date.with_timezone(&cst).date_naive()==day);
    }
    Ok(false)
}

impl ConversationTicket {
    /// 未知提交后的只读核对；不修改尝试状态，不重发。
    pub async fn reconcile_candidate(&self,client:&DouyinClient,client_id:&str,text:&str)->Result<Option<String>> {
        self.reconcile_message_from(client,client_id,text,self.uid).await
    }
    /// 从当前账号可读的私聊核对指定发送人的消息；零发送、零状态写入。
    pub async fn reconcile_message_from(&self,client:&DouyinClient,client_id:&str,text:&str,sender:u64)->Result<Option<String>> {
        anyhow::ensure!(self.conversation_type==1,"RECONCILE_PRIVATE_ONLY");
        validate_conversation(sender,&self.conversation_id,1)?;
        anyhow::ensure!(self.is_current(client),"RECONCILE_CONTEXT_CHANGED");
        let mut query=Vec::new();encode_field_bytes(1,self.conversation_id.as_bytes(),&mut query);
        for (field,value) in [(2,1),(3,self.short_id),(4,1),(6,50)]{encode_field_varint(field,value,&mut query);}
        let mut body=Vec::new();encode_field_bytes(301,&query,&mut body);
        let bytes=client.web_im("https://imapi.douyin.com/v1/message/get_by_conversation",301,&body).await.context("RECONCILE_HISTORY")?;
        let env=parse_protobuf_fields(&bytes);let body=parse_protobuf_fields(unique_field(&env,6,2)?);
        let history=parse_protobuf_fields(unique_field(&body,301,2)?);
        for (_,_,raw) in history.iter().filter(|(n,w,_)|*n==1&&*w==2) {
            let message=parse_protobuf_fields(raw);
            let ids:Vec<_>=message.iter().filter(|(n,w,_)|*n==9&&*w==2).filter_map(|(_,_,v)|{
                let entry=parse_protobuf_fields(v);
                (unique_field(&entry,1,2).ok()==Some(b"s:client_message_id".as_slice())).then(||unique_field(&entry,2,2).ok().map(|v|v.to_vec())).flatten()
            }).collect();
            if ids.len()!=1 || ids[0]!=client_id.as_bytes(){continue;}
            let id=read_varint(unique_field(&message,3,0)?,0).map(|v|v.0).filter(|v|*v>0).context("RECONCILE_MESSAGE_ID")?;
            let now=chrono::Utc::now();let day=now.with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive();
            anyhow::ensure!(verify_history_message(&bytes,sender,&self.conversation_id,id,text,day,now)?,"RECONCILE_BINDING_MISMATCH");
            return Ok(Some(id.to_string()));
        }
        Ok(None)
    }
}

#[path = "pcim_init.rs"]
pub mod pcim_init;
