use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    db,
    model::UpdateSettingsReq,
    notify::bark::BarkNotifier,
    server::AppState,
};

#[derive(Deserialize)]
pub struct TestBarkReq {
    pub server: Option<String>,
    pub key: Option<String>,
}

pub async fn get_settings(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let _settings_guard=state.engine.settings_update_lock.lock().await;
    let settings = db::get_all_settings(&state.pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;

    let bark_server = settings.get("bark_server").cloned()
        .unwrap_or_else(|| state.engine.notifier.default_server.clone());

    let bark_key = settings.get("bark_key").cloned()
        .or_else(|| state.engine.notifier.default_key.clone());

    let schedule_time=state.engine.schedule_time.read().await.clone();
    let (min_delay,max_delay)=state.engine.delay_range();
    let max_retries=state.engine.max_retries.load(std::sync::atomic::Ordering::Relaxed);

    let masked_api_key = if state.api_key.len() > 8 {
        format!("{}***{}", &state.api_key[..4], &state.api_key[state.api_key.len() - 4..])
    } else {
        "***".to_string()
    };

    Ok(Json(json!({
        "code": 200,
        "data": {
            "bark_server": bark_server,
            "bark_key": bark_key,
            "spark_time": schedule_time,
            "min_delay_secs": min_delay,
            "max_delay_secs": max_delay,
            "max_retries": max_retries,
            "api_key_masked": masked_api_key,
            "has_bark_key": bark_key.as_ref().is_some_and(|k| !k.trim().is_empty()),
        }
    })))
}

pub async fn update_settings(
    State(state): State<AppState>,
    Json(req): Json<UpdateSettingsReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let _settings_guard=state.engine.settings_update_lock.lock().await;
    let (old_min,old_max)=state.engine.delay_range();
    let min=req.min_delay_secs.unwrap_or(old_min);
    let max=req.max_delay_secs.unwrap_or(old_max);
    let time=req.spark_time.as_ref().map(|s|s.trim());
    let valid_time=time.is_none_or(|s| {
        let b=s.as_bytes(); b.len()==5 && b[2]==b':'
            && b.iter().enumerate().all(|(i,c)|i==2||c.is_ascii_digit())
            && s[..2].parse::<u32>().is_ok_and(|v|v<24)
            && s[3..].parse::<u32>().is_ok_and(|v|v<60)
    });
    if !valid_time || min>max || max>86400 || req.max_retries.is_some_and(|v|!(1..=10).contains(&v)) {
        return Err((StatusCode::BAD_REQUEST,Json(json!({"code":400,"message":"请使用有效的 HH:mm 时间；延迟须满足 0 ≤ 最小值 ≤ 最大值 ≤ 86400 秒，重试次数为 1～10"}))));
    }
    let mut values=Vec::new();
    if let Some(v)=&req.bark_server {values.push(("bark_server",v.trim().to_string()));}
    if let Some(v)=&req.bark_key {values.push(("bark_key",v.trim().to_string()));}
    if let Some(v)=time {values.push(("spark_time",v.to_string()));}
    if req.min_delay_secs.is_some()||req.max_delay_secs.is_some() {
        values.push(("min_delay_secs",min.to_string()));
        values.push(("max_delay_secs",max.to_string()));
    }
    if let Some(v)=req.max_retries {values.push(("max_retries",v.to_string()));}
    let save=async {
        let mut tx=state.pool.begin().await?;
        for (key,value) in values {
            sqlx::query("INSERT INTO system_settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
                .bind(key).bind(value).execute(&mut *tx).await?;
        }
        tx.commit().await
    }.await;
    save.map_err(|_|(StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"code":500,"message":"配置保存失败，运行参数未更改"}))))?;
    if let Some(v)=time {*state.engine.schedule_time.write().await=v.to_string();}
    if req.min_delay_secs.is_some()||req.max_delay_secs.is_some() {state.engine.set_delay_range(min,max);}
    if let Some(v)=req.max_retries {state.engine.max_retries.store(v,std::sync::atomic::Ordering::Relaxed);}

    Ok(Json(json!({
        "code": 200,
        "message": "配置更新成功"
    })))
}

pub async fn test_bark(
    State(state): State<AppState>,
    Json(req): Json<TestBarkReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let settings = db::get_all_settings(&state.pool).await.unwrap_or_default();

    let server = req.server
        .filter(|s| !s.trim().is_empty())
        .or_else(|| settings.get("bark_server").cloned())
        .unwrap_or_else(|| state.engine.notifier.default_server.clone());

    let key = req.key
        .filter(|k| !k.trim().is_empty())
        .or_else(|| settings.get("bark_key").cloned())
        .or_else(|| state.engine.notifier.default_key.clone());

    let target_key = match key {
        Some(k) if !k.trim().is_empty() => k,
        _ => return Err((StatusCode::BAD_REQUEST, Json(json!({"code": 400, "message": "请先填入 Bark Key 再进行测试"})))),
    };

    BarkNotifier::test_push(&server, &target_key).await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"code": 400, "message": format!("测试推送失败: {e}")}))))?;

    Ok(Json(json!({
        "code": 200,
        "message": "Bark 测试通知已发送，请在手机上确认查收"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc,atomic::Ordering};
    async fn fixture() -> AppState {
        let pool=db::init_pool("sqlite::memory:").await.unwrap();
        let secret=crate::crypto::SecretBox::new(&[21;32]);
        let engine=Arc::new(crate::scheduler::SparkEngine::new(pool.clone(),secret.clone(),BarkNotifier::new("http://127.0.0.1:1".into(),None),"13:51".into(),128,1024,4));
        AppState {pool,secret_box:secret,engine,api_key:Arc::new("public-test-key".into())}
    }
    fn req(value:serde_json::Value) -> UpdateSettingsReq {serde_json::from_value(value).unwrap()}

    #[tokio::test]
    async fn saved_delay_updates_running_engine_and_get_returns_effective_values() {
        let s=fixture().await;
        assert!(update_settings(State(s.clone()),Json(req(json!({"spark_time":"14:25","min_delay_secs":4,"max_delay_secs":16,"max_retries":3})))).await.is_ok());
        assert_eq!(s.engine.delay_range(),(4,16));assert_eq!(*s.engine.schedule_time.read().await,"14:25");
        assert_eq!(s.engine.max_retries.load(Ordering::Relaxed),3);
        let db=db::get_all_settings(&s.pool).await.unwrap();assert_eq!(db["min_delay_secs"],"4");assert_eq!(db["max_delay_secs"],"16");
        // DB 数据不能冒充实际运行参数。
        db::set_setting(&s.pool,"min_delay_secs","999").await.unwrap();
        let response=get_settings(State(s)).await.unwrap().into_response();
        let bytes=axum::body::to_bytes(response.into_body(),65536).await.unwrap();
        let json:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["data"]["min_delay_secs"],4);assert_eq!(json["data"]["max_delay_secs"],16);
    }

    #[tokio::test]
    async fn invalid_settings_leave_database_and_runtime_unchanged() {
        let s=fixture().await;
        for invalid in [json!({"spark_time":"24:00"}),json!({"spark_time":"1:30"}),json!({"spark_time":"中文a"}),json!({"min_delay_secs":2000}),json!({"max_delay_secs":1}),json!({"max_delay_secs":86401}),json!({"max_retries":0}),json!({"max_retries":11})] {
            let mut invalid=invalid;invalid["bark_key"]=json!("must-not-be-written");
            let error=match update_settings(State(s.clone()),Json(req(invalid))).await {Err(e)=>e,Ok(_)=>panic!("accepted invalid settings")};
            assert_eq!(error.0,StatusCode::BAD_REQUEST);assert!(db::get_all_settings(&s.pool).await.unwrap().is_empty());
            assert_eq!(s.engine.delay_range(),(128,1024));assert_eq!(*s.engine.schedule_time.read().await,"13:51");
        }
    }

    #[tokio::test]
    async fn database_failure_rolls_back_all_fields_and_runtime() {
        let s=fixture().await;
        sqlx::query("CREATE TRIGGER reject_test_setting BEFORE INSERT ON system_settings WHEN NEW.key='max_delay_secs' BEGIN SELECT RAISE(ABORT,'public test failure'); END").execute(&s.pool).await.unwrap();
        assert!(update_settings(State(s.clone()),Json(req(json!({"spark_time":"14:25","min_delay_secs":4,"max_delay_secs":16})))).await.is_err());
        assert!(db::get_all_settings(&s.pool).await.unwrap().is_empty());assert_eq!(s.engine.delay_range(),(128,1024));assert_eq!(*s.engine.schedule_time.read().await,"13:51");
    }

    #[tokio::test]
    async fn get_reads_database_only_after_settings_lock_is_acquired() {
        let s=fixture().await;let guard=s.engine.settings_update_lock.lock().await;
        let copy=s.clone();let query=tokio::spawn(async move {get_settings(State(copy)).await.unwrap().into_response()});
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        db::set_setting(&s.pool,"bark_server","http://public-new-server").await.unwrap();
        s.engine.set_delay_range(4,16);drop(guard);
        let response=query.await.unwrap();let bytes=axum::body::to_bytes(response.into_body(),65536).await.unwrap();
        let json:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["data"]["bark_server"],"http://public-new-server");assert_eq!(json["data"]["min_delay_secs"],4);
    }

    #[tokio::test]
    async fn concurrent_partial_updates_preserve_valid_whole_range() {
        let s=fixture().await;
        let (a,b)=tokio::join!(update_settings(State(s.clone()),Json(req(json!({"min_delay_secs":200})))),update_settings(State(s.clone()),Json(req(json!({"max_delay_secs":150})))));
        assert!(a.is_ok()!=b.is_ok());
        let (min,max)=s.engine.delay_range();assert!(min<=max);
        let db=db::get_all_settings(&s.pool).await.unwrap();assert_eq!(db["min_delay_secs"],min.to_string());assert_eq!(db["max_delay_secs"],max.to_string());
    }
}
