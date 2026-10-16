//! 官方可信时间锚点；不发请求、不续期、不启用签名，也不接受本地时间冒充服务器时间。
use anyhow::{Context, Result, ensure};
use reqwest::{Method, StatusCode, Url, header::HeaderMap};
use std::time::{Duration, Instant, SystemTime};

const SYNC_URL: &str =
    "https://www.douyin.com/passport/user_info/get_sec_ts/?aid=6383&is_from_ttaccountsdk=1";
const MAX_RESPONSE_AGE: Duration = Duration::from_secs(2);
const ANCHOR_LIFETIME: Duration = Duration::from_secs(3600);
const MAX_CLOCK_DRIFT: Duration = Duration::from_secs(2);

/// 故意不支持序列化：重启后必须重新同步，不能延长旧材料有效期。
/// 该模块尚未接入任何生产请求或签名入口。
pub struct TrustedTimeAnchor {
    uid: u64,
    session_hash: String,
    server_epoch_sec: i64,
    received: Instant,
    received_wall: SystemTime,
}

impl TrustedTimeAnchor {
    /// 调用方必须提供同一受控 HTTPS 请求的实际响应、单调时间和本机接收时间。
    /// 不返回 HTTP 头，不把锚点当作 Ticket 或身份凭证。
    pub fn from_response(
        uid: u64,
        cookie: &str,
        url: &Url,
        method: &Method,
        status: StatusCode,
        headers: &HeaderMap,
        started: Instant,
        received: Instant,
        received_wall: SystemTime,
    ) -> Result<Self> {
        ensure!(uid > 0, "可信时间缺少账号身份");
        ensure!(
            url.as_str() == SYNC_URL && method == Method::POST,
            "可信时间来源或方法不符"
        );
        ensure!(status.is_success(), "可信时间响应失败，禁止使用旧锚点回退");
        ensure!(
            !headers
                .keys()
                .any(|k| k.as_str().contains("verify") || k.as_str().contains("captcha"))
                && !headers.contains_key("location"),
            "可信时间响应要求验证或跳转，停止同步"
        );
        ensure!(
            received
                .checked_duration_since(started)
                .is_some_and(|age| age <= MAX_RESPONSE_AGE),
            "可信时间响应过慢或时序无效"
        );
        let values: Vec<_> = headers.get_all("bd-ticket-guard-ts").iter().collect();
        ensure!(values.len() == 1, "可信时间头缺失或重复");
        let raw = values[0].to_str().context("可信时间头格式无效")?;
        ensure!(
            !raw.is_empty() && raw.len() <= 11 && raw.bytes().all(|b| b.is_ascii_digit()),
            "可信时间头不是有效秒数"
        );
        let server_epoch_sec: i64 = raw.parse().context("可信时间头无效")?;
        ensure!(
            (1..=253402300799).contains(&server_epoch_sec),
            "可信时间超出有效范围"
        );
        Ok(Self {
            uid,
            session_hash: super::im_auth::session_hash(cookie)?,
            server_epoch_sec,
            received,
            received_wall,
        })
    }

    /// 仅返回该会话的服务器秒数；锚点过期、时钟回拨/跳变或跨账号均失败。
    pub fn timestamp(&self, uid: u64, cookie: &str) -> Result<i64> {
        self.timestamp_at(uid, cookie, Instant::now(), SystemTime::now())
    }

    fn timestamp_at(&self, uid: u64, cookie: &str, now: Instant, wall: SystemTime) -> Result<i64> {
        ensure!(
            uid == self.uid && super::im_auth::session_hash(cookie)? == self.session_hash,
            "可信时间与账号或会话不符"
        );
        let monotonic_age = now
            .checked_duration_since(self.received)
            .context("可信时间单调时序无效")?;
        let wall_age = wall
            .duration_since(self.received_wall)
            .context("本地时钟回拨，必须重新同步")?;
        ensure!(
            monotonic_age.max(wall_age) < ANCHOR_LIFETIME,
            "可信时间锚点过期，必须重新同步"
        );
        ensure!(
            monotonic_age.abs_diff(wall_age) <= MAX_CLOCK_DRIFT,
            "本地时钟发生跳变，必须重新同步"
        );
        self.server_epoch_sec
            .checked_add(monotonic_age.as_secs() as i64)
            .context("可信时间溢出")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const COOKIE: &str = "sessionid=offline-time-account";
    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("bd-ticket-guard-ts", "1700000000".parse().unwrap());
        h
    }
    fn anchor(h: &HeaderMap) -> Result<TrustedTimeAnchor> {
        let now = Instant::now();
        TrustedTimeAnchor::from_response(
            1,
            COOKIE,
            &Url::parse(SYNC_URL).unwrap(),
            &Method::POST,
            StatusCode::OK,
            h,
            now,
            now,
            SystemTime::now(),
        )
    }
    #[test]
    fn matches_official_anchor_calculation_and_expiry_baseline() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("sdk/time_baseline.json")).unwrap();
        let a = anchor(&headers()).unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let mono = Duration::from_millis(case["monotonic_ms"].as_u64().unwrap() - 1000);
            let wall = Duration::from_millis(case["wall_ms"].as_u64().unwrap() - 1000000);
            let result = a.timestamp_at(1, COOKIE, a.received + mono, a.received_wall + wall);
            if case["expected"]["signable"].as_bool().unwrap() {
                assert_eq!(
                    result.unwrap(),
                    case["expected"]["timestamp"].as_i64().unwrap()
                );
            } else {
                assert!(result.is_err());
            }
        }
    }
    #[test]
    fn server_time_is_bound_to_uid_and_session() {
        let a = anchor(&headers()).unwrap();
        assert_eq!(
            a.timestamp_at(
                1,
                COOKIE,
                a.received + Duration::from_secs(3),
                a.received_wall + Duration::from_secs(3)
            )
            .unwrap(),
            1700000003
        );
        assert!(a.timestamp(2, COOKIE).is_err());
        assert!(a.timestamp(1, "sessionid=other").is_err());
        assert!(a.timestamp(1, "").is_err());
    }
    #[test]
    fn missing_duplicate_malformed_or_untrusted_time_is_rejected() {
        assert!(anchor(&HeaderMap::new()).is_err());
        for value in ["0", "-1", "NaN", "1.5", " 1700000000", "1700000000000"] {
            let mut h = headers();
            h.insert("bd-ticket-guard-ts", value.parse().unwrap());
            assert!(anchor(&h).is_err());
        }
        let mut h = headers();
        h.append("bd-ticket-guard-ts", "1700000001".parse().unwrap());
        assert!(anchor(&h).is_err());
        for name in ["x-verify-code", "x-captcha", "location"] {
            let mut h = headers();
            h.insert(name, "present".parse().unwrap());
            assert!(anchor(&h).is_err());
        }
    }
    #[test]
    fn source_method_status_and_response_age_are_strict() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let h = headers();
        for raw in [
            "http://www.douyin.com/passport/user_info/get_sec_ts/?aid=6383&is_from_ttaccountsdk=1",
            "https://evil.test/passport/user_info/get_sec_ts/?aid=6383&is_from_ttaccountsdk=1",
            "https://www.douyin.com/passport/user_info/get_sec_ts/?aid=1128&is_from_ttaccountsdk=1",
            "https://www.douyin.com/passport/user_info/get_sec_ts/?aid=6383&is_from_ttaccountsdk=1&x=1",
        ] {
            assert!(
                TrustedTimeAnchor::from_response(
                    1,
                    COOKIE,
                    &Url::parse(raw).unwrap(),
                    &Method::POST,
                    StatusCode::OK,
                    &h,
                    now,
                    now,
                    wall
                )
                .is_err()
            );
        }
        let url = Url::parse(SYNC_URL).unwrap();
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert!(
                TrustedTimeAnchor::from_response(
                    1,
                    COOKIE,
                    &url,
                    &Method::POST,
                    status,
                    &h,
                    now,
                    now,
                    wall
                )
                .is_err()
            );
        }
        assert!(
            TrustedTimeAnchor::from_response(
                1,
                COOKIE,
                &url,
                &Method::GET,
                StatusCode::OK,
                &h,
                now,
                now,
                wall
            )
            .is_err()
        );
        assert!(
            TrustedTimeAnchor::from_response(
                1,
                COOKIE,
                &url,
                &Method::POST,
                StatusCode::OK,
                &h,
                now,
                now + Duration::from_millis(2001),
                wall
            )
            .is_err()
        );
        assert!(
            TrustedTimeAnchor::from_response(
                1,
                COOKIE,
                &url,
                &Method::POST,
                StatusCode::OK,
                &h,
                now + Duration::from_secs(1),
                now,
                wall
            )
            .is_err()
        );
    }
    #[test]
    fn expired_rollback_and_clock_jump_have_no_local_fallback() {
        let a = anchor(&headers()).unwrap();
        for (mono, wall) in [(3600, 3600), (3599, 3600), (0, 3), (3, 0)] {
            assert!(
                a.timestamp_at(
                    1,
                    COOKIE,
                    a.received + Duration::from_secs(mono),
                    a.received_wall + Duration::from_secs(wall)
                )
                .is_err()
            );
        }
        assert!(
            a.timestamp_at(
                1,
                COOKIE,
                a.received,
                a.received_wall - Duration::from_secs(1)
            )
            .is_err()
        );
    }
}
