use anyhow::{Context, Result, ensure};
use chrono::{Datelike, FixedOffset, Utc, Weekday};
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{sync::OnceLock, time::Duration};

use crate::model::SparkTarget;

const ITAB_YIYAN_URL: &str = "https://base.itab.link/yiyan/random?lang=cn";
const ITAB_FP: &str = "W6lRjJldEZ.1743471904";
const ITAB_ORIGIN: &str = "chrome-extension://mhloojimgilafopcmlcikiidgbbnelip";
const ITAB_SIGNATURE_KEY: &str = "U2FsdGVkX1+cPLMAgvIDKTHlZRD/kdr4ie3EjkwRFBQ=";
const ITAB_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MmM1NzUxMTBkY2ZmNmNjMmY4ODlhM2IiLCJ1cFBhc3N3b3JkVmVyc2lvbiI6MTc1MjQ1OTk4NTM2OSwiaWF0IjoxNzU0NTMwMzE3LCJleHAiOjE4MTY3MzgzMTd9.cUVo1CAYix-DSoNX8w9ixNK_fnuGxTXPQRIxTt-9IEA";
const ITAB_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";

const FALLBACK_QUOTES: &[(&str, &str)] = &[
    ("此生此夜不长好，明月明年何处看。", "苏轼"),
    ("宠辱不惊，闲看庭前花开花落；去留无意，漫随天外云卷云舒。", "陈继儒"),
    ("所谓美好的心灵，就是能体贴万物的心，能温柔对待一草一木的心灵。", "林清玄"),
    ("山河远阔，人间烟火，无一是你，无一不是你。", "尧十三"),
    ("海内存知己，天涯若比邻。", "王勃"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YiyanQuote {
    pub hitokoto: String,
    pub from: String,
    pub raw_from: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparkTemplateItem {
    pub id: String,
    pub name: String,
    pub content: String,
    pub description: String,
    pub builtin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariableInfo {
    pub token: &'static str,
    pub label: &'static str,
    pub example: &'static str,
}

pub fn supported_variables() -> Vec<TemplateVariableInfo> {
    vec![
        TemplateVariableInfo {
            token: "{yiyan}",
            label: "每日一言正文",
            example: "此生此夜不长好，明月明年何处看。",
        },
        TemplateVariableInfo {
            token: "{from}",
            label: "一言作者/出处",
            example: "苏轼",
        },
        TemplateVariableInfo {
            token: "{yiyan_full}",
            label: "一言正文 + 出处",
            example: "此生此夜不长好，明月明年何处看。 —— 苏轼",
        },
        TemplateVariableInfo {
            token: "{days}",
            label: "当前火花天数",
            example: "30",
        },
        TemplateVariableInfo {
            token: "{name}",
            label: "好友备注/昵称",
            example: "小王",
        },
        TemplateVariableInfo {
            token: "{date}",
            label: "今日日期",
            example: "2026-11-12",
        },
        TemplateVariableInfo {
            token: "{weekday}",
            label: "今日星期",
            example: "星期四",
        },
    ]
}

pub fn builtin_templates() -> Vec<SparkTemplateItem> {
    vec![
        SparkTemplateItem {
            id: "builtin_classic".to_string(),
            name: "经典火花".to_string(),
            content: "🔥".to_string(),
            description: "发送经典火焰表情续火".to_string(),
            builtin: true,
        },
        SparkTemplateItem {
            id: "builtin_yiyan".to_string(),
            name: "每日一言".to_string(),
            content: "{yiyan}".to_string(),
            description: "实时从 iTab 一言接口拉取随机金句".to_string(),
            builtin: true,
        },
        SparkTemplateItem {
            id: "builtin_spark_yiyan".to_string(),
            name: "火花 + 每日一言".to_string(),
            content: "🔥 {yiyan}".to_string(),
            description: "火焰图标搭配每日随机一言".to_string(),
            builtin: true,
        },
        SparkTemplateItem {
            id: "builtin_yiyan_from".to_string(),
            name: "一言 + 作者出处".to_string(),
            content: "{yiyan} —— {from}".to_string(),
            description: "每日一言正文并附带作者或作品出处".to_string(),
            builtin: true,
        },
        SparkTemplateItem {
            id: "builtin_days_yiyan".to_string(),
            name: "火花天数 + 一言".to_string(),
            content: "🔥 续火第 {days} 天 · {yiyan}".to_string(),
            description: "自动带入当前好友火花天数与每日一言".to_string(),
            builtin: true,
        },
        SparkTemplateItem {
            id: "builtin_greeting_yiyan".to_string(),
            name: "好友称呼 + 一言".to_string(),
            content: "{name}，今日份火花已送达 🔥 {yiyan}".to_string(),
            description: "优先使用好友备注名问候并附上每日一言".to_string(),
            builtin: true,
        },
    ]
}

fn yiyan_client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(6))
            .build()
            .unwrap_or_else(|_| Client::new())
    })
}

fn clean_from_field(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('-').trim_matches('—').trim();
    if trimmed.is_empty() {
        "佚名".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn fallback_yiyan() -> YiyanQuote {
    let idx = (Utc::now().timestamp_subsec_nanos() as usize) % FALLBACK_QUOTES.len();
    let (hitokoto, from) = FALLBACK_QUOTES[idx];
    YiyanQuote {
        hitokoto: hitokoto.to_string(),
        from: from.to_string(),
        raw_from: format!("-{from}-"),
    }
}

/// 请求 iTab 每日一言随机接口。
pub async fn fetch_random_yiyan() -> Result<YiyanQuote> {
    let response = yiyan_client()
        .get(ITAB_YIYAN_URL)
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .header(header::ACCEPT_LANGUAGE, "zh-CN,zh;q=0.9")
        .header("dnt", "1")
        .header("fp", ITAB_FP)
        .header("mode", "itab")
        .header(header::ORIGIN, ITAB_ORIGIN)
        .header("priority", "u=1, i")
        .header(
            "sec-ch-ua",
            "\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"156\", \"Brave\";v=\"156\"",
        )
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", "\"macOS\"")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "cross-site")
        .header("sec-gpc", "1")
        .header("signaturekey", ITAB_SIGNATURE_KEY)
        .header("token", ITAB_TOKEN)
        .header(header::USER_AGENT, ITAB_UA)
        .send()
        .await
        .context("请求 iTab 每日一言接口失败")?;

    ensure!(
        response.status().is_success(),
        "iTab 每日一言接口返回 HTTP {}",
        response.status()
    );
    let root: Value = response
        .json()
        .await
        .context("解析 iTab 每日一言 JSON 失败")?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .context("iTab 每日一言响应缺少 data 字段")?;
    let hitokoto = data
        .get("hitokoto")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("iTab 每日一言响应缺少 hitokoto 正文")?
        .to_string();
    let raw_from = data
        .get("from")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let from = clean_from_field(&raw_from);
    Ok(YiyanQuote {
        hitokoto,
        from,
        raw_from,
    })
}

pub fn template_needs_yiyan(template: &str) -> bool {
    let t = template.trim();
    t.eq_ignore_ascii_case("@yiyan")
        || t.contains("{yiyan}")
        || t.contains("{hitokoto}")
        || t.contains("{from}")
        || t.contains("{yiyan_from}")
        || t.contains("{yiyan_full}")
}

pub fn template_is_dynamic(template: &str) -> bool {
    let t = template.trim();
    template_needs_yiyan(t)
        || t.contains("||")
        || t.contains('\n')
        || t.contains("{days}")
        || t.contains("{spark_days}")
        || t.contains("{name}")
        || t.contains("{nickname}")
        || t.contains("{date}")
        || t.contains("{weekday}")
}

fn select_candidate_segment(raw_template: &str) -> &str {
    let trimmed = raw_template.trim();
    if trimmed.is_empty() {
        return "🔥";
    }
    let candidates: Vec<&str> = if trimmed.contains("||") {
        trimmed
            .split("||")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    } else if trimmed.contains('\n') {
        trimmed
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![trimmed]
    };
    if candidates.is_empty() {
        return "🔥";
    }
    if candidates.len() == 1 {
        return candidates[0];
    }
    let idx = (Utc::now().timestamp_subsec_nanos() as usize) % candidates.len();
    candidates[idx]
}

fn beijing_date_and_weekday() -> (String, &'static str) {
    let cst = FixedOffset::east_opt(8 * 3600).unwrap();
    let now = Utc::now().with_timezone(&cst);
    let date = now.format("%Y-%m-%d").to_string();
    let weekday = match now.weekday() {
        Weekday::Mon => "星期一",
        Weekday::Tue => "星期二",
        Weekday::Wed => "星期三",
        Weekday::Thu => "星期四",
        Weekday::Fri => "星期五",
        Weekday::Sat => "星期六",
        Weekday::Sun => "星期日",
    };
    (date, weekday)
}

pub fn render_with_context(
    raw_template: &str,
    target_name: &str,
    spark_days: i32,
    quote: Option<&YiyanQuote>,
) -> String {
    let chosen = select_candidate_segment(raw_template);
    if chosen.eq_ignore_ascii_case("@yiyan") {
        if let Some(q) = quote {
            return q.hitokoto.clone();
        }
        return fallback_yiyan().hitokoto;
    }
    if !template_is_dynamic(raw_template) {
        return chosen.to_string();
    }
    let fallback;
    let q = match quote {
        Some(q) => q,
        None => {
            fallback = fallback_yiyan();
            &fallback
        }
    };
    let (date, weekday) = beijing_date_and_weekday();
    let days_str = spark_days.max(1).to_string();
    let name = if target_name.trim().is_empty() {
        "朋友"
    } else {
        target_name.trim()
    };
    let yiyan_full = format!("{} —— {}", q.hitokoto, q.from);

    let rendered = chosen
        .replace("{yiyan_full}", &yiyan_full)
        .replace("{yiyan}", &q.hitokoto)
        .replace("{hitokoto}", &q.hitokoto)
        .replace("{from}", &q.from)
        .replace("{yiyan_from}", &q.from)
        .replace("{days}", &days_str)
        .replace("{spark_days}", &days_str)
        .replace("{name}", name)
        .replace("{nickname}", name)
        .replace("{date}", &date)
        .replace("{weekday}", weekday);

    let final_text = rendered.trim();
    if final_text.is_empty() {
        "🔥".to_string()
    } else {
        final_text.to_string()
    }
}

/// 渲染指定目标的续火花消息：若模板不含动态占位符则原样返回（零网络开销），
/// 若包含 `{yiyan}` 等占位符则实时请求 iTab 一言接口并渲染。
pub async fn render_target_message(target: &SparkTarget) -> String {
    let raw = target.message_template.trim();
    if raw.is_empty() {
        return "🔥".to_string();
    }
    if !template_is_dynamic(raw) {
        return target.message_template.clone();
    }
    let quote = if template_needs_yiyan(raw) {
        match fetch_random_yiyan().await {
            Ok(q) => Some(q),
            Err(err) => {
                tracing::warn!(error = %err, "拉取 iTab 每日一言失败，使用内置经典名句兜底");
                Some(fallback_yiyan())
            }
        }
    } else {
        None
    };
    let display_name = target
        .remark_name
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&target.target_nickname);
    render_with_context(raw, display_name, target.spark_days, quote.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_template_is_preserved_verbatim() {
        assert!(!template_is_dynamic("🔥"));
        assert!(!template_is_dynamic("public text"));
        assert_eq!(render_with_context("🔥", "小明", 10, None), "🔥");
    }

    #[test]
    fn dynamic_template_renders_yiyan_and_target_fields() {
        let quote = YiyanQuote {
            hitokoto: "此生此夜不长好，明月明年何处看。".to_string(),
            from: clean_from_field("-苏轼-"),
            raw_from: "-苏轼-".to_string(),
        };
        assert_eq!(quote.from, "苏轼");
        let out = render_with_context(
            "{name}，🔥 续火第 {days} 天：{yiyan} —— {from}",
            "阿珍",
            52,
            Some(&quote),
        );
        assert_eq!(
            out,
            "阿珍，🔥 续火第 52 天：此生此夜不长好，明月明年何处看。 —— 苏轼"
        );
    }
}
