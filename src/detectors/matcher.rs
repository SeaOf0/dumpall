use std::cell::RefCell;
use std::collections::HashMap;

use crate::model::HttpLogEvent;

use super::aggregations::EventAggregation;
use super::rule_model::MatchExpr;

thread_local! {
    /// 进程内正则缓存：同一 pattern 只编译一次；编译失败不缓存（下次重试）。
    static REGEX_CACHE: RefCell<HashMap<String, regex::Regex>> = RefCell::new(HashMap::new());
}

/// 编译（或复用缓存的）正则。matches_with 与规则 validate 共用，避免逐记录重编译。
/// 编译失败返回 None（不缓存，下次重试）。
pub fn cached_regex(pattern: &str) -> Option<regex::Regex> {
    compile_cached(pattern).ok()
}

/// 编译并缓存正则：命中缓存直接克隆；未命中则编译，成功才入缓存。
/// 校验路径可用返回的 regex::Error 输出具体原因。
pub fn compile_cached(pattern: &str) -> std::result::Result<regex::Regex, regex::Error> {
    REGEX_CACHE.with(|cache| {
        if let Some(regex) = cache.borrow().get(pattern) {
            return Ok(regex.clone());
        }
        let compiled = regex::Regex::new(pattern)?;
        cache
            .borrow_mut()
            .insert(pattern.to_string(), compiled.clone());
        Ok(compiled)
    })
}

pub fn matches_event(expr: &MatchExpr, event: &HttpLogEvent) -> bool {
    matches_event_with_aggregation(expr, event, None)
}

pub fn matches_event_with_aggregation(
    expr: &MatchExpr,
    event: &HttpLogEvent,
    aggregation: Option<&EventAggregation>,
) -> bool {
    matches_with(expr, "request", &|field| {
        event_field_with_aggregation(event, aggregation, field)
    })
}

pub fn matches_record(
    expr: &MatchExpr,
    default_field: &str,
    field_lookup: &dyn Fn(&str) -> Option<String>,
) -> bool {
    matches_with(expr, default_field, field_lookup)
}

fn matches_with(
    expr: &MatchExpr,
    default_field: &str,
    field_lookup: &dyn Fn(&str) -> Option<String>,
) -> bool {
    if !expr.all.is_empty()
        && !expr
            .all
            .iter()
            .all(|child| matches_with(child, default_field, field_lookup))
    {
        return false;
    }
    if !expr.any.is_empty()
        && !expr
            .any
            .iter()
            .any(|child| matches_with(child, default_field, field_lookup))
    {
        return false;
    }
    if let Some(child) = &expr.not {
        if matches_with(child, default_field, field_lookup) {
            return false;
        }
    }

    let mut has_leaf = false;
    let mut leaf_matched = true;

    if let Some(expected) = &expr.equals {
        has_leaf = true;
        leaf_matched &= field_value(expr, default_field, field_lookup)
            .map(|value| value.eq_ignore_ascii_case(expected))
            .unwrap_or(false);
    }
    if let Some(needle) = &expr.contains {
        has_leaf = true;
        let needle = needle.to_ascii_lowercase();
        // 双匹配：先按原文（已 lowercase）匹配，再按解码视图匹配；
        // 原文匹配保留现有 contains 语义，解码匹配覆盖 URL 编码变形。
        leaf_matched &= field_value(expr, default_field, field_lookup)
            .map(|value| {
                let value = value.to_ascii_lowercase();
                value.contains(&needle) || normalize_match_text(&value).contains(&needle)
            })
            .unwrap_or(false);
    }
    if !expr.contains_any.is_empty() {
        has_leaf = true;
        leaf_matched &= field_value(expr, default_field, field_lookup)
            .map(|value| {
                let value = value.to_ascii_lowercase();
                let normalized = normalize_match_text(&value);
                expr.contains_any.iter().any(|needle| {
                    let needle = needle.to_ascii_lowercase();
                    value.contains(&needle) || normalized.contains(&needle)
                })
            })
            .unwrap_or(false);
    }
    if let Some(pattern) = &expr.regex {
        has_leaf = true;
        leaf_matched &= field_value(expr, default_field, field_lookup)
            .and_then(|value| {
                cached_regex(pattern).map(|regex| regex.is_match(&value))
            })
            .unwrap_or(false);
    }
    if !expr.in_values.is_empty() {
        has_leaf = true;
        leaf_matched &= field_value(expr, default_field, field_lookup)
            .map(|value| {
                expr.in_values
                    .iter()
                    .any(|expected| value.eq_ignore_ascii_case(expected))
            })
            .unwrap_or(false);
    }
    for (operator, expected) in [
        ("gt", expr.gt),
        ("gte", expr.gte),
        ("lt", expr.lt),
        ("lte", expr.lte),
    ] {
        if let Some(expected) = expected {
            has_leaf = true;
            leaf_matched &= numeric_compare(
                field_value(expr, default_field, field_lookup),
                operator,
                expected,
            );
        }
    }
    if !expr.status_in.is_empty() {
        has_leaf = true;
        leaf_matched &= field_lookup("status")
            .and_then(|status| status.parse::<u16>().ok())
            .map(|status| expr.status_in.contains(&status))
            .unwrap_or(false);
    }

    !has_leaf || leaf_matched
}

fn field_value(
    expr: &MatchExpr,
    default_field: &str,
    field_lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let field = expr.field.as_deref().unwrap_or(default_field);
    field_lookup(field)
}

fn numeric_compare(value: Option<String>, operator: &str, expected: f64) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Ok(value) = value.parse::<f64>() else {
        return false;
    };
    match operator {
        "gt" => value > expected,
        "gte" => value >= expected,
        "lt" => value < expected,
        "lte" => value <= expected,
        _ => false,
    }
}

/// contains/contains_any 的归一化匹配视图。
/// 输入已 lowercase；'+' 视作空格（form 编码），随后做一次完整 percent-decode
/// （%XX 十六进制大小写不敏感，非法序列原样保留）。
/// 只解码一次以避免二次解码歧义（%25 双重编码变体由规则自身枚举覆盖）。
fn normalize_match_text(value: &str) -> String {
    percent_decode_text(&value.replace('+', " "))
}

/// 单次 percent-decode：%XX（十六进制大小写不敏感）解码为对应字节；
/// 遇到非法序列（如 %G1、结尾截断的 %2）保留原文，不做任何猜测。
pub fn percent_decode_text(input: &str) -> String {
    percent_decode_once(input)
}

/// 单次 percent-decode：%XX（十六进制大小写不敏感）解码为对应字节；
/// 遇到非法序列（如 %G1、结尾截断的 %2）保留原文，不做任何猜测。
fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                output.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn event_field(event: &HttpLogEvent, field: &str) -> Option<String> {
    event_field_with_aggregation(event, None, field)
}

pub fn event_field_with_aggregation(
    event: &HttpLogEvent,
    aggregation: Option<&EventAggregation>,
    field: &str,
) -> Option<String> {
    if let Some(value) = aggregation.and_then(|aggregation| aggregation.field_value(field)) {
        return Some(value);
    }

    match field {
        "timestamp" => event.timestamp.clone(),
        "source_file" => Some(event.source_file.clone()),
        "line_number" => Some(event.line_number.to_string()),
        "remote_ip" => event.effective_remote_ip().map(str::to_string),
        "logged_remote_ip" => event.remote_ip.clone(),
        "xff_ip" => event.xff_ip.clone(),
        "inferred_client_ip" => event.inferred_client_ip.clone(),
        "proxy_ip" => event.proxy_ip.clone(),
        "client_ip_source" => event.client_ip_source.clone(),
        "method" => event.method.clone(),
        "scheme" => event.scheme.clone(),
        "host" => event.host.clone(),
        "uri_path" => event.uri_path.clone(),
        "uri_query" => event.uri_query.clone(),
        "uri" => Some(format!(
            "{}{}",
            event.uri_path.as_deref().unwrap_or_default(),
            event
                .uri_query
                .as_ref()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        )),
        "status" => event.status.map(|status| status.to_string()),
        "bytes_sent" => event.bytes_sent.map(|bytes| bytes.to_string()),
        "referer" => event.referer.clone(),
        "user_agent" => event.user_agent.clone(),
        "request_time" => event.request_time.map(|value| value.to_string()),
        "upstream_status" => event.upstream_status.clone(),
        "upstream_time" => event.upstream_time.map(|value| value.to_string()),
        "parser_name" => Some(event.parser_name.clone()),
        "raw_hash" => Some(event.raw_hash.clone()),
        "request" => Some(format!(
            "{} {} {} {}",
            event.method.as_deref().unwrap_or_default(),
            event.uri_path.as_deref().unwrap_or_default(),
            event.uri_query.as_deref().unwrap_or_default(),
            event.user_agent.as_deref().unwrap_or_default()
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::rule_model::MatchExpr;
    use crate::model::HttpLogEvent;

    #[test]
    fn matches_contains_any_case_insensitive() {
        let event = event("/search", Some("q=UNION+SELECT"));
        let expr = MatchExpr {
            field: Some("uri_query".to_string()),
            contains_any: vec!["union select".to_string(), "information_schema".to_string()],
            ..MatchExpr::default()
        };

        assert!(matches_event(&expr, &event));
    }

    #[test]
    fn percent_decode_handles_mixed_case_and_invalid_sequences() {
        // 大小写不敏感 %XX 全量解码。
        let first = event("/search", Some("q=1%2fUNION%2FSELECT"));
        let expr = MatchExpr {
            field: Some("uri_query".to_string()),
            contains: Some("/union/select".to_string()),
            ..MatchExpr::default()
        };
        assert!(matches_event(&expr, &first));

        // 解码视图覆盖未知字段的编码变形（如 SQL 注释符）。
        let second = event("/search", Some("q=1%2f%2A+union"));
        let expr = MatchExpr {
            field: Some("uri_query".to_string()),
            contains: Some("/* union".to_string()),
            ..MatchExpr::default()
        };
        assert!(matches_event(&expr, &second));

        // 非法序列保留原文，不产生错误解码。
        assert_eq!(normalize_match_text("a%zz%2fb"), "a%zz/b");
        assert_eq!(normalize_match_text("trailing%2"), "trailing%2");
    }

    #[test]
    fn cached_regex_reuses_compiled_pattern() {
        let first = cached_regex("(?i)union\\s+select").unwrap();
        let second = cached_regex("(?i)union\\s+select").unwrap();
        assert!(first.is_match("x UNION SELECT y"));
        assert!(second.is_match("x union select y"));
        assert!(cached_regex("(unclosed").is_none());
    }

    fn event(path: &str, query: Option<&str>) -> HttpLogEvent {
        HttpLogEvent {
            timestamp: Some("2026-05-15T00:00:00Z".to_string()),
            source_file: "access.log".to_string(),
            line_number: 1,
            remote_ip: Some("127.0.0.1".to_string()),
            xff_ip: None,
            inferred_client_ip: None,
            proxy_ip: None,
            client_ip_source: None,
            method: Some("GET".to_string()),
            scheme: None,
            host: None,
            uri_path: Some(path.to_string()),
            uri_query: query.map(str::to_string),
            status: Some(200),
            bytes_sent: Some(1),
            referer: None,
            user_agent: Some("test".to_string()),
            request_time: None,
            upstream_status: None,
            upstream_time: None,
            raw_hash: "hash".to_string(),
            parser_name: "test".to_string(),
            parse_confidence: 1.0,
        }
    }
}
