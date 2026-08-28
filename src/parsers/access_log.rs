use std::path::Path;

use sha2::{Digest, Sha256};

use crate::model::HttpLogEvent;

pub fn parse_common_line(
    source_file: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<HttpLogEvent, String> {
    let remote_ip = line
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "missing remote IP".to_string())?
        .to_string();
    let time_raw = between(line, '[', ']').ok_or_else(|| "missing timestamp".to_string())?;
    let timestamp =
        crate::parsers::time::parse_clf_time(time_raw).or_else(|| Some(time_raw.to_string()));

    let after_time = line
        .split_once(']')
        .map(|(_, rest)| rest)
        .ok_or_else(|| "missing request after timestamp".to_string())?;
    // 请求行按未转义引号定界:请求内含 \" 时不会提前截断
    let request_start = after_time
        .find('"')
        .map(|position| position + 1)
        .ok_or_else(|| "missing quoted request".to_string())?;
    let request_end = find_unescaped_quote(after_time, request_start)
        .ok_or_else(|| "missing quoted request".to_string())?;
    let request = &after_time[request_start..request_end];
    let request_parts: Vec<&str> = request.split_whitespace().collect();
    if request_parts.len() < 2 {
        return Err("request does not contain method and URI".to_string());
    }
    let (method, uri) = split_request_line(&request_parts);
    let (uri_path, uri_query) = split_uri(&uri);

    let after_request = &after_time[request_end + 1..];
    let mut tail_parts = after_request.split_whitespace();
    let status = tail_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok());
    let bytes_sent = tail_parts
        .next()
        .filter(|value| *value != "-")
        .and_then(|value| value.parse::<u64>().ok());

    let quoted = quoted_values(after_request);
    let referer = quoted.first().and_then(|value| non_dash(value));
    let user_agent = quoted.get(1).and_then(|value| non_dash(value));

    Ok(HttpLogEvent {
        timestamp,
        source_file: source_file.display().to_string(),
        line_number,
        remote_ip: Some(remote_ip),
        xff_ip: None,
        inferred_client_ip: None,
        proxy_ip: None,
        client_ip_source: None,
        method: Some(method),
        scheme: None,
        host: None,
        uri_path,
        uri_query,
        status,
        bytes_sent,
        referer,
        user_agent,
        request_time: None,
        upstream_status: None,
        upstream_time: None,
        raw_hash: sha256_hex(line.as_bytes()),
        parser_name: "common_access".to_string(),
        parse_confidence: 0.86,
    })
}

fn between(value: &str, open: char, close: char) -> Option<&str> {
    let start = value.find(open)? + open.len_utf8();
    let end = value[start..].find(close)? + start;
    Some(&value[start..end])
}

/// 从 `from` 开始查找下一个未被反斜杠转义的双引号字节位置。
/// 反斜杠是 ASCII 字节,不会出现在多字节字符序列内部,切片边界安全。
fn find_unescaped_quote(value: &str, from: usize) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut cursor = from;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' && cursor + 1 < bytes.len() {
            cursor += 2;
            continue;
        }
        if bytes[cursor] == b'"' {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

/// 请求行 = 方法 + URI(可能含空格)+ 协议:
/// method 取第一个 token(须是合法 HTTP 动词),protocol 取最后一个(HTTP/ 开头时),
/// URI 为中间所有 token 用单个空格 join,避免含空格 URI 被截断。
/// method 不合法时回退原逻辑(第一、二个 token)。
fn split_request_line(request_parts: &[&str]) -> (String, String) {
    let method = request_parts[0];
    if request_parts.len() >= 3
        && is_http_method(method)
        && request_parts
            .last()
            .is_some_and(|last| last.starts_with("HTTP/"))
    {
        let uri = request_parts[1..request_parts.len() - 1].join(" ");
        return (method.to_string(), uri);
    }
    (request_parts[0].to_string(), request_parts[1].to_string())
}

/// 合法 HTTP 动词(不区分大小写):常见列表 + 长度启发(纯 ASCII 字母且 <= 16)。
fn is_http_method(value: &str) -> bool {
    const KNOWN: [&str; 20] = [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
        "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "PURGE", "REPORT",
        "SEARCH", "MKCALENDAR",
    ];
    let upper = value.to_ascii_uppercase();
    KNOWN.iter().any(|known| *known == upper)
        || (!value.is_empty()
            && value.len() <= 16
            && value.chars().all(|ch| ch.is_ascii_alphabetic()))
}

pub fn split_uri(uri: &str) -> (Option<String>, Option<String>) {
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    (
        non_dash(path),
        if query.is_empty() {
            None
        } else {
            Some(query.to_string())
        },
    )
}

fn quoted_values(value: &str) -> Vec<String> {
    // 逐字段按未转义引号定界:`\"` 转义的引号不终止字段,避免 referer/UA 错位。
    let mut values = Vec::new();
    let mut cursor = 0_usize;
    while let Some(start) = value[cursor..].find('"').map(|offset| cursor + offset + 1) {
        let Some(end) = find_unescaped_quote(value, start) else {
            break;
        };
        values.push(value[start..end].to_string());
        cursor = end + 1;
    }
    values
}

pub fn non_dash(value: &str) -> Option<String> {
    if value.is_empty() || value == "-" {
        None
    } else {
        Some(value.to_string())
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_combined_access_log() {
        let event = parse_common_line(
            Path::new("access.log"),
            1,
            r#"127.0.0.1 - - [15/May/2026:08:00:00 +0000] "GET /index.php?a=1 HTTP/1.1" 200 123 "-" "curl/8.0""#,
        )
        .unwrap();

        assert_eq!(event.remote_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(event.method.as_deref(), Some("GET"));
        assert_eq!(event.uri_path.as_deref(), Some("/index.php"));
        assert_eq!(event.uri_query.as_deref(), Some("a=1"));
        assert_eq!(event.status, Some(200));
        assert_eq!(event.bytes_sent, Some(123));
        assert_eq!(event.user_agent.as_deref(), Some("curl/8.0"));
    }

    #[test]
    fn keeps_uri_with_spaces() {
        // 含空格 URI:method=首个合法动词,protocol=最后一个 HTTP/*,URI=中间 join
        let event = parse_common_line(
            Path::new("access.log"),
            1,
            r#"127.0.0.1 - - [15/May/2026:08:00:00 +0000] "GET /upload/my file name.png?a=1 HTTP/1.1" 200 10"#,
        )
        .unwrap();
        assert_eq!(event.method.as_deref(), Some("GET"));
        assert_eq!(event.uri_path.as_deref(), Some("/upload/my file name.png"));
        assert_eq!(event.uri_query.as_deref(), Some("a=1"));
        assert_eq!(event.status, Some(200));
    }

    #[test]
    fn non_method_request_falls_back_to_original_split() {
        // 首个 token 不是 HTTP 动词:按原逻辑取第一、二个 token
        let event = parse_common_line(
            Path::new("access.log"),
            1,
            r#"127.0.0.1 - - [15/May/2026:08:00:00 +0000] "\x16\x03\x01 /binary HTTP/1.1" 400 0"#,
        )
        .unwrap();
        assert_eq!(event.method.as_deref(), Some("\\x16\\x03\\x01"));
        assert_eq!(event.uri_path.as_deref(), Some("/binary"));
    }

    #[test]
    fn escaped_quotes_do_not_break_field_alignment() {
        // referer/UA 含 \" 转义:字段不错位,status 不被吃掉
        let event = parse_common_line(
            Path::new("access.log"),
            1,
            r#"127.0.0.1 - - [15/May/2026:08:00:00 +0000] "GET /ok HTTP/1.1" 200 12 "\"quoted\" referer" "Mozilla \"5.0\"""#,
        )
        .unwrap();
        assert_eq!(event.status, Some(200));
        assert_eq!(event.referer.as_deref(), Some(r#"\"quoted\" referer"#));
        assert_eq!(event.user_agent.as_deref(), Some(r#"Mozilla \"5.0\""#));
    }

    #[test]
    fn request_with_escaped_quote_keeps_status() {
        // 请求行内含 \" :请求提取按未转义引号定界,其后的 status 仍能取到
        let event = parse_common_line(
            Path::new("access.log"),
            1,
            r#"127.0.0.1 - - [15/May/2026:08:00:00 +0000] "GET /a\"b?x=1 HTTP/1.1" 500 3"#,
        )
        .unwrap();
        assert_eq!(event.status, Some(500));
        assert_eq!(event.uri_path.as_deref(), Some(r#"/a\"b"#));
        assert_eq!(event.uri_query.as_deref(), Some("x=1"));
    }
}
