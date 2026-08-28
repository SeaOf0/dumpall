use std::path::Path;

use serde_json::Value;

use crate::model::HttpLogEvent;

use super::access_log::{non_dash, sha256_hex, split_uri};

pub fn parse_line(
    source_file: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<HttpLogEvent, String> {
    let value: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "JSON log line is not an object".to_string())?;

    let timestamp =
        get_string(&value, &["@timestamp", "timestamp", "time", "ts"]).and_then(|time| {
            crate::time_utils::parse_datetime(&time)
                .ok()
                .map(crate::time_utils::format_iso)
                .or(Some(time))
        });
    let request = get_string(&value, &["request", "request_line"]);
    let method = get_string(&value, &["method", "request_method"]).or_else(|| {
        request
            .as_deref()
            .and_then(|request| request.split_whitespace().next().map(str::to_string))
    });
    let uri = get_string(&value, &["uri", "url", "request_uri", "path"]).or_else(|| {
        request
            .as_deref()
            .and_then(|request| request.split_whitespace().nth(1).map(str::to_string))
    });
    let (uri_path, uri_query) = uri.as_deref().map(split_uri).unwrap_or((None, None));

    if method.is_none() || uri_path.is_none() {
        return Err("JSON log did not expose method and URI/path".to_string());
    }

    Ok(HttpLogEvent {
        timestamp,
        source_file: source_file.display().to_string(),
        line_number,
        remote_ip: get_string(
            &value,
            &["remote_ip", "client_ip", "ip", "c_ip", "remote_addr"],
        ),
        xff_ip: get_string(
            &value,
            &[
                "xff",
                "x_forwarded_for",
                "x-forwarded-for",
                "x_real_ip",
                "x-real-ip",
                "forwarded",
                "cf_connecting_ip",
                "cf-connecting-ip",
                "true_client_ip",
                "true-client-ip",
                "x_client_ip",
                "x-client-ip",
            ],
        ),
        inferred_client_ip: None,
        proxy_ip: None,
        client_ip_source: None,
        method,
        scheme: get_string(&value, &["scheme", "protocol"]),
        host: get_string(&value, &["host", "http_host"]),
        uri_path,
        uri_query,
        status: get_u16(&value, &["status", "status_code", "sc_status"]),
        bytes_sent: get_u64(
            &value,
            &["bytes", "bytes_sent", "body_bytes_sent", "sc_bytes"],
        ),
        referer: get_string(&value, &["referer", "referrer", "http_referer"]),
        user_agent: get_string(
            &value,
            &["user_agent", "user-agent", "http_user_agent", "ua"],
        ),
        request_time: get_f64(&value, &["request_time", "duration", "time_taken"]),
        upstream_status: get_string(&value, &["upstream_status"]),
        upstream_time: get_f64(&value, &["upstream_time"]),
        raw_hash: sha256_hex(line.as_bytes()),
        parser_name: "json_access".to_string(),
        parse_confidence: if object.len() >= 4 { 0.86 } else { 0.7 },
    })
}

fn get_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(*key) {
            if let Some(text) = found.as_str().and_then(non_dash) {
                return Some(text);
            }
            if found.is_number() || found.is_boolean() {
                return Some(found.to_string());
            }
        }
    }
    None
}

fn get_u16(value: &Value, keys: &[&str]) -> Option<u16> {
    keys.iter()
        .find_map(|key| value.get(*key))
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str()?.parse::<u64>().ok())
        })
        .and_then(|value| u16::try_from(value).ok())
}

fn get_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key))
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str()?.parse::<u64>().ok())
        })
}

fn get_f64(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| value.get(*key))
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str()?.parse::<f64>().ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_access_log() {
        let event = parse_line(
            Path::new("access.jsonl"),
            1,
            r#"{"timestamp":"2026-05-15T08:00:00Z","remote_ip":"198.51.100.10","method":"POST","uri":"/api/login?u=a","status":403,"bytes":42,"user_agent":"test"}"#,
        )
        .unwrap();

        assert_eq!(event.remote_ip.as_deref(), Some("198.51.100.10"));
        assert_eq!(event.method.as_deref(), Some("POST"));
        assert_eq!(event.uri_path.as_deref(), Some("/api/login"));
        assert_eq!(event.uri_query.as_deref(), Some("u=a"));
        assert_eq!(event.status, Some(403));
    }
}
