use std::path::Path;

use crate::model::HttpLogEvent;

use super::access_log::{non_dash, sha256_hex};

pub fn parse_line(
    source_file: &Path,
    line_number: u64,
    line: &str,
    fields: Option<&[String]>,
) -> std::result::Result<HttpLogEvent, String> {
    let fields =
        fields.ok_or_else(|| "IIS #Fields header was not seen before data line".to_string())?;
    let values: Vec<&str> = line.split_whitespace().collect();
    // 字段数与 #Fields 声明不一致时整行报错,不做静默错位取列
    // (取错列会把 IP/状态/UA 串位,取证语义完全失真)。
    if values.len() != fields.len() {
        return Err(format!(
            "IIS row has {} fields but #Fields declares {}",
            values.len(),
            fields.len()
        ));
    }

    let get = |name: &str| -> Option<&str> {
        fields
            .iter()
            .position(|field| field.eq_ignore_ascii_case(name))
            .and_then(|index| values.get(index).copied())
    };

    let timestamp = match (get("date"), get("time")) {
        (Some(date), Some(time)) => crate::parsers::time::parse_iis_datetime(date, time),
        _ => None,
    };
    let method = get("cs-method").and_then(non_dash);
    let uri_path = get("cs-uri-stem").and_then(non_dash);
    let uri_query = get("cs-uri-query").and_then(non_dash);
    let status = get("sc-status").and_then(|value| value.parse::<u16>().ok());
    let bytes_sent = get("sc-bytes").and_then(|value| value.parse::<u64>().ok());
    let request_time = get("time-taken")
        .and_then(|value| value.parse::<f64>().ok())
        .map(|millis| millis / 1000.0);

    Ok(HttpLogEvent {
        timestamp,
        source_file: source_file.display().to_string(),
        line_number,
        remote_ip: get("c-ip").and_then(non_dash),
        xff_ip: get("x-forwarded-for").and_then(non_dash),
        inferred_client_ip: None,
        proxy_ip: None,
        client_ip_source: None,
        method,
        scheme: None,
        host: get("cs-host").and_then(non_dash),
        uri_path,
        uri_query,
        status,
        bytes_sent,
        referer: get("cs(Referer)").and_then(non_dash),
        user_agent: get("cs(User-Agent)").and_then(non_dash),
        request_time,
        upstream_status: None,
        upstream_time: None,
        raw_hash: sha256_hex(line.as_bytes()),
        parser_name: "iis_w3c".to_string(),
        parse_confidence: 0.9,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iis_w3c_line() {
        let fields =
            "date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent)"
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
        let event = parse_line(
            Path::new("u_ex260515.log"),
            3,
            "2026-05-15 08:00:00 203.0.113.10 GET /login.aspx user=1 200 512 Mozilla/5.0",
            Some(&fields),
        )
        .unwrap();

        assert_eq!(event.remote_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(event.uri_path.as_deref(), Some("/login.aspx"));
        assert_eq!(event.uri_query.as_deref(), Some("user=1"));
        assert_eq!(event.status, Some(200));
    }

    #[test]
    fn field_count_mismatch_is_an_error() {
        // 多列/少列都拒绝解析,不得静默错位取列
        let fields =
            "date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent)"
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();

        let missing = parse_line(
            Path::new("u_ex260515.log"),
            3,
            "2026-05-15 08:00:00 203.0.113.10 GET /login.aspx user=1 200",
            Some(&fields),
        );
        assert!(missing.is_err());

        let extra = parse_line(
            Path::new("u_ex260515.log"),
            4,
            "2026-05-15 08:00:00 203.0.113.10 GET /login.aspx user=1 200 512 Mozilla/5.0 extra",
            Some(&fields),
        );
        assert!(extra.is_err());
    }
}
