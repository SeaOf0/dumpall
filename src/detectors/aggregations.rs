use crate::model::HttpLogEvent;
use crate::time_utils;

#[derive(Debug, Clone, Default)]
pub struct EventAggregation {
    pub same_ip_request_count_5m: u64,
    pub same_ip_same_path_count_5m: u64,
    pub same_ip_404_count_5m: u64,
    pub same_ip_login_fail_count_5m: u64,
}

impl EventAggregation {
    pub fn field_value(&self, field: &str) -> Option<String> {
        match field {
            "same_ip_request_count_5m" => Some(self.same_ip_request_count_5m.to_string()),
            "same_ip_same_path_count_5m" => Some(self.same_ip_same_path_count_5m.to_string()),
            "same_ip_404_count_5m" => Some(self.same_ip_404_count_5m.to_string()),
            "same_ip_login_fail_count_5m" => Some(self.same_ip_login_fail_count_5m.to_string()),
            _ => None,
        }
    }
}

/// 先按 remote_ip 分桶（BTreeMap<String, Vec<index>>）再桶内两两比较，
/// 跨桶直接跳过，避免全量 O(n²)；同桶内 O(k²) 可接受。
/// 对比计数语义不变（含自身）。
pub fn build_event_aggregations(events: &[HttpLogEvent]) -> Vec<EventAggregation> {
    let parsed_times: Vec<_> = events
        .iter()
        .map(|event| {
            event
                .timestamp
                .as_deref()
                .and_then(|value| time_utils::parse_datetime(value).ok())
        })
        .collect();

    let mut by_ip: std::collections::BTreeMap<String, Vec<usize>> =
        std::collections::BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        if let Some(remote_ip) = event.effective_remote_ip() {
            by_ip.entry(remote_ip.to_string()).or_default().push(index);
        }
    }

    let mut aggregations = vec![EventAggregation::default(); events.len()];
    for indices in by_ip.values() {
        for &index in indices {
            aggregations[index] = aggregate_for(index, &events[index], indices, events, &parsed_times);
        }
    }
    aggregations
}

/// 5 分钟桶：时间缺失或不可解析时返回 None（无时间事件不进 0 桶）。
pub fn five_minute_bucket(event: &HttpLogEvent) -> Option<i64> {
    event
        .timestamp
        .as_deref()
        .and_then(|value| time_utils::parse_datetime(value).ok())
        .map(|timestamp| timestamp.unix_timestamp() / 300)
}

fn aggregate_for(
    index: usize,
    event: &HttpLogEvent,
    same_ip_indices: &[usize],
    events: &[HttpLogEvent],
    parsed_times: &[Option<time::OffsetDateTime>],
) -> EventAggregation {
    let mut aggregation = EventAggregation::default();

    for &other_index in same_ip_indices {
        let other = &events[other_index];
        if !inside_five_minutes(
            parsed_times.get(index).and_then(|value| *value),
            parsed_times.get(other_index).and_then(|value| *value),
        ) {
            continue;
        }

        aggregation.same_ip_request_count_5m += 1;
        if event.uri_path == other.uri_path {
            aggregation.same_ip_same_path_count_5m += 1;
        }
        if other.status == Some(404) {
            aggregation.same_ip_404_count_5m += 1;
        }
        if is_login_failure(other) {
            aggregation.same_ip_login_fail_count_5m += 1;
        }
    }

    aggregation
}

/// 任一侧时间缺失/不可解析 → 不计入 5 分钟聚合（返回 false），
/// 防止无时间戳数据把窗口计数膨胀为全量。
fn inside_five_minutes(
    left: Option<time::OffsetDateTime>,
    right: Option<time::OffsetDateTime>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => (left - right).whole_seconds().abs() <= 300,
        _ => false,
    }
}

fn is_login_failure(event: &HttpLogEvent) -> bool {
    let is_failure_status = matches!(event.status, Some(401 | 403 | 429));
    if !is_failure_status {
        return false;
    }
    event
        .uri_path
        .as_deref()
        .map(|path| {
            let path = path.to_ascii_lowercase();
            path.contains("login")
                || path.contains("signin")
                || path.contains("auth")
                || path.contains("admin")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(ip: &str, timestamp: Option<&str>, path: &str, status: u16) -> HttpLogEvent {
        HttpLogEvent {
            timestamp: timestamp.map(str::to_string),
            source_file: "access.log".to_string(),
            line_number: 1,
            remote_ip: Some(ip.to_string()),
            xff_ip: None,
            inferred_client_ip: None,
            proxy_ip: None,
            client_ip_source: None,
            method: Some("GET".to_string()),
            scheme: None,
            host: None,
            uri_path: Some(path.to_string()),
            uri_query: None,
            status: Some(status),
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

    #[test]
    fn missing_timestamps_do_not_inflate_window_counts() {
        let events = vec![
            event("203.0.113.1", Some("2026-05-15T08:00:00Z"), "/a", 200),
            // 同 IP 但无时间戳：不应计入有时间事件的 5 分钟窗口。
            event("203.0.113.1", None, "/a", 200),
            event("203.0.113.1", Some("garbage-time"), "/a", 200),
            // 远端 IP 的事件不受影响。
            event("203.0.113.2", Some("2026-05-15T08:00:10Z"), "/b", 200),
        ];
        let aggregations = build_event_aggregations(&events);

        // 有时间事件只统计同 IP 有时间的 1 条（含自身）。
        assert_eq!(aggregations[0].same_ip_request_count_5m, 1);
        // 无时间事件自身聚合为 0（两侧任一缺失即不计入）。
        assert_eq!(aggregations[1].same_ip_request_count_5m, 0);
        assert_eq!(aggregations[2].same_ip_request_count_5m, 0);
        // 不同 IP 不串桶。
        assert_eq!(aggregations[3].same_ip_request_count_5m, 1);

        // 同 IP 同时有 3 条带时间事件时（含自身）为 3。
        let events = vec![
            event("203.0.113.1", Some("2026-05-15T08:00:00Z"), "/a", 200),
            event("203.0.113.1", Some("2026-05-15T08:01:00Z"), "/a", 200),
            event("203.0.113.1", Some("2026-05-15T08:02:00Z"), "/a", 200),
        ];
        let aggregations = build_event_aggregations(&events);
        assert_eq!(aggregations[0].same_ip_request_count_5m, 3);
        assert_eq!(aggregations[0].same_ip_same_path_count_5m, 3);
    }

    #[test]
    fn five_minute_bucket_is_none_without_parseable_time() {
        assert!(five_minute_bucket(&event("1.1.1.1", None, "/", 200)).is_none());
        assert!(five_minute_bucket(&event("1.1.1.1", Some("bad"), "/", 200)).is_none());
        let expected = time_utils::parse_datetime("2026-05-15T08:04:59Z")
            .unwrap()
            .unix_timestamp()
            / 300;
        assert_eq!(
            five_minute_bucket(&event("1.1.1.1", Some("2026-05-15T08:04:59Z"), "/", 200)),
            Some(expected)
        );
    }
}
