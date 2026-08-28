use std::net::IpAddr;

use crate::model::HttpLogEvent;

use super::identity::{parse_ip_token, Cidr};

#[derive(Debug, Default)]
pub struct TrustedProxyReport {
    pub inferences: usize,
    pub invalid_entries: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrustedProxySet {
    cidrs: Vec<Cidr>,
}

impl TrustedProxySet {
    pub fn from_values(values: &[String]) -> (Self, Vec<String>) {
        let mut cidrs = Vec::new();
        let mut invalid = Vec::new();
        for value in values {
            match Cidr::parse(value) {
                Ok(cidr) => cidrs.push(cidr),
                Err(error) => invalid.push(format!("{value}: {error}")),
            }
        }
        (Self { cidrs }, invalid)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }
}

pub fn apply_trusted_proxy(
    events: &mut [HttpLogEvent],
    trusted_proxy_values: &[String],
) -> TrustedProxyReport {
    let (trusted, invalid_entries) = TrustedProxySet::from_values(trusted_proxy_values);
    if trusted.is_empty() {
        return TrustedProxyReport {
            inferences: 0,
            invalid_entries,
        };
    }

    let mut inferences = 0;
    for event in events {
        let Some(remote_ip_text) = event.remote_ip.as_deref() else {
            continue;
        };
        let Some(remote_ip) = parse_ip_token(remote_ip_text) else {
            continue;
        };
        if !trusted.contains(remote_ip) {
            continue;
        }
        let Some(header) = event.xff_ip.as_deref() else {
            continue;
        };
        let Some(client_ip) = extract_client_ip(header, &trusted) else {
            continue;
        };
        if client_ip == remote_ip {
            continue;
        }

        event.proxy_ip = Some(remote_ip_text.to_string());
        event.inferred_client_ip = Some(client_ip.to_string());
        event.client_ip_source = Some("trusted_proxy_header".to_string());
        inferences += 1;
    }

    TrustedProxyReport {
        inferences,
        invalid_entries,
    }
}

fn extract_client_ip(header: &str, trusted: &TrustedProxySet) -> Option<IpAddr> {
    if header.to_ascii_lowercase().contains("for=") {
        if let Some(ip) = extract_forwarded_for(header, trusted) {
            return Some(ip);
        }
    }

    for part in header.split(',') {
        let Some(ip) = parse_ip_token(part) else {
            continue;
        };
        if !trusted.contains(ip) {
            return Some(ip);
        }
    }

    // 整条链都是可信代理时没有可推断的真实客户端:
    // 不再回退取第一个 IP(那是代理自身),返回 None,调用侧保持原 remote_ip。
    None
}

fn extract_forwarded_for(header: &str, trusted: &TrustedProxySet) -> Option<IpAddr> {
    for element in header.split(',') {
        for attribute in element.split(';') {
            let Some((name, value)) = attribute.split_once('=') else {
                continue;
            };
            if !name.trim().eq_ignore_ascii_case("for") {
                continue;
            }
            let value = value.trim().trim_matches('"');
            let Some(ip) = parse_ip_token(value) else {
                continue;
            };
            if !trusted.contains(ip) {
                return Some(ip);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_trusted_proxy_remote_can_set_inferred_client() {
        let mut events = vec![HttpLogEvent {
            timestamp: Some("2026-05-15T00:00:00Z".to_string()),
            source_file: "access.log".to_string(),
            line_number: 1,
            remote_ip: Some("10.0.0.5".to_string()),
            xff_ip: Some("203.0.113.10, 10.0.0.5".to_string()),
            inferred_client_ip: None,
            proxy_ip: None,
            client_ip_source: None,
            method: Some("GET".to_string()),
            scheme: None,
            host: None,
            uri_path: Some("/".to_string()),
            uri_query: None,
            status: Some(200),
            bytes_sent: None,
            referer: None,
            user_agent: None,
            request_time: None,
            upstream_status: None,
            upstream_time: None,
            raw_hash: "hash".to_string(),
            parser_name: "fixture".to_string(),
            parse_confidence: 1.0,
        }];

        let report = apply_trusted_proxy(&mut events, &["10.0.0.0/8".to_string()]);

        assert_eq!(report.inferences, 1);
        assert_eq!(events[0].proxy_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(events[0].effective_remote_ip(), Some("203.0.113.10"));
    }

    #[test]
    fn all_trusted_chain_does_not_fabricate_client_ip() {
        // 整条 XFF 链都在可信代理网段内:没有真实客户端可推断,
        // 不能回退把第一个(代理自身的)IP 当客户端。
        let mut events = vec![HttpLogEvent {
            timestamp: Some("2026-05-15T00:00:00Z".to_string()),
            source_file: "access.log".to_string(),
            line_number: 1,
            remote_ip: Some("10.0.0.5".to_string()),
            xff_ip: Some("10.0.0.9, 10.0.0.5".to_string()),
            inferred_client_ip: None,
            proxy_ip: None,
            client_ip_source: None,
            method: Some("GET".to_string()),
            scheme: None,
            host: None,
            uri_path: Some("/".to_string()),
            uri_query: None,
            status: Some(200),
            bytes_sent: None,
            referer: None,
            user_agent: None,
            request_time: None,
            upstream_status: None,
            upstream_time: None,
            raw_hash: "hash".to_string(),
            parser_name: "fixture".to_string(),
            parse_confidence: 1.0,
        }];

        let report = apply_trusted_proxy(&mut events, &["10.0.0.0/8".to_string()]);

        assert_eq!(report.inferences, 0);
        assert!(events[0].inferred_client_ip.is_none());
        assert_eq!(events[0].effective_remote_ip(), Some("10.0.0.5"));
    }
}
