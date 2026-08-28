use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::{DumpallError, Result};
use crate::model::HttpLogEvent;

use super::rule_model::DetectionRule;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Allowlist {
    #[serde(default)]
    pub paths: PathAllowlist,
    #[serde(default)]
    pub source_ips: SourceIpAllowlist,
    #[serde(default)]
    pub user_agents: UserAgentAllowlist,
    #[serde(default)]
    pub rules: RuleAllowlist,
    #[serde(default)]
    pub suppress: Vec<SuppressRule>,
    /// 配置中发现的问题（无法解析的 IP/CIDR 条目等），加载时生成；
    /// 不导致运行失败，但会写入日志与 notes，不再静默失效。
    #[serde(skip)]
    pub warnings: Vec<String>,
    /// source_ips.internal 解析出的 CIDR（统一 128 位 v6 表示，v4 已映射）。
    #[serde(skip)]
    internal_networks: Vec<InternalNetwork>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PathAllowlist {
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub prefix: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SourceIpAllowlist {
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub internal: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserAgentAllowlist {
    #[serde(default)]
    pub contains: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleAllowlist {
    #[serde(default)]
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SuppressRule {
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub source_ip: Option<String>,
    #[serde(default)]
    pub user_agent_contains: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl Allowlist {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let content = fs::read_to_string(path)?;
        let mut allowlist: Self = toml::from_str(&content).map_err(|error| {
            DumpallError::invalid_argument(
                "allowlist",
                format!("{} is not valid TOML: {error}", path.display()),
            )
        })?;
        allowlist.finalize();
        Ok(allowlist)
    }

    /// 解析 internal CIDR 与 exact IP，收集无法解析条目的警告。
    fn finalize(&mut self) {
        let mut warnings = Vec::new();
        let mut networks = Vec::new();
        for entry in &self.source_ips.internal {
            match parse_internal_network(entry) {
                Some(network) => networks.push(network),
                None => warnings.push(format!(
                    "source_ips.internal entry `{entry}` is not a parseable IP or CIDR and will not match anything"
                )),
            }
        }
        for entry in &self.source_ips.exact {
            if parse_ip_bytes(entry).is_none() {
                warnings.push(format!(
                    "source_ips.exact entry `{entry}` is not a parseable IP address and will only match by literal string comparison"
                ));
            }
        }
        self.internal_networks = networks;
        self.warnings = warnings;
    }

    pub fn rule_disabled(&self, rule_id: &str) -> bool {
        self.rules
            .disabled
            .iter()
            .any(|disabled| disabled.eq_ignore_ascii_case(rule_id))
    }

    pub fn suppresses(&self, rule: &DetectionRule, event: &HttpLogEvent) -> bool {
        self.suppresses_values(
            rule,
            event.uri_path.as_deref(),
            event.effective_remote_ip(),
            event.user_agent.as_deref(),
        )
    }

    pub fn suppresses_values(
        &self,
        rule: &DetectionRule,
        path: Option<&str>,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> bool {
        if self.rule_disabled(&rule.id) {
            return true;
        }
        if self.path_suppressed(path) {
            return true;
        }
        if self.ip_suppressed(source_ip) {
            return true;
        }
        if self.user_agent_suppressed(user_agent) {
            return true;
        }
        self.suppress.iter().any(|suppress| {
            suppress
                .rule_id
                .as_deref()
                .map(|id| id.eq_ignore_ascii_case(&rule.id))
                .unwrap_or(true)
                && suppress
                    .path_prefix
                    .as_deref()
                    .map(|prefix| {
                        path.map(|path| {
                            normalize_allowlist_path(path)
                                .starts_with(&normalize_allowlist_path(prefix))
                        })
                        .unwrap_or(false)
                    })
                    .unwrap_or(true)
                && suppress
                    .source_ip
                    .as_deref()
                    .map(|ip| source_ip == Some(ip))
                    .unwrap_or(true)
                && suppress
                    .user_agent_contains
                    .as_deref()
                    .map(|needle| {
                        user_agent
                            .map(|ua| {
                                ua.to_ascii_lowercase()
                                    .contains(&needle.to_ascii_lowercase())
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(true)
        })
    }

    fn path_suppressed(&self, path: Option<&str>) -> bool {
        let Some(path) = path else {
            return false;
        };
        // 前缀/精确匹配前先做归一化（URL decode + 去除 ./ ../ 段 + 合并多斜杠），
        // 防 /api/health 前缀抑制 /api/health/../admin 这类穿越形态。
        let normalized = normalize_allowlist_path(path);
        self.paths.exact.iter().any(|item| {
            item == path || normalize_allowlist_path(item) == normalized
        }) || self
            .paths
            .prefix
            .iter()
            .any(|prefix| normalized.starts_with(&normalize_allowlist_path(prefix)))
    }

    fn ip_suppressed(&self, ip: Option<&str>) -> bool {
        let Some(ip) = ip else {
            return false;
        };
        // exact：字符串等值，或解析后的地址等值（含 v4-mapped v6 等价）。
        if let Some(candidate) = parse_ip_bytes(ip) {
            if self.source_ips.exact.iter().any(|item| {
                item == ip || parse_ip_bytes(item) == Some(candidate)
            }) {
                return true;
            }
            // internal：真 CIDR 位运算匹配（v4/v6；v4-mapped v6 已归一）。
            return self
                .internal_networks
                .iter()
                .any(|network| network.contains(candidate));
        }
        // 无法解析的 IP 值退回字符串精确匹配，不做 CIDR 判断。
        self.source_ips.exact.iter().any(|item| item == ip)
    }

    fn user_agent_suppressed(&self, user_agent: Option<&str>) -> bool {
        let Some(user_agent) = user_agent else {
            return false;
        };
        let user_agent = user_agent.to_ascii_lowercase();
        self.user_agents
            .contains
            .iter()
            .any(|needle| user_agent.contains(&needle.to_ascii_lowercase()))
    }
}

/// internal 网段：统一 128 位 v6 字节表示 + 前缀位数。
/// v4 与 v4-mapped v6 在解析阶段归一到同一表示（v4 按 ::ffff:0:0/96 嵌入，
/// 前缀折算 +96），因此 10.0.0.0/8 与 ::ffff:10.0.0.0/104 语义一致。
#[derive(Debug, Clone, Copy)]
struct InternalNetwork {
    network: [u8; 16],
    prefix: u32,
}

impl InternalNetwork {
    fn contains(&self, candidate: [u8; 16]) -> bool {
        let full_bytes = (self.prefix / 8) as usize;
        let remainder_bits = self.prefix % 8;
        for index in 0..full_bytes {
            if self.network[index] != candidate[index] {
                return false;
            }
        }
        if remainder_bits > 0 {
            let mask: u8 = 0xff << (8 - remainder_bits);
            if (self.network[full_bytes] & mask) != (candidate[full_bytes] & mask) {
                return false;
            }
        }
        true
    }
}

/// 解析 internal 条目：裸 IP（视为全长度主机前缀）或 CIDR。
fn parse_internal_network(entry: &str) -> Option<InternalNetwork> {
    let entry = entry.trim();
    if let Some((address, prefix)) = entry.split_once('/') {
        let prefix: u32 = prefix.trim().parse().ok()?;
        let (bytes, written_as_v4) = parse_ip_bytes_with_form(address)?;
        let effective_prefix = if written_as_v4 {
            // 点分 v4 写法的前缀是 v4 空间长度（0..=32），映射到 v6 后 +96。
            if prefix > 32 {
                return None;
            }
            prefix + 96
        } else if prefix <= 128 {
            // v6 写法（含 ::ffff:a.b.c.d/n，n 已是 v6 空间长度，保持不变）。
            prefix
        } else {
            return None;
        };
        Some(InternalNetwork {
            network: mask_host_bits(bytes, effective_prefix),
            prefix: effective_prefix,
        })
    } else {
        let bytes = parse_ip_bytes(entry)?;
        Some(InternalNetwork {
            network: bytes,
            prefix: 128,
        })
    }
}

/// 解析 IP 为 16 字节 v6 表示：v4 → ::ffff:a.b.c.d；v6 v4-mapped 保持映射形式。
fn parse_ip_bytes(value: &str) -> Option<[u8; 16]> {
    parse_ip_bytes_with_form(value).map(|(bytes, _)| bytes)
}

/// 同 [parse_ip_bytes]，并返回是否以点分 v4 形式书写（影响 CIDR 前缀折算）。
fn parse_ip_bytes_with_form(value: &str) -> Option<([u8; 16], bool)> {
    let value = value.trim();
    if let Ok(v4) = value.parse::<std::net::Ipv4Addr>() {
        let mut bytes = [0u8; 16];
        bytes[10] = 0xff;
        bytes[11] = 0xff;
        bytes[12..].copy_from_slice(&v4.octets());
        return Some((bytes, true));
    }
    let v6 = value.parse::<std::net::Ipv6Addr>().ok()?;
    Some((v6.octets(), false))
}

fn mask_host_bits(mut bytes: [u8; 16], prefix: u32) -> [u8; 16] {
    let full_bytes = (prefix / 8) as usize;
    let remainder_bits = prefix % 8;
    if remainder_bits > 0 {
        let mask: u8 = 0xff << (8 - remainder_bits);
        bytes[full_bytes] &= mask;
    }
    for byte in bytes.iter_mut().skip(full_bytes + 1) {
        *byte = 0;
    }
    bytes
}

/// path 归一化（用于 exact/prefix 匹配）：URL decode + 去除 ./ 与 ../ 段 + 合并多斜杠。
/// 例：/api/health/../admin → /api/admin；//api///x → /api/x。
fn normalize_allowlist_path(path: &str) -> String {
    let decoded = super::matcher::percent_decode_text(path);
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let prefix = if decoded.starts_with('/') { "/" } else { "" };
    format!("{prefix}{}", segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> DetectionRule {
        DetectionRule {
            id: "WEB-SQLI-001".to_string(),
            name: "test".to_string(),
            version: 1,
            category: "sqli".to_string(),
            source: "http_access".to_string(),
            enabled: true,
            severity: None,
            matcher: super::super::rule_model::MatchExpr {
                contains: Some("union".to_string()),
                ..Default::default()
            },
            score: Default::default(),
            recommendation: None,
            description: None,
        }
    }

    fn allowlist_with_internal(internal: &[&str], exact: &[&str]) -> Allowlist {
        let mut allowlist = Allowlist {
            source_ips: SourceIpAllowlist {
                exact: exact.iter().map(|value| value.to_string()).collect(),
                internal: internal.iter().map(|value| value.to_string()).collect(),
            },
            ..Allowlist::default()
        };
        allowlist.finalize();
        allowlist
    }

    #[test]
    fn internal_cidrs_match_v4_and_v6() {
        let allowlist = allowlist_with_internal(
            &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fd00::/8"],
            &[],
        );
        let rule = rule();
        for ip in [
            "10.1.2.3",
            "172.31.255.254",
            "192.168.5.5",
            "127.0.0.1",
            "fd12::1",
        ] {
            assert!(
                allowlist.suppresses_values(&rule, None, Some(ip), None),
                "{ip} should be suppressed"
            );
        }
        for ip in [
            "172.32.0.1",
            "11.0.0.1",
            "192.169.0.1",
            "128.0.0.1",
            "fe80::1",
            "203.0.113.10",
        ] {
            assert!(
                !allowlist.suppresses_values(&rule, None, Some(ip), None),
                "{ip} should not be suppressed"
            );
        }
    }

    #[test]
    fn v4_mapped_v6_normalizes_to_v4_space() {
        // ::ffff:10.0.0.0/104 等价于 10.0.0.0/8。
        let allowlist = allowlist_with_internal(&["::ffff:10.0.0.0/104"], &[]);
        let rule = rule();
        assert!(allowlist.suppresses_values(&rule, None, Some("10.9.9.9"), None));
        assert!(allowlist
            .suppresses_values(&rule, None, Some("::ffff:10.9.9.9"), None));
        assert!(!allowlist.suppresses_values(&rule, None, Some("11.0.0.1"), None));
    }

    #[test]
    fn unparseable_entries_produce_warnings() {
        let allowlist = allowlist_with_internal(&["not-a-cidr", "10.0.0.0/33"], &["also-bad"]);
        assert_eq!(allowlist.warnings.len(), 3, "{:?}", allowlist.warnings);
        assert!(allowlist.warnings[0].contains("not-a-cidr"));
    }

    #[test]
    fn path_prefix_normalization_blocks_traversal_evasion() {
        let mut allowlist = Allowlist {
            paths: PathAllowlist {
                exact: vec![],
                prefix: vec!["/api/health".to_string()],
            },
            ..Allowlist::default()
        };
        allowlist.finalize();
        let rule = rule();
        // 直接前缀抑制仍然生效。
        assert!(allowlist.suppresses_values(&rule, Some("/api/health"), None, None));
        assert!(allowlist
            .suppresses_values(&rule, Some("/api/health/sub"), None, None));
        // ../ 穿越/编码/多斜杠形态归一化后不再被 /api/health 前缀误抑制
        //（/api/health/../admin 实际访问的是 /api/admin）。
        assert!(!allowlist
            .suppresses_values(&rule, Some("/api/health/../admin"), None, None));
        assert!(!allowlist
            .suppresses_values(&rule, Some("//api/./health/../admin"), None, None));
        // 无关路径不受影响。
        assert!(!allowlist.suppresses_values(&rule, Some("/api/users"), None, None));
    }

    #[test]
    fn exact_path_uses_normalized_comparison() {
        let mut allowlist = Allowlist {
            paths: PathAllowlist {
                exact: vec!["/api/health".to_string()],
                prefix: vec![],
            },
            ..Allowlist::default()
        };
        allowlist.finalize();
        let rule = rule();
        assert!(allowlist
            .suppresses_values(&rule, Some("/api/health/../health"), None, None));
    }
}
