use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    raw: String,
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("empty CIDR value".to_string());
        }

        let (addr, prefix) = if let Some((addr, prefix)) = value.split_once('/') {
            let addr = parse_ip_token(addr).ok_or_else(|| format!("invalid CIDR IP `{addr}`"))?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| format!("invalid CIDR prefix `{prefix}`"))?;
            validate_prefix(addr, prefix)?;
            (addr, prefix)
        } else {
            let addr = parse_ip_token(value).ok_or_else(|| format!("invalid IP `{value}`"))?;
            let prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            (addr, prefix)
        };

        // 网段地址先做 canonical 化,::ffff:10.0.0.0/120 与 10.0.0.0/24 视为同一网段。
        let addr = canonical_ip(&addr.to_string()).unwrap_or(addr);

        Ok(Self {
            raw: value.to_string(),
            addr,
            prefix,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // IPv4-mapped IPv6(::ffff:1.2.3.4)先映射回 IPv4,
        // 否则 V4 网段永远匹配不到以 V6 写法出现的同一地址。
        let ip = canonical_ip(&ip.to_string()).unwrap_or(ip);
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = ipv4_mask(self.prefix);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = ipv6_mask(self.prefix);
                (u128::from_be_bytes(network.octets()) & mask)
                    == (u128::from_be_bytes(ip.octets()) & mask)
            }
            _ => false,
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IpType {
    Public,
    Private,
    Loopback,
    LinkLocal,
    Reserved,
    #[default]
    Invalid,
}

impl IpType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Loopback => "loopback",
            Self::LinkLocal => "linklocal",
            Self::Reserved => "reserved",
            Self::Invalid => "invalid",
        }
    }

    pub fn is_internal(self) -> bool {
        matches!(self, Self::Private | Self::Loopback | Self::LinkLocal)
    }
}

pub fn parse_ip_token(value: &str) -> Option<IpAddr> {
    let value = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('<')
        .trim_matches('>');
    if value.is_empty() || value.eq_ignore_ascii_case("unknown") || value == "-" {
        return None;
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Some(stripped) = value
        .strip_prefix('[')
        .and_then(|value| value.split_once(']'))
    {
        return stripped.0.parse::<IpAddr>().ok();
    }

    let colon_count = value.matches(':').count();
    if colon_count == 1 {
        if let Some((host, port)) = value.rsplit_once(':') {
            if port.chars().all(|ch| ch.is_ascii_digit()) {
                return host.parse::<IpAddr>().ok();
            }
        }
    }

    None
}

/// 解析并 canonical 化 IP:IPv4-mapped IPv6(::ffff:1.2.3.4)转为 IPv4,
/// 其余保持原样。IOC 匹配、网段判断、关联比较都必须先过这一步,
/// 否则同一地址的 V4/V6 两种写法会互相匹配失败。
pub fn canonical_ip(value: &str) -> Option<IpAddr> {
    match parse_ip_token(value)? {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).or(Some(IpAddr::V6(v6))),
        v4 => Some(v4),
    }
}

pub fn classify_ip_text(value: &str) -> IpType {
    parse_ip_token(value)
        .map(classify_ip)
        .unwrap_or(IpType::Invalid)
}

pub fn classify_ip(ip: IpAddr) -> IpType {
    match ip {
        IpAddr::V4(ip) => classify_ipv4(ip),
        IpAddr::V6(ip) => classify_ipv6(ip),
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> IpType {
    if ip.is_loopback() {
        IpType::Loopback
    } else if ip.is_private() {
        IpType::Private
    } else if ip.is_link_local() {
        IpType::LinkLocal
    } else if ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || in_ipv4_range(ip, Ipv4Addr::new(100, 64, 0, 0), 10)
        || in_ipv4_range(ip, Ipv4Addr::new(192, 0, 0, 0), 24)
        || in_ipv4_range(ip, Ipv4Addr::new(198, 18, 0, 0), 15)
    {
        IpType::Reserved
    } else {
        IpType::Public
    }
}

fn classify_ipv6(ip: Ipv6Addr) -> IpType {
    // IPv4-mapped IPv6(::ffff:10.0.0.1)本质是 IPv4 地址,按映射后的 V4 分类,
    // 否则 ::ffff:10.0.0.1 会被判成公网而非内网。
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_ipv4(v4);
    }
    let octets = ip.octets();
    if ip.is_loopback() {
        IpType::Loopback
    } else if (octets[0] & 0xfe) == 0xfc {
        IpType::Private
    } else if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
        IpType::LinkLocal
    } else if ip.is_unspecified()
        || ip.is_multicast()
        || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
    {
        IpType::Reserved
    } else {
        IpType::Public
    }
}

fn in_ipv4_range(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = ipv4_mask(prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn validate_prefix(addr: IpAddr, prefix: u8) -> std::result::Result<(), String> {
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(format!("CIDR prefix {prefix} exceeds {max} bits"));
    }
    Ok(())
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matches_ipv4_and_single_ip() {
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains("10.1.2.3".parse().unwrap()));
        assert!(!cidr.contains("198.51.100.1".parse().unwrap()));

        let single = Cidr::parse("203.0.113.10").unwrap();
        assert!(single.contains("203.0.113.10".parse().unwrap()));
        assert!(!single.contains("203.0.113.11".parse().unwrap()));
    }

    #[test]
    fn classifies_internal_and_reserved_ranges() {
        assert_eq!(classify_ip_text("127.0.0.1"), IpType::Loopback);
        assert_eq!(classify_ip_text("10.1.2.3"), IpType::Private);
        assert_eq!(classify_ip_text("169.254.1.1"), IpType::LinkLocal);
        assert_eq!(classify_ip_text("203.0.113.10"), IpType::Reserved);
    }

    #[test]
    fn canonicalizes_ipv4_mapped_ipv6() {
        assert_eq!(
            canonical_ip("::ffff:203.0.113.10"),
            "203.0.113.10".parse::<IpAddr>().ok()
        );
        assert_eq!(
            canonical_ip("203.0.113.10").map(|ip| ip.to_string()),
            Some("203.0.113.10".to_string())
        );
        // 非 mapped 的真 IPv6 保持不变;不可解析返回 None。
        assert_eq!(
            canonical_ip("2001:db8::1"),
            "2001:db8::1".parse::<IpAddr>().ok()
        );
        assert_eq!(canonical_ip("unknown"), None);

        // V4 网段要能命中 V6-mapped 写法的同一地址;内网判定按映射后的 V4 走。
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert_eq!(classify_ip_text("::ffff:10.1.2.3"), IpType::Private);
    }
}
