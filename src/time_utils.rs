use std::sync::OnceLock;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

/// 用户通过 --tz-offset 显式指定的时区偏移；设置后覆盖系统本地时区，
/// 用于无时区时间戳的解释与本地时间渲染（离线分析机与被检主机时区不一致的场景）。
static FIXED_OFFSET: OnceLock<UtcOffset> = OnceLock::new();

pub fn set_fixed_offset(offset: UtcOffset) {
    let _ = FIXED_OFFSET.set(offset);
}

pub fn fixed_offset() -> Option<UtcOffset> {
    FIXED_OFFSET.get().copied()
}

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc().to_offset(local_offset_or_zero())
}

pub fn now_iso() -> String {
    format_iso(now())
}

/// Unix epoch 秒 → ISO8601（生效时区，非法值返回空串）。
pub fn format_epoch_iso(epoch: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(epoch) {
        Ok(value) => format_iso(value.to_offset(local_offset_or_zero())),
        Err(_) => String::new(),
    }
}

/// SystemTime → ISO8601（生效时区，无法表示时返回 unknown）。
pub fn system_time_to_iso(value: std::time::SystemTime) -> String {
    match value.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(duration) => format_epoch_iso(duration.as_secs() as i64),
        Err(_) => "unknown".to_string(),
    }
}

fn local_offset_or_zero() -> UtcOffset {
    if let Some(offset) = FIXED_OFFSET.get().copied() {
        return offset;
    }
    UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC)
}

/// 当前时间基准说明（写入 run.log）：显式偏移 / 系统本地时区 / UTC 回退。
/// Linux 多线程进程内 time crate 无法读取本地时区，回退必须显式可见，
/// 否则同一份报告会混排本地时区与 UTC 两种时间戳。
pub fn timezone_basis_note() -> String {
    if let Some(offset) = FIXED_OFFSET.get().copied() {
        return format!("timezone: explicit --tz-offset {offset} in effect for naive timestamps and local rendering");
    }
    match UtcOffset::current_local_offset() {
        Ok(offset) => format!("timezone: system local offset {offset}"),
        Err(_) => "timezone: system local offset unavailable on this platform configuration; naive timestamps and local rendering fall back to UTC (use --tz-offset to pin the analysis timezone)"
            .to_string(),
    }
}

pub fn format_iso(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_else(|_| value.to_string())
}

pub fn format_result_stamp(value: OffsetDateTime) -> String {
    let format = format_description!(
        "[year][month repr:numerical padding:zero][day]_[hour][minute][second]"
    );
    value
        .format(format)
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn parse_datetime(value: &str) -> std::result::Result<OffsetDateTime, String> {
    if let Ok(parsed) = OffsetDateTime::parse(value, &Rfc3339) {
        return Ok(parsed);
    }

    let local_offset = local_offset_or_zero();
    for pattern in [
        "[year]-[month]-[day] [hour]:[minute]:[second]",
        "[year]-[month]-[day]T[hour]:[minute]:[second]",
    ] {
        let format = time::format_description::parse(pattern)
            .map_err(|error| format!("internal datetime format error: {error}"))?;
        if let Ok(parsed) = PrimitiveDateTime::parse(value, &format) {
            return Ok(parsed.assume_offset(local_offset));
        }
    }

    Err(format!("`{value}` is not RFC3339 or YYYY-MM-DD HH:MM:SS"))
}

/// 时间戳排序键：成功解析返回 unix 纳秒；无时间戳或不可解析返回 None。
/// 时间线/攻击链排序必须用它，不能对 ISO 字符串做字典序排序——
/// 混合 `+08:00` 与 `Z` 偏移时字典序与真实时间序不一致。
pub fn timestamp_instant_nanos(value: Option<&str>) -> Option<i128> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    parse_datetime(value).ok().map(|parsed| {
        parsed.unix_timestamp_nanos()
    })
}

/// 解析用户提供的时区偏移（--tz-offset），接受 +HH:MM / -HH:MM / UTC 三种形式。
pub fn parse_user_offset(value: &str) -> std::result::Result<UtcOffset, String> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("utc") || value == "Z" {
        return Ok(UtcOffset::UTC);
    }
    let (sign, rest) = match value.as_bytes().first() {
        Some(b'+') => (1i8, &value[1..]),
        Some(b'-') => (-1i8, &value[1..]),
        _ => return Err(format!("`{value}` must be +HH:MM, -HH:MM or UTC")),
    };
    let mut parts = rest.split(':');
    let hours: i8 = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or_else(|| format!("`{value}` must be +HH:MM, -HH:MM or UTC"))?;
    let minutes: i8 = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or_else(|| format!("`{value}` must be +HH:MM, -HH:MM or UTC"))?;
    if parts.next().is_some() || hours > 23 || minutes < 0 || minutes > 59 {
        return Err(format!("`{value}` is out of the supported offset range"));
    }
    UtcOffset::from_hms(sign * hours, sign * minutes, 0)
        .map_err(|error| format!("`{value}` is not a valid UTC offset: {error}"))
}

/// 传统 syslog 时间戳 "Mon DD HH:MM:SS"（无年份，auth.log/secure 的默认格式）。
/// 年份按当前生效时间推断；推断结果晚于当前时间超过 1 天时回退一年
/// （1 月分析去年 12 月日志的跨年场景）。
pub fn parse_syslog_timestamp(value: &str) -> Option<OffsetDateTime> {
    let mut parts = value.split_whitespace();
    let month = month_from_name(parts.next()?)?;
    let day: u8 = parts.next()?.parse().ok()?;
    let time_part = parts.next()?;
    let mut time_fields = time_part.split(':');
    let hour: u8 = time_fields.next()?.parse().ok()?;
    let minute: u8 = time_fields.next()?.parse().ok()?;
    let second: u8 = time_fields.next()?.parse().ok()?;

    let now = now();
    let candidate_year = |year: i32| -> Option<OffsetDateTime> {
        let date = Date::from_calendar_date(year, month, day).ok()?;
        let time = Time::from_hms(hour, minute, second).ok()?;
        Some(PrimitiveDateTime::new(date, time).assume_offset(local_offset_or_zero()))
    };
    let with_current_year = candidate_year(now.year())?;
    if with_current_year > now + time::Duration::days(1) {
        return candidate_year(now.year() - 1);
    }
    Some(with_current_year)
}

fn month_from_name(value: &str) -> Option<Month> {
    match value.to_ascii_lowercase().as_str() {
        "jan" => Some(Month::January),
        "feb" => Some(Month::February),
        "mar" => Some(Month::March),
        "apr" => Some(Month::April),
        "may" => Some(Month::May),
        "jun" => Some(Month::June),
        "jul" => Some(Month::July),
        "aug" => Some(Month::August),
        "sep" => Some(Month::September),
        "oct" => Some(Month::October),
        "nov" => Some(Month::November),
        "dec" => Some(Month::December),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_timestamp_infers_year() {
        let parsed = parse_syslog_timestamp("Aug 27 06:44:01").expect("should parse");
        assert_eq!(parsed.month(), time::Month::August);
        assert_eq!(parsed.day(), 27);
        assert_eq!(
            parsed,
            parse_datetime(&format_iso(parsed)).expect("round trip")
        );
    }

    #[test]
    fn syslog_timestamp_rejects_garbage() {
        assert!(parse_syslog_timestamp("not a timestamp").is_none());
        assert!(parse_syslog_timestamp("").is_none());
    }

    #[test]
    fn sort_key_orders_across_offsets() {
        // 绝对时刻 13:00Z(+08:00 21:00) 晚于 05:00Z；字典序会得到相反顺序。
        let early = timestamp_instant_nanos(Some("2026-08-27T05:00:00Z")).unwrap();
        let late = timestamp_instant_nanos(Some("2026-08-27T21:00:00+08:00")).unwrap();
        assert!(early < late);
        assert_eq!(timestamp_instant_nanos(None), None);
        assert_eq!(timestamp_instant_nanos(Some("15/May/2026:08:00:00 +0000")), None);
    }
}
