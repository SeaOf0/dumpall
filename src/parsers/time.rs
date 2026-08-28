use time::{Date, Month, PrimitiveDateTime, Time, UtcOffset};

pub fn parse_clf_time(value: &str) -> Option<String> {
    let mut parts = value.split_whitespace();
    let datetime = parts.next()?;
    let offset_token = parts.next();
    let mut dt_parts = datetime.split(['/', ':']);
    let day = dt_parts.next()?.parse::<u8>().ok()?;
    let month = parse_month(dt_parts.next()?)?;
    let year = dt_parts.next()?.parse::<i32>().ok()?;
    let hour = dt_parts.next()?.parse::<u8>().ok()?;
    let minute = dt_parts.next()?.parse::<u8>().ok()?;
    let second = dt_parts.next()?.parse::<u8>().ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    // CLF 时间戳缺时区时不再默认 +0000:与其它 naive 时间戳一致,
    // 按生效时区解释(--tz-offset 显式覆盖,否则系统本地时区)。
    let offset = match offset_token {
        Some(token) => parse_offset(token)?,
        None => crate::time_utils::fixed_offset()
            .or_else(|| UtcOffset::current_local_offset().ok())
            .unwrap_or(UtcOffset::UTC),
    };
    Some(crate::time_utils::format_iso(
        PrimitiveDateTime::new(date, time).assume_offset(offset),
    ))
}

pub fn parse_iis_datetime(date: &str, time_value: &str) -> Option<String> {
    // IIS W3C 的 Date/Time 字段是服务器本地时间(除非部署显式改写为 UTC),
    // 不再硬编码 Z:与其它 naive 时间戳一致走 time_utils 的本地偏移路径,
    // 受 --tz-offset 控制;#Fields 旁的 #Date 注释仅为生成时间,可忽略。
    let value = format!("{date} {time_value}");
    crate::time_utils::parse_datetime(&value)
        .ok()
        .map(crate::time_utils::format_iso)
}

fn parse_month(value: &str) -> Option<Month> {
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

fn parse_offset(value: &str) -> Option<UtcOffset> {
    if value.len() != 5 {
        return None;
    }
    let sign = &value[..1];
    let hour = value[1..3].parse::<i8>().ok()?;
    let minute = value[3..5].parse::<i8>().ok()?;
    match sign {
        "+" => UtcOffset::from_hms(hour, minute, 0).ok(),
        "-" => UtcOffset::from_hms(-hour, -minute, 0).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clf_time_to_iso() {
        assert_eq!(
            parse_clf_time("15/May/2026:08:00:00 +0000").as_deref(),
            Some("2026-05-15T08:00:00Z")
        );
    }

    #[test]
    fn clf_time_without_offset_uses_effective_timezone() {
        // 无时区 CLF:按生效时区解释(受 --tz-offset 控制),不再默认 +0000;
        // 结果应可往返解析且时钟面值保持 08:00:00。
        let parsed = parse_clf_time("15/May/2026:08:00:00").expect("naive CLF parses");
        let expected = crate::time_utils::parse_datetime("2026-05-15 08:00:00").unwrap();
        assert_eq!(parsed, crate::time_utils::format_iso(expected));
    }

    #[test]
    fn iis_datetime_is_server_local_time() {
        // W3C Date/Time 视为服务器本地时间:与 naive 一致(不再硬编码 Z)
        let parsed = parse_iis_datetime("2026-05-15", "08:03:00").expect("iis datetime parses");
        let expected = crate::time_utils::parse_datetime("2026-05-15 08:03:00").unwrap();
        assert_eq!(parsed, crate::time_utils::format_iso(expected));
    }
}
