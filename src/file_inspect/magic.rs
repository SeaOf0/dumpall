#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagicType {
    Empty,
    Php,
    Html,
    Xml,
    Json,
    Text,
    Jpeg,
    Png,
    Gif,
    Pdf,
    Zip,
    Binary,
}

impl MagicType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Php => "php_script",
            Self::Html => "html",
            Self::Xml => "xml",
            Self::Json => "json",
            Self::Text => "text",
            Self::Jpeg => "jpeg",
            Self::Png => "png",
            Self::Gif => "gif",
            Self::Pdf => "pdf",
            Self::Zip => "zip_archive",
            Self::Binary => "binary",
        }
    }

    pub fn is_image(self) -> bool {
        matches!(self, Self::Jpeg | Self::Png | Self::Gif)
    }
}

pub fn detect(bytes: &[u8]) -> MagicType {
    if bytes.is_empty() {
        return MagicType::Empty;
    }
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return MagicType::Jpeg;
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return MagicType::Png;
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return MagicType::Gif;
    }
    if bytes.starts_with(b"%PDF-") {
        return MagicType::Pdf;
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return MagicType::Zip;
    }

    let trimmed = trim_ascii_start(bytes);
    if starts_with_ignore_ascii_case(trimmed, b"<?php") {
        return MagicType::Php;
    }
    if starts_with_ignore_ascii_case(trimmed, b"<!doctype html")
        || starts_with_ignore_ascii_case(trimmed, b"<html")
    {
        return MagicType::Html;
    }
    if starts_with_ignore_ascii_case(trimmed, b"<?xml") {
        return MagicType::Xml;
    }
    if matches!(trimmed.first(), Some(b'{') | Some(b'[')) && std::str::from_utf8(bytes).is_ok() {
        return MagicType::Json;
    }
    if std::str::from_utf8(bytes).is_ok() || looks_like_text(bytes) {
        return MagicType::Text;
    }
    MagicType::Binary
}

pub fn extension_mismatch(extension: &str, magic: MagicType) -> bool {
    let extension = extension.trim_start_matches('.').to_ascii_lowercase();
    match extension.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "ico" | "webp" => !magic.is_image(),
        "zip" | "jar" | "war" => magic != MagicType::Zip,
        "pdf" => magic != MagicType::Pdf,
        _ => false,
    }
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    &bytes[index..]
}

fn starts_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

fn looks_like_text(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(4096);
    if sample_len == 0 {
        return true;
    }
    let control = bytes[..sample_len]
        .iter()
        .filter(|byte| byte.is_ascii_control() && !matches!(byte, b'\r' | b'\n' | b'\t'))
        .count();
    control * 100 / sample_len < 5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_magic_and_mismatch() {
        assert_eq!(detect(b"<?php echo 1;"), MagicType::Php);
        assert_eq!(detect(b"\x89PNG\r\n\x1a\nrest"), MagicType::Png);
        assert!(extension_mismatch("png", MagicType::Text));
        assert!(!extension_mismatch("png", MagicType::Png));
    }
}
