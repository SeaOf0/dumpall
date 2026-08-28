use crate::cli::CommonArgs;
use crate::error::{DumpallError, Result};

#[derive(Debug, Clone)]
pub struct SafetyLimits {
    pub max_cpu_percent: u8,
    pub threads: usize,
    pub max_file_size_mb: u64,
    pub max_depth: usize,
    pub redact: bool,
    pub offline: bool,
    pub verbose: bool,
}

impl SafetyLimits {
    pub fn from_args(args: &CommonArgs) -> Result<Self> {
        let max_cpu_percent = args.max_cpu.unwrap_or(50);
        if !(1..=100).contains(&max_cpu_percent) {
            return Err(DumpallError::invalid_argument(
                "max-cpu",
                "value must be between 1 and 100",
            ));
        }

        let threads = args.threads.unwrap_or_else(default_threads);
        if threads == 0 {
            return Err(DumpallError::invalid_argument(
                "threads",
                "value must be greater than zero",
            ));
        }

        let max_file_size_mb = args.max_file_size.unwrap_or(512);
        if max_file_size_mb == 0 {
            return Err(DumpallError::invalid_argument(
                "max-file-size",
                "value must be greater than zero",
            ));
        }

        let max_depth = args.max_depth.unwrap_or(8);
        if max_depth == 0 {
            return Err(DumpallError::invalid_argument(
                "max-depth",
                "value must be greater than zero",
            ));
        }

        Ok(Self {
            max_cpu_percent,
            threads,
            max_file_size_mb,
            max_depth,
            redact: args.redact,
            offline: args.offline,
            verbose: args.verbose,
        })
    }
}

pub fn default_threads() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1);
    (cpus / 2).clamp(1, 4)
}

pub fn redact_text(input: &str) -> String {
    let mut output = input.to_string();
    for marker in [
        "authorization:",
        "authorization=",
        "bearer ",
        "apikey:",
        "apikey=",
        "api_key=",
        "x-api-key:",
        "x-api-key=",
        "cookie:",
        "cookie=",
        "password:",
        "password=",
        "passwd:",
        "passwd=",
        "pwd=",
        "token:",
        "token=",
        "access_token=",
        "refresh_token=",
        "session=",
        "sessionid=",
        "jwt=",
        "privatekey=",
        "client_secret=",
        "secret=",
        "connectionstring=",
        "connection_string=",
    ] {
        output = redact_marker_values(&output, marker);
    }
    output
}

fn redact_marker_values(input: &str, marker: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    let lower = input.to_ascii_lowercase();

    while let Some(relative) = lower[cursor..].find(marker) {
        let marker_start = cursor + relative;
        let mut value_start = marker_start + marker.len();
        output.push_str(&input[cursor..value_start]);
        while value_start < input.len()
            && input[value_start..]
                .chars()
                .next()
                .map(|ch| matches!(ch, ' ' | '\t'))
                .unwrap_or(false)
        {
            let ch = input[value_start..].chars().next().unwrap();
            output.push(ch);
            value_start += ch.len_utf8();
        }

        let value_end = input[value_start..]
            .find(['&', ';', ',', '"', '\'', '\r', '\n', ' '])
            .map(|end| value_start + end)
            .unwrap_or(input.len());
        if value_end > value_start {
            output.push_str("<redacted>");
        }
        cursor = value_end;
    }

    output.push_str(&input[cursor..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_text_masks_sensitive_values() {
        let input = "curl /login?token=abc123&user=a Authorization: BearerXYZ password=hunter2,ok";
        let redacted = redact_text(input);

        assert!(redacted.contains("token=<redacted>&user=a"));
        assert!(redacted.contains("Authorization: <redacted>"));
        assert!(redacted.contains("password=<redacted>,ok"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("hunter2"));
    }
}
