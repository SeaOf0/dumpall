pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

pub fn max_line_entropy(bytes: &[u8]) -> f64 {
    bytes
        .split(|byte| matches!(byte, b'\n' | b'\r'))
        .filter(|line| line.len() >= 40)
        .map(shannon_entropy)
        .fold(0.0, f64::max)
}

pub fn longest_base64_run(bytes: &[u8]) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for byte in bytes {
        if is_base64_byte(*byte) {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_long_base64_runs() {
        let input = b"abc !!!! QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo= end";
        assert!(longest_base64_run(input) >= 36);
        assert!(shannon_entropy(b"aaaaaaaa") < shannon_entropy(b"abcdefgh"));
    }
}
