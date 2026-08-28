use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct ScriptSignals {
    pub dynamic_execution: bool,
    pub command_execution: bool,
    pub reflection: bool,
    pub http_param_bridge: bool,
    pub suspicious_filename: bool,
}

pub fn analyze(path: &Path, text: &str) -> ScriptSignals {
    let lower = text.to_ascii_lowercase();
    // 带 '(' 的函数名一律走调用点匹配（前一字符非 [a-z0-9_]），
    // 避免 curl_exec(/preg_replace(/base64_encode( 等业务函数的子串误命中。
    let dynamic_execution = contains_any(&lower, &["scriptenginemanager"])
        || contains_any_call(
            &lower,
            &["eval(", "assert(", "create_function(", "frombase64string("],
        )
        || preg_replace_with_e_modifier(&lower);
    let command_execution = contains_any(
        &lower,
        &[
            "runtime.getruntime().exec",
            "new processbuilder",
            "process.start(",
            "cmd.exe",
            "powershell",
            "/bin/sh",
            "/bin/bash",
        ],
    ) || contains_any_call(
        &lower,
        &["system(", "shell_exec(", "passthru(", "proc_open(", "popen(", "exec("],
    );
    let reflection = contains_any(
        &lower,
        &[
            "class.forname",
            ".getmethod(",
            ".invoke(",
            "reflectionclass",
            "system.reflection",
            "assembly.load",
        ],
    );
    let http_input = contains_any(
        &lower,
        &[
            "$_get",
            "$_post",
            "$_request",
            "request.getparameter",
            "request.querystring",
            "request.form",
            "request[",
        ],
    );

    ScriptSignals {
        dynamic_execution,
        command_execution,
        reflection,
        http_param_bridge: http_input && (dynamic_execution || command_execution || reflection),
        suspicious_filename: suspicious_filename(path),
    }
}

/// 调用点匹配：needle 以 '(' 结尾时，命中要求前一个字符不是 [a-z0-9_]，
/// 避免 curl_exec( / preg_replace( / dispatch( 等业务函数名里的子串误命中。
fn contains_call(hay_lower: &str, needle: &str) -> bool {
    debug_assert!(needle.ends_with('('));
    let mut search_from = 0usize;
    while let Some(found) = hay_lower[search_from..].find(needle) {
        let absolute = search_from + found;
        let boundary_ok = absolute == 0
            || !hay_lower[..absolute]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
        if boundary_ok {
            return true;
        }
        search_from = absolute + needle.len();
    }
    false
}

fn contains_any_call(hay_lower: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| contains_call(hay_lower, needle))
}

/// PHP preg_replace 仅在模式使用 /e 修饰符（ retired 但仍构成动态执行风险）时计
/// 动态执行；普通 preg_replace 是常见业务调用，不加分。
fn preg_replace_with_e_modifier(hay_lower: &str) -> bool {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        // preg_replace( 后的第一个引号串形如 '/payload/e'（或 "/payload/e"）。
        // regex crate 不支持反向引用,改为不回引开引号的等价匹配:
// preg_replace( 后第一个引号串内出现 /e 修饰符即命中。
regex::Regex::new(r#"preg_replace\s*\(\s*['"][^'"]*/e"#).unwrap()
    });
    pattern.is_match(hay_lower)
}

fn contains_any(input: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| input.contains(needle))
}

fn suspicious_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    [
        "shell", "cmd", "command", "backdoor", "webshell", "upload", "cache", "image", "avatar",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_param_to_command_bridge() {
        let signals = analyze(
            Path::new("avatar.php"),
            "<?php $cmd=$_GET['cmd']; system($cmd); ?>",
        );

        assert!(signals.command_execution);
        assert!(signals.http_param_bridge);
        assert!(signals.suspicious_filename);
    }

    #[test]
    fn call_site_matching_avoids_function_name_substrings() {
        // curl_exec( / base64_encode( / dispatch( 不再命中 exec(。
        let signals = analyze(
            Path::new("api.php"),
            "<?php $r = curl_exec($ch); $d = base64_encode($r); dispatch($d); ?>",
        );
        assert!(!signals.command_execution);

        // 真正的独立调用仍命中：前一个字符是空白/分号/引号。
        let signals = analyze(Path::new("a.php"), "<?php exec('whoami'); ?>");
        assert!(signals.command_execution);
        let signals = analyze(Path::new("b.php"), "<?php\nsystem($cmd); ?>");
        assert!(signals.command_execution);
        // 行首直接调用。
        let signals = analyze(Path::new("c.php"), "exec('id');\n");
        assert!(signals.command_execution);
    }

    #[test]
    fn preg_replace_counts_only_with_e_modifier() {
        // 普通 preg_replace（业务常见）不构成动态执行。
        let signals = analyze(
            Path::new("normal.php"),
            "<?php preg_replace('/\\d+/', 'x', $s); ?>",
        );
        assert!(!signals.dynamic_execution);

        // /e 修饰符（动态执行）命中。
        let signals = analyze(
            Path::new("evil.php"),
            "<?php preg_replace('/a/e', 'system($_GET[\"c\"])', $s); ?>",
        );
        assert!(signals.dynamic_execution);
    }
}
