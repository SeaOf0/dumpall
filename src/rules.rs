use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::detectors::rule_engine;
use crate::error::Result;

#[derive(Debug, Clone, Serialize)]
pub struct RuleValidationReport {
    pub files_checked: usize,
    pub files: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl RuleValidationReport {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn to_human_summary(&self) -> String {
        let mut output = format!(
            "Validated {} rule file(s): {} error(s), {} warning(s)",
            self.files_checked,
            self.errors.len(),
            self.warnings.len()
        );

        for warning in &self.warnings {
            output.push_str(&format!("\nwarning: {warning}"));
        }
        for error in &self.errors {
            output.push_str(&format!("\nerror: {error}"));
        }
        output
    }
}

pub fn validate_rule_paths(paths: &[PathBuf]) -> Result<RuleValidationReport> {
    let mut report = RuleValidationReport {
        files_checked: 0,
        files: Vec::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
    };

    if paths.is_empty() {
        for loaded in rule_engine::load_rule_sets(&[])? {
            report.files_checked += 1;
            report.files.push(if loaded.embedded {
                loaded.path.to_string_lossy().to_string()
            } else {
                loaded.path.display().to_string()
            });
            if loaded.rule_set.rules.is_empty() {
                report.warnings.push(format!(
                    "{} contains no rules",
                    report.files.last().cloned().unwrap_or_default()
                ));
            }
        }
        return Ok(report);
    }

    for path in expand_rule_paths(paths) {
        report.files.push(path.display().to_string());
        report.files_checked += 1;
        match fs::read_to_string(&path) {
            Ok(content) if content.trim().is_empty() => {
                report.warnings.push(format!("{} is empty", path.display()))
            }
            Ok(_) => match rule_engine::validate_rule_file(&path) {
                Ok(0) => report
                    .warnings
                    .push(format!("{} contains no rules", path.display())),
                Ok(_) => {}
                Err(error) => report
                    .errors
                    .push(format!("{} failed validation: {error}", path.display())),
            },
            Err(error) => report
                .errors
                .push(format!("{} could not be read: {error}", path.display())),
        }
    }

    Ok(report)
}

pub fn count_default_rule_files() -> usize {
    rule_engine::load_rule_sets(&[])
        .map(|rules| rules.len())
        .unwrap_or(0)
}

fn expand_rule_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_file() {
            files.push(path.clone());
            continue;
        }
        if path.is_dir() {
            collect_yaml_files(path, &mut files);
            continue;
        }
        files.push(path.clone());
    }
    files.sort();
    files
}

fn collect_yaml_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        files.push(dir.to_path_buf());
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| matches!(extension, "yml" | "yaml"))
            .unwrap_or(false);
        if is_yaml {
            files.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_yaml_rule_fixture() {
        let path = PathBuf::from("tests/fixtures/rules/minimal.yml");
        let report = validate_rule_paths(&[path]).unwrap();

        assert_eq!(report.files_checked, 1);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
    }
}
