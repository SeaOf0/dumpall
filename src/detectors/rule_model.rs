use serde::Deserialize;

use crate::error::{DumpallError, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct RuleSet {
    pub schema_version: Option<u32>,
    #[serde(default)]
    pub rules: Vec<DetectionRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_rule_version")]
    pub version: u32,
    pub category: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(rename = "match")]
    pub matcher: MatchExpr,
    #[serde(default)]
    pub score: RuleScore,
    #[serde(default)]
    pub recommendation: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleScore {
    #[serde(default = "default_base_score")]
    pub base: u16,
    #[serde(default)]
    pub add: Vec<ScoreAdjustment>,
    #[serde(default)]
    pub subtract: Vec<ScoreAdjustment>,
}

impl Default for RuleScore {
    fn default() -> Self {
        Self {
            base: default_base_score(),
            add: Vec::new(),
            subtract: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScoreAdjustment {
    pub when: MatchExpr,
    pub value: u16,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatchExpr {
    #[serde(default)]
    pub all: Vec<MatchExpr>,
    #[serde(default)]
    pub any: Vec<MatchExpr>,
    #[serde(default)]
    pub not: Option<Box<MatchExpr>>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub contains_any: Vec<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default, rename = "in")]
    pub in_values: Vec<String>,
    #[serde(default)]
    pub gt: Option<f64>,
    #[serde(default)]
    pub gte: Option<f64>,
    #[serde(default)]
    pub lt: Option<f64>,
    #[serde(default)]
    pub lte: Option<f64>,
    #[serde(default, alias = "status in")]
    pub status_in: Vec<u16>,
}

impl DetectionRule {
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(DumpallError::rule_validation("rule id must not be empty"));
        }
        if self.name.trim().is_empty() {
            return Err(DumpallError::rule_validation(format!(
                "{} name must not be empty",
                self.id
            )));
        }
        if self.category.trim().is_empty() {
            return Err(DumpallError::rule_validation(format!(
                "{} category must not be empty",
                self.id
            )));
        }
        if self.source.trim().is_empty() {
            return Err(DumpallError::rule_validation(format!(
                "{} source must not be empty",
                self.id
            )));
        }
        if !has_match_logic(&self.matcher) {
            return Err(DumpallError::rule_validation(format!(
                "{} match expression must contain at least one condition",
                self.id
            )));
        }
        validate_match_expr(&self.id, &self.matcher)?;
        validate_score(&self.id, &self.score)
    }
}

pub fn parse_rule_set(content: &str) -> Result<RuleSet> {
    let rule_set: RuleSet = serde_yaml::from_str(content)?;
    for rule in &rule_set.rules {
        rule.validate()?;
    }
    validate_unique_rule_ids(&rule_set.rules, None)?;
    Ok(rule_set)
}

/// 文件内规则 ID 重复检测：同一文件内出现重复 ID 时给出 rule_validation 错误并列出重复项。
pub fn validate_unique_rule_ids(rules: &[DetectionRule], source: Option<&str>) -> Result<()> {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for rule in rules {
        *counts.entry(rule.id.as_str()).or_default() += 1;
    }
    let duplicates: Vec<String> = counts
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(id, count)| format!("{id} x{count}"))
        .collect();
    if !duplicates.is_empty() {
        let location = source
            .map(|path| format!(" in {path}"))
            .unwrap_or_default();
        return Err(DumpallError::rule_validation(format!(
            "duplicate rule id(s){location}: {}",
            duplicates.join(", ")
        )));
    }
    Ok(())
}

fn validate_match_expr(rule_id: &str, expr: &MatchExpr) -> Result<()> {
    if let Some(pattern) = &expr.regex {
        // 复用 matcher 的进程内正则缓存，避免校验与匹配两阶段重复编译。
        super::matcher::compile_cached(pattern).map_err(|error| {
            DumpallError::rule_validation(format!(
                "{rule_id} has invalid regex `{pattern}`: {error}"
            ))
        })?;
    }
    for child in &expr.all {
        validate_match_expr(rule_id, child)?;
    }
    for child in &expr.any {
        validate_match_expr(rule_id, child)?;
    }
    if let Some(child) = &expr.not {
        validate_match_expr(rule_id, child)?;
    }
    Ok(())
}

fn validate_score(rule_id: &str, score: &RuleScore) -> Result<()> {
    if score.base > 100 {
        return Err(DumpallError::rule_validation(format!(
            "{rule_id} score.base must be between 0 and 100"
        )));
    }
    for adjustment in score.add.iter().chain(score.subtract.iter()) {
        if adjustment.value > 100 {
            return Err(DumpallError::rule_validation(format!(
                "{rule_id} score adjustment must be between 0 and 100"
            )));
        }
        validate_match_expr(rule_id, &adjustment.when)?;
        if !has_match_logic(&adjustment.when) {
            return Err(DumpallError::rule_validation(format!(
                "{rule_id} score adjustment must contain a condition"
            )));
        }
    }
    Ok(())
}

fn has_match_logic(expr: &MatchExpr) -> bool {
    !expr.all.is_empty()
        || !expr.any.is_empty()
        || expr.not.is_some()
        || expr.equals.is_some()
        || expr.contains.is_some()
        || !expr.contains_any.is_empty()
        || expr.regex.is_some()
        || !expr.in_values.is_empty()
        || expr.gt.is_some()
        || expr.gte.is_some()
        || expr.lt.is_some()
        || expr.lte.is_some()
        || !expr.status_in.is_empty()
}

fn default_source() -> String {
    "http_access".to_string()
}

fn default_enabled() -> bool {
    true
}

fn default_rule_version() -> u32 {
    1
}

fn default_base_score() -> u16 {
    40
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_rule_ids_within_file_are_rejected() {
        let content = r#"
schema_version: 1
rules:
  - id: DUP-001
    name: first
    category: test
    source: http_access
    match:
      contains: "attack"
  - id: DUP-001
    name: second
    category: test
    source: http_access
    match:
      contains: "attack"
"#;
        let error = parse_rule_set(content).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("DUP-001"), "{message}");
        assert!(message.contains("duplicate"), "{message}");
    }
}
