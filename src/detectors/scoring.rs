use crate::model::{ScoreBreakdown, Severity};

use super::matcher::matches_record;
use super::rule_model::DetectionRule;

#[derive(Debug, Clone)]
pub struct ScoreOutcome {
    pub value: u16,
    pub severity: Severity,
    pub reasons: Vec<String>,
    pub breakdown: ScoreBreakdown,
}

pub fn score_for_rule(
    rule: &DetectionRule,
    default_field: &str,
    field_lookup: &dyn Fn(&str) -> Option<String>,
) -> ScoreOutcome {
    let mut score = i32::from(rule.score.base.min(100));
    let mut reasons = vec![format!("base score {}", rule.score.base.min(100))];

    for adjustment in &rule.score.add {
        if matches_record(&adjustment.when, default_field, field_lookup) {
            score += i32::from(adjustment.value);
            reasons.push(
                adjustment
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("+{} matched score condition", adjustment.value)),
            );
        }
    }

    for adjustment in &rule.score.subtract {
        if matches_record(&adjustment.when, default_field, field_lookup) {
            score -= i32::from(adjustment.value);
            reasons.push(
                adjustment
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("-{} matched score condition", adjustment.value)),
            );
        }
    }

    let value = score.clamp(0, 100) as u16;
    let mut breakdown = ScoreBreakdown::from_base(rule.score.base.min(100));
    let delta = value as i16 - rule.score.base.min(100) as i16;
    if delta >= 0 {
        breakdown.add_context(delta);
    } else {
        breakdown.add_noise_discount(delta.unsigned_abs());
    }
    ScoreOutcome {
        value,
        severity: severity_for_score(value),
        reasons,
        breakdown,
    }
}

pub fn severity_for_score(score: u16) -> Severity {
    Severity::from_score(score)
}
