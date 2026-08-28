use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::CollectionError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Discovery {
    pub collector: String,
    pub kind: String,
    pub path: Option<String>,
    pub source: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceBudget {
    pub max_files: Option<u64>,
    pub max_records: Option<u64>,
    pub max_file_size_mb: Option<u64>,
    pub active_check_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectPlan {
    pub collector: String,
    pub enabled: bool,
    pub readonly: bool,
    pub dry_run_supported: bool,
    pub active_check_allowed: bool,
    pub summary: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub budget: ResourceBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectOutput {
    pub collector: String,
    pub files_scanned: u64,
    pub records_emitted: u64,
    pub notes: Vec<String>,
    pub errors: Vec<CollectionError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorPlanSummary {
    pub name: String,
    pub enabled: bool,
    pub readonly: bool,
    pub active_check_allowed: bool,
    pub coverage_status: String,
    pub evidence_quality_on_gap: String,
    pub summary: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
}

pub trait Collector {
    fn name(&self) -> &'static str;

    fn discover(&self, ctx: &ResolvedRun) -> Result<Vec<Discovery>>;

    fn plan(&self, ctx: &ResolvedRun, discoveries: &[Discovery]) -> Result<CollectPlan>;

    fn collect(&self, ctx: &ResolvedRun, plan: &CollectPlan) -> Result<CollectOutput>;
}

pub fn dry_run_plan(resolved: &ResolvedRun) -> Vec<CollectorPlanSummary> {
    let collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(crate::collectors::runtime::RuntimeCollector),
        Box::new(crate::collectors::events::EventsCollector),
        Box::new(crate::collectors::container::ContainerCollector),
    ];

    collectors
        .into_iter()
        .filter_map(|collector| plan_summary(collector.as_ref(), resolved).ok())
        .collect()
}

pub fn runtime_input_paths(resolved: &ResolvedRun) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    paths.extend(resolved.tomcat_base.iter().cloned());
    paths.extend(resolved.spring_app_path.iter().cloned());
    paths.extend(resolved.iis_config.iter().cloned());
    paths.extend(resolved.java_home.iter().cloned());
    paths.extend(resolved.component_baseline.iter().cloned());
    paths
}

fn plan_summary(collector: &dyn Collector, resolved: &ResolvedRun) -> Result<CollectorPlanSummary> {
    let discoveries = collector.discover(resolved)?;
    let plan = collector.plan(resolved, &discoveries)?;
    Ok(CollectorPlanSummary {
        name: collector.name().to_string(),
        enabled: plan.enabled,
        readonly: plan.readonly,
        active_check_allowed: plan.active_check_allowed,
        coverage_status: if plan.enabled && plan.inputs.is_empty() {
            "not_collected".to_string()
        } else if plan.enabled {
            "planned".to_string()
        } else {
            "disabled".to_string()
        },
        evidence_quality_on_gap: "Q5".to_string(),
        summary: plan.summary,
        inputs: plan.inputs,
        outputs: plan.outputs,
    })
}

pub fn path_strings(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, Commands};
    use crate::config::ResolvedRun;
    use crate::model::RunMode;

    #[test]
    fn dry_run_includes_v12_collectors_when_enabled() {
        let cli = Cli::parse_from([
            "dumpall",
            "scan",
            "--profile",
            "runtime",
            "--tomcat-base",
            "tomcat",
        ]);
        let Commands::Scan(scan) = cli.command else {
            panic!("expected scan command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Scan, &scan.common).unwrap();

        let plans = dry_run_plan(&resolved);
        let runtime = plans
            .iter()
            .find(|plan| plan.name == "runtime")
            .expect("runtime collector plan");

        assert!(runtime.enabled);
        assert!(runtime.readonly);
        assert!(runtime.inputs.iter().any(|input| input.contains("tomcat")));
        assert!(runtime
            .outputs
            .iter()
            .any(|output| output == "runtime/tomcat_components.csv"));
    }
}
