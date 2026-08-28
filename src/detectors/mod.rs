pub mod aggregations;
pub mod allowlist;
pub mod app;
pub mod container;
pub mod db;
pub mod host_enrichment;
pub mod linux_events;
pub mod matcher;
pub mod rule_engine;
pub mod rule_model;
pub mod runtime;
pub mod scoring;
pub mod static_scan;
pub mod waf;
pub mod windows_events;
pub mod yara_scan;

pub use rule_engine::{run_detection, DetectionReport};
