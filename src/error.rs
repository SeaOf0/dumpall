use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, DumpallError>;

#[derive(Debug, Error)]
pub enum DumpallError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("output directory already exists and will not be overwritten: {0}")]
    OutputDirectoryExists(PathBuf),

    #[error("invalid argument `{field}`: {message}")]
    InvalidArgument {
        field: &'static str,
        message: String,
    },

    #[error("rule validation failed: {0}")]
    RuleValidation(String),

    #[error("{0}")]
    Message(String),
}

impl DumpallError {
    pub fn invalid_argument(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidArgument {
            field,
            message: message.into(),
        }
    }

    pub fn rule_validation(message: impl Into<String>) -> Self {
        Self::RuleValidation(message.into())
    }
}
