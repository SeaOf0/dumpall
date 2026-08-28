use std::path::Path;

use crate::config::ResolvedRun;
use crate::model::CollectionError;

use super::{push_java_artifact, push_warning, RuntimeInventory};

pub const COLLECTOR_SCOPE: &str = "java_runtime_paths";

pub(crate) fn collect_java_home(
    resolved: &ResolvedRun,
    java_home: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    if !java_home.exists() {
        push_warning(
            inventory,
            errors,
            "java",
            java_home,
            "discover",
            "Java home path does not exist",
            Some(
                "Provide a readable --java-home path if Java runtime context is required."
                    .to_string(),
            ),
        );
        return Ok(());
    }

    for relative in [
        "bin/java.exe",
        "bin/java",
        "bin/jcmd.exe",
        "bin/jcmd",
        "bin/jmap.exe",
        "bin/jmap",
    ] {
        let path = java_home.join(relative);
        if path.is_file() {
            push_java_artifact(
                inventory,
                resolved,
                "java",
                "java_tool",
                path.file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or(relative),
                "",
                &path,
                path.display().to_string(),
                "java_home",
                &[],
            );
        }
    }
    Ok(())
}
