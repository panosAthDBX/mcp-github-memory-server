//! Project identifiers and helpers for workspace-scoped storage.

use regex::Regex;

pub type ProjectId = String;

pub const DEFAULT_PROJECT_ID: &str = "default";

pub fn sanitize_project_id(raw: &str) -> ProjectId {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DEFAULT_PROJECT_ID.to_string();
    }
    let re = Regex::new(r"[^A-Za-z0-9_\-]").expect("valid regex");
    let cleaned = re.replace_all(trimmed, "_");
    cleaned.to_string()
}
