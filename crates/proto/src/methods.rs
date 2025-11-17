use schemars::JsonSchema;
use serde::{de, Deserialize, Serialize};

pub const TOOL_MEMORY_SAVE: &str = "memory.save";
pub const TOOL_MEMORY_GET: &str = "memory.get";
pub const TOOL_MEMORY_SEARCH: &str = "memory.search";
pub const TOOL_MEMORY_UPDATE: &str = "memory.update";
pub const TOOL_MEMORY_DELETE: &str = "memory.delete";
pub const TOOL_MEMORY_IMPORT_BASIC: &str = "memory.import.basic";
pub const TOOL_MEMORY_SYNC: &str = "memory.sync";
pub const TOOL_MEMORY_ENCRYPT: &str = "memory.encrypt";
pub const TOOL_MEMORY_DECRYPT: &str = "memory.decrypt";
pub const TOOL_PROJECT_LINK_FOLDER: &str = "project.link_folder";
pub const TOOL_PROJECT_UNLINK_FOLDER: &str = "project.unlink_folder";
pub const METHOD_RESOURCES_LIST: &str = "resources/list";
pub const METHOD_RESOURCES_READ: &str = "resources/read";
/// Legacy alias kept for backwards compatibility with early clients.
pub const TOOL_RESOURCE_LIST: &str = "resource.list";
/// Legacy alias kept for backwards compatibility with early clients.
pub const TOOL_RESOURCE_READ: &str = "resource.read";
pub const METHOD_TOOLS_LIST: &str = "tools/list";
pub const METHOD_TOOLS_CALL: &str = "tools/call";
pub const TOOL_INITIALIZE: &str = "initialize";
pub const TOOL_LIST_MEMORY_PROJECTS: &str = "list_memory_projects";
pub const TOOL_CREATE_MEMORY_PROJECT: &str = "create_memory_project";
pub const TOOL_DELETE_MEMORY_PROJECT: &str = "delete_memory_project";
pub const TOOL_LIST_DIRECTORY: &str = "list_directory";
pub const TOOL_SYNC_STATUS: &str = "sync_status";
pub const TOOL_WRITE_NOTE: &str = "write_note";
pub const TOOL_READ_NOTE: &str = "read_note";
pub const TOOL_EDIT_NOTE: &str = "edit_note";
pub const TOOL_VIEW_NOTE: &str = "view_note";
pub const TOOL_DELETE_NOTE: &str = "delete_note";
pub const TOOL_MOVE_NOTE: &str = "move_note";
pub const TOOL_SEARCH_NOTES: &str = "search_notes";
pub const TOOL_RECENT_ACTIVITY: &str = "recent_activity";
pub const TOOL_BUILD_CONTEXT: &str = "build_context";
pub const TOOL_READ_CONTENT: &str = "read_content";
pub const TOOL_SEARCH: &str = "search";
pub const TOOL_FETCH: &str = "fetch";
pub const TOOL_PROJECT_INFO: &str = "project_info";
pub const TOOL_CANVAS: &str = "canvas";
pub const TOOL_AI_ASSISTANT_GUIDE: &str = "ai_assistant_guide";
pub const TOOL_CONTINUE_CONVERSATION: &str = "continue_conversation";
pub const TOOL_PROJECT_LIST_LINKS: &str = "project.list_links";
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

fn sanitize_tool_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => c,
            _ => '_',
        })
        .collect()
}

pub fn exported_tool_name(canonical: &str) -> String {
    sanitize_tool_name(canonical)
}

pub fn canonical_tool_name(name: &str) -> Option<&'static str> {
    const CANONICAL: [&str; 33] = [
        TOOL_MEMORY_SAVE,
        TOOL_MEMORY_GET,
        TOOL_MEMORY_SEARCH,
        TOOL_MEMORY_UPDATE,
        TOOL_MEMORY_DELETE,
        TOOL_MEMORY_IMPORT_BASIC,
        TOOL_MEMORY_SYNC,
        TOOL_MEMORY_ENCRYPT,
        TOOL_MEMORY_DECRYPT,
        TOOL_LIST_MEMORY_PROJECTS,
        TOOL_CREATE_MEMORY_PROJECT,
        TOOL_DELETE_MEMORY_PROJECT,
        TOOL_LIST_DIRECTORY,
        TOOL_SYNC_STATUS,
        TOOL_PROJECT_LINK_FOLDER,
        TOOL_PROJECT_UNLINK_FOLDER,
        TOOL_PROJECT_LIST_LINKS,
        TOOL_WRITE_NOTE,
        TOOL_READ_NOTE,
        TOOL_EDIT_NOTE,
        TOOL_VIEW_NOTE,
        TOOL_DELETE_NOTE,
        TOOL_MOVE_NOTE,
        TOOL_SEARCH_NOTES,
        TOOL_RECENT_ACTIVITY,
        TOOL_BUILD_CONTEXT,
        TOOL_READ_CONTENT,
        TOOL_SEARCH,
        TOOL_FETCH,
        TOOL_PROJECT_INFO,
        TOOL_CANVAS,
        TOOL_AI_ASSISTANT_GUIDE,
        TOOL_CONTINUE_CONVERSATION,
    ];
    for canonical in CANONICAL {
        if name == canonical || name == sanitize_tool_name(canonical) {
            return Some(canonical);
        }
    }
    None
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion", default)]
    pub protocol_version: Option<String>,
    #[serde(default)]
    pub capabilities: Option<serde_json::Value>,
    #[serde(rename = "clientInfo", default)]
    pub client_info: Option<ClientInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ClientInfo {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SaveParams {
    pub title: Option<String>,
    pub content: String,
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub ttl: Option<String>,
    pub score: Option<f32>,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GetParams {
    pub id: String,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SearchParamsWire {
    #[serde(deserialize_with = "deserialize_query")]
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<serde_json::Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub offset: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub sort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

impl Default for SearchParamsWire {
    fn default() -> Self {
        Self {
            query: String::new(),
            filters: None,
            time_range: None,
            limit: None,
            offset: None,
            sort: None,
            project: None,
        }
    }
}

fn deserialize_query<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    coerce_query(value).map_err(de::Error::custom)
}

fn deserialize_opt_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    coerce_opt_string(value).map_err(de::Error::custom)
}

fn deserialize_opt_u32<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    coerce_opt_u32(value).map_err(de::Error::custom)
}

fn coerce_query(value: Option<serde_json::Value>) -> Result<String, String> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(String::new()),
        Some(serde_json::Value::String(s)) => Ok(s.trim().to_owned()),
        Some(v) => Ok(extract_string(&v).unwrap_or_else(|| v.to_string())),
    }
}

fn coerce_opt_string(value: Option<serde_json::Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => Ok(extract_string(&v)),
    }
}

fn coerce_opt_u32(value: Option<serde_json::Value>) -> Result<Option<u32>, String> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => value_to_u32(&v),
    }
}

fn extract_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        serde_json::Value::Array(items) => {
            let mut parts = Vec::new();
            for item in items {
                if let Some(seg) = extract_string(item) {
                    if !seg.is_empty() {
                        parts.push(seg);
                    }
                }
            }
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(" "))
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["query", "text", "value", "content", "message", "string"] {
                if let Some(found) = map.get(key) {
                    if let Some(val) = extract_string(found) {
                        if !val.is_empty() {
                            return Some(val);
                        }
                    }
                }
            }
            if let Some(parts) = map.get("parts").and_then(|v| v.as_array()) {
                for part in parts {
                    if let Some(val) = extract_string(part) {
                        if !val.is_empty() {
                            return Some(val);
                        }
                    }
                }
            }
            None
        }
    }
}

fn value_to_u32(value: &serde_json::Value) -> Result<Option<u32>, String> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > u32::MAX as u64 {
                    return Err(format!("value {u} exceeds u32 range"));
                }
                return Ok(Some(u as u32));
            }
            if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Err(format!("value {i} must not be negative"));
                }
                if i > u32::MAX as i64 {
                    return Err(format!("value {i} exceeds u32 range"));
                }
                return Ok(Some(i as u32));
            }
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err("numeric value must be finite".into());
                }
                if f < 0.0 {
                    return Err(format!("value {f} must not be negative"));
                }
                let truncated = f.trunc();
                if (f - truncated).abs() > f64::EPSILON {
                    return Err(format!("value {f} must be a whole number"));
                }
                if truncated > u32::MAX as f64 {
                    return Err(format!("value {f} exceeds u32 range"));
                }
                return Ok(Some(truncated as u32));
            }
            Err(format!("unsupported numeric literal {n}"))
        }
        serde_json::Value::String(s) => parse_string_to_u32(s),
        serde_json::Value::Bool(_) => Err("boolean is not a valid positive integer".into()),
        serde_json::Value::Array(items) => {
            for item in items {
                if let Some(v) = value_to_u32(item)? {
                    return Ok(Some(v));
                }
            }
            Ok(None)
        }
        serde_json::Value::Object(map) => {
            for key in ["value", "integer", "number", "limit", "count", "amount"] {
                if let Some(inner) = map.get(key) {
                    if let Some(v) = value_to_u32(inner)? {
                        return Ok(Some(v));
                    }
                }
            }
            for key in ["text", "string"] {
                if let Some(inner) = map.get(key) {
                    if let Some(v) = value_to_u32(inner)? {
                        return Ok(Some(v));
                    }
                }
            }
            if let Some(inner) = map.get("query") {
                if let Some(v) = value_to_u32(inner)? {
                    return Ok(Some(v));
                }
            }
            if let Some(s) = extract_string(value) {
                return parse_string_to_u32(&s);
            }
            Ok(None)
        }
    }
}

fn parse_string_to_u32(input: &str) -> Result<Option<u32>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.starts_with('-') {
        return Err(format!("value \"{trimmed}\" must not be negative"));
    }
    let sanitized = trimmed.strip_prefix('+').unwrap_or(trimmed);
    if let Some(value) = parse_basic_integer(sanitized) {
        return Ok(Some(value));
    }
    Err(format!(
        "unable to parse positive integer from \"{trimmed}\""
    ))
}

fn parse_basic_integer(input: &str) -> Option<u32> {
    let digits = input.replace('_', "");
    if digits.is_empty() {
        return None;
    }
    if let Ok(v) = digits.parse::<u32>() {
        return Some(v);
    }
    if let Some(idx) = digits.find('.') {
        let (int_part, frac_part) = digits.split_at(idx);
        if frac_part.trim_matches('0') == "." {
            let normalized = if int_part.is_empty() { "0" } else { int_part };
            if let Ok(v) = normalized.parse::<u32>() {
                return Some(v);
            }
        }
    }
    None
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UpdateParams {
    pub id: String,
    pub patch: serde_json::Value,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeleteParams {
    pub id: String,
    #[serde(default)]
    pub hard: Option<bool>,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ImportBasicParams {
    pub path: String,
    pub dry_run: Option<bool>,
    pub map_types: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SyncParams {
    pub direction: Option<String>,
    pub pr: Option<bool>,
    pub remote: Option<String>,
    pub branch: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceListParams {
    pub limit: Option<u32>,
    #[serde(rename = "cursor", default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct ListToolsParams {
    #[serde(rename = "cursor", default)]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct ResourceDescriptor {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceListResult {
    pub resources: Vec<ResourceDescriptor>,
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceReadParams {
    pub uri: String,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct ResourceContents {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceReadResult {
    pub contents: Vec<ResourceContents>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct ListMemoryProjectsParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MemoryProjectDescriptor {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListMemoryProjectsResult {
    pub projects: Vec<MemoryProjectDescriptor>,
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateMemoryProjectParams {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeleteProjectParams {
    pub id: String,
    #[serde(default)]
    pub force: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct ListDirectoryParams {
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DirectoryEntry {
    pub name: String,
    pub path: String,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListDirectoryResult {
    pub entries: Vec<DirectoryEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct SyncStatusParams {
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SyncStatusResult {
    pub project: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LinkFolderParams {
    pub project: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rescan: Option<bool>,
    #[serde(rename = "watchMode", default, skip_serializing_if = "Option::is_none")]
    pub watch_mode: Option<String>,
    #[serde(
        rename = "pollIntervalMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub poll_interval_ms: Option<u64>,
    #[serde(rename = "jitterPct", default, skip_serializing_if = "Option::is_none")]
    pub jitter_pct: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LinkFolderResult {
    pub project: String,
    pub path: String,
    #[serde(
        rename = "displayPath",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub display_path: Option<String>,
    #[serde(rename = "resolvedPath")]
    pub resolved_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    #[serde(rename = "linkId")]
    pub link_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch: Option<LinkWatchInfo>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "lastScan", default, skip_serializing_if = "Option::is_none")]
    pub last_scan: Option<String>,
    #[serde(rename = "fileCount", default, skip_serializing_if = "Option::is_none")]
    pub file_count: Option<u64>,
    #[serde(
        rename = "totalBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub total_bytes: Option<u64>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(
        rename = "lastRuntimeMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_runtime_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct UnlinkFolderParams {
    pub project: String,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UnlinkFolderResult {
    pub project: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct ListLinkedFoldersParams {
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LinkedFolderDescriptor {
    pub project: String,
    pub path: String,
    #[serde(
        rename = "displayPath",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub display_path: Option<String>,
    #[serde(rename = "resolvedPath")]
    pub resolved_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    #[serde(rename = "linkId")]
    pub link_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch: Option<LinkWatchInfo>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "lastScan", default, skip_serializing_if = "Option::is_none")]
    pub last_scan: Option<String>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "fileCount", default, skip_serializing_if = "Option::is_none")]
    pub file_count: Option<u64>,
    #[serde(
        rename = "totalBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(
        rename = "lastRuntimeMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_runtime_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListLinkedFoldersResult {
    pub links: Vec<LinkedFolderDescriptor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LinkWatchInfo {
    pub mode: String,
    #[serde(
        rename = "pollIntervalMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub poll_interval_ms: Option<u64>,
    #[serde(rename = "jitterPct", default, skip_serializing_if = "Option::is_none")]
    pub jitter_pct: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct WriteNoteParams {
    pub content: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note_type: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
}


#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReadNoteParams {
    pub id: String,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EditNoteParams {
    pub id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note_type: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeleteNoteParams {
    pub id: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub hard: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MoveNoteParams {
    pub id: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(rename = "target_project")]
    pub target_project: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct SearchNotesParams {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note_types: Option<Vec<String>>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SearchNotesResult {
    pub notes: Vec<serde_json::Value>,
    pub total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct RecentActivityParams {
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecentActivityResult {
    pub notes: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct BuildContextParams {
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub query: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BuildContextResult {
    pub notes: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReadContentParams {
    pub id: String,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReadContentResult {
    pub id: String,
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SearchPromptParams {
    pub query: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SearchPromptResult {
    pub query: String,
    pub project: String,
    pub total: u64,
    pub results: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct FetchParams {
    pub id: String,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct FetchResult {
    pub id: String,
    pub project: String,
    pub title: String,
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(rename = "type")]
    pub note_type: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct ProjectInfoParams {
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub recent_limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProjectInfoResult {
    pub project: String,
    #[serde(rename = "noteCount")]
    pub note_count: u64,
    #[serde(rename = "lastUpdated", skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,
    #[serde(rename = "recentNotes", skip_serializing_if = "Vec::is_empty", default)]
    pub recent_notes: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CanvasParams {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub nodes: Vec<serde_json::Value>,
    #[serde(default)]
    pub edges: Vec<serde_json::Value>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CanvasResult {
    pub id: String,
    pub project: String,
    pub title: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct AiAssistantGuideParams {
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AiAssistantGuideResult {
    pub title: String,
    pub sections: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct ContinueConversationParams {
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ContinueConversationResult {
    pub topic: Option<String>,
    pub project: String,
    pub suggestions: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EncryptParams {
    pub id: String,
    pub recipients: Vec<String>,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecryptParams {
    pub id: String,
    pub identity: String,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListToolsResult {
    pub tools: Vec<ToolDefinition>,
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CallToolParams {
    #[serde(rename = "toolName", alias = "name")]
    pub tool_name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ToolResponseContent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CallToolResult {
    pub content: Vec<ToolResponseContent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CapabilitiesMemory {
    pub version: u32,
    pub encryption: bool,
    pub search: String,
    pub ttl: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CapabilitiesStorage {
    pub github: bool,
    pub local: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CapabilitiesTransport {
    pub stdio: bool,
    pub ws: bool,
    pub http: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: serde_json::Value,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ServerInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "websiteUrl")]
    pub website_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<Vec<ServerIcon>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ServerIcon {
    pub src: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sizes: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema::{InstanceType, Schema, SingleOrVec};
    use serde_json::json;

    #[test]
    fn search_params_query_defaults_to_string_empty() {
        let schema = schemars::schema_for!(SearchParamsWire);
        let object_validation = schema
            .schema
            .object
            .as_ref()
            .expect("expected object validation for SearchParamsWire");
        let query_schema = object_validation
            .properties
            .get("query")
            .expect("query property missing");
        let Schema::Object(query_obj) = query_schema else {
            panic!("expected object schema for query");
        };
        let instance_type = query_obj
            .instance_type
            .as_ref()
            .expect("missing instance type for query");
        match instance_type {
            SingleOrVec::Single(single) => {
                assert!(matches!(**single, InstanceType::String));
            }
            SingleOrVec::Vec(_) => panic!("query type should not be a union"),
        }
        let default_value = query_obj
            .metadata
            .as_ref()
            .and_then(|meta| meta.default.clone())
            .expect("query default missing");
        assert_eq!(default_value, serde_json::Value::String(String::new()));
    }

    #[test]
    fn exported_tool_name_replaces_invalid_characters() {
        let exported = exported_tool_name(TOOL_MEMORY_IMPORT_BASIC);
        assert_eq!(exported, "memory_import_basic");
    }

    #[test]
    fn canonical_tool_name_accepts_sanitized_names() {
        let canonical = canonical_tool_name("memory_sync");
        assert_eq!(canonical, Some(TOOL_MEMORY_SYNC));
    }

    #[test]
    fn search_params_wire_accepts_structured_query_payload() {
        let value = json!({
            "query": {
                "type": "input_text",
                "text": "   hello world   "
            }
        });
        let parsed: SearchParamsWire =
            serde_json::from_value(value).expect("parse structured query");
        assert_eq!(parsed.query, "hello world");
    }

    #[test]
    fn search_params_wire_coerces_wrapped_limit_and_offset() {
        let value = json!({
            "query": "matching",
            "limit": {
                "type": "integer",
                "integer": "5"
            },
            "offset": {
                "value": 2.0
            }
        });
        let parsed: SearchParamsWire =
            serde_json::from_value(value).expect("parse wrapped numerics");
        assert_eq!(parsed.limit, Some(5));
        assert_eq!(parsed.offset, Some(2));
    }

    #[test]
    fn search_params_wire_handles_stringified_numbers() {
        let value = json!({
            "query": "foo",
            "limit": "10",
            "offset": "+3",
            "sort": { "value": "recency" }
        });
        let parsed: SearchParamsWire =
            serde_json::from_value(value).expect("parse stringified numbers");
        assert_eq!(parsed.limit, Some(10));
        assert_eq!(parsed.offset, Some(3));
        assert_eq!(parsed.sort.as_deref(), Some("recency"));
    }

    #[test]
    fn search_params_wire_preserves_filters_object() {
        let value = json!({
            "filters": {
                "type": ["fact"],
                "tags": ["b"]
            }
        });
        let parsed: SearchParamsWire = serde_json::from_value(value).expect("parse filters");
        let filters = parsed.filters.expect("filters missing");
        let filter_type = filters
            .get("type")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.get(0))
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(filter_type, "fact");
        let filter_tag = filters
            .get("tags")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.get(0))
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(filter_tag, "b");
    }
    
    #[test]
    fn write_note_params_tags_schema_inspection() {
        let schema = schemars::schema_for!(WriteNoteParams);
        println!("\nFull WriteNoteParams schema:");
        println!("{}", serde_json::to_string_pretty(&schema).unwrap());
        
        let object_validation = schema
            .schema
            .object
            .as_ref()
            .expect("expected object validation for WriteNoteParams");
        
        if let Some(tags_schema) = object_validation.properties.get("tags") {
            println!("\nTags property schema:");
            println!("{}", serde_json::to_string_pretty(tags_schema).unwrap());
            
            if let Schema::Object(tags_obj) = tags_schema {
                println!("\nTags instance_type: {:?}", tags_obj.instance_type);
            }
        } else {
            panic!("tags property not found in schema");
        }
    }
}
