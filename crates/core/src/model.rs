use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type MemoryId = String;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptionMeta {
    pub algo: Option<String>,
    pub kid: Option<String>,
    pub encrypted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct SourceMeta {
    pub agent: Option<String>,
    pub session: Option<String>,
    pub origin: Option<String>,
    pub app: Option<String>,
    #[serde(default)]
    pub file_uri: Option<String>,
    #[serde(default)]
    pub relative_path: Option<String>,
    #[serde(default)]
    pub checksum_sha256: Option<String>,
    #[serde(default)]
    pub linked_folder_id: Option<String>,
    #[serde(default)]
    pub file_mtime: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub front_matter: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct CompatMeta {
    pub basic_id: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Memory {
    pub id: MemoryId,
    pub version: u32,
    #[serde(rename = "type")]
    pub r#type: String,
    pub title: String,
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub source: Option<SourceMeta>,
    pub score: Option<f32>,
    /// TTL as ISO 8601 duration string or null.
    pub ttl: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub encryption: Option<EncryptionMeta>,
    #[serde(default)]
    pub compat: Option<CompatMeta>,
}

impl Memory {
    pub fn new(title: &str, content: &str, r#type: &str) -> Self {
        let now = Utc::now();
        let id = format!("mem_{}", uuid::Uuid::new_v4());
        Self {
            id,
            version: 1,
            r#type: r#type.to_owned(),
            title: title.to_owned(),
            content: content.to_owned(),
            tags: Vec::new(),
            source: None,
            score: None,
            ttl: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
            encryption: Some(EncryptionMeta {
                algo: None,
                kid: None,
                encrypted: false,
            }),
            compat: None,
        }
    }
}
