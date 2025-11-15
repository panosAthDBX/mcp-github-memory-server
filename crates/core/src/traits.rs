use crate::{model::Memory, project::ProjectId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::any::Any;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchParams {
    pub query: String,
    #[serde(default)]
    pub types: Option<Vec<String>>, // filter by type
    #[serde(default)]
    pub tags: Option<Vec<String>>, // filter by tags
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_time: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: String,
    pub score: Option<f32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResults {
    pub items: Vec<SearchResult>,
    pub total: u64,
}

/// Storage trait to be implemented by storage adapters.
/// No async in core; callers should use spawn_blocking when invoking from async contexts.
pub trait Storage {
    type Error: std::error::Error + Send + Sync + 'static;

    fn save(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error>;
    fn get(&self, project: &ProjectId, id: &str) -> Result<Option<Memory>, Self::Error>;
    fn update(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error>;
    fn delete(&self, project: &ProjectId, id: &str, hard: bool) -> Result<(), Self::Error>;

    /// Return a list of recent memory IDs for warm-up or resource listing.
    fn list_recent_ids(
        &self,
        project: &ProjectId,
        limit: usize,
    ) -> Result<Vec<String>, Self::Error>;

    fn list_projects(&self) -> Result<Vec<ProjectId>, Self::Error>;

    fn as_any(&self) -> &dyn Any;
}

/// Index trait for search backends.
pub trait Index {
    type Error: std::error::Error + Send + Sync + 'static;

    fn update(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error>;
    fn delete(&self, project: &ProjectId, id: &str) -> Result<(), Self::Error>;
    fn search(
        &self,
        project: &ProjectId,
        params: &SearchParams,
    ) -> Result<SearchResults, Self::Error>;
}
