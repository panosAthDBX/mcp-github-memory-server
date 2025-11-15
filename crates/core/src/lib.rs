//! Core domain model, validation, and traits.
//! No async and no IO within this crate.

pub mod errors;
pub mod model;
pub mod project;
pub mod traits;
pub mod validate;

pub use crate::errors::{CoreError, ValidationError};
pub use crate::model::{CompatMeta, EncryptionMeta, Memory, MemoryId, SourceMeta};
pub use crate::project::{sanitize_project_id, ProjectId, DEFAULT_PROJECT_ID};
pub use crate::traits::{Index, SearchParams, SearchResult, SearchResults, Storage};
pub use crate::validate::{is_valid_type, normalize_type, parse_ttl_iso8601, ttl_not_expired};
