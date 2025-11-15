use mcp_gitmem_core::model::Memory;
use mcp_gitmem_core::project::{sanitize_project_id, ProjectId, DEFAULT_PROJECT_ID};
use mcp_gitmem_core::traits::{Index, Storage};
use mcp_gitmem_index_tantivy::TantivyIndex;
use mcp_gitmem_storage_ephemeral::EphemeralStorage;
use mcp_gitmem_storage_local::LocalStorage;
use std::time::Instant;

pub struct EphemeralStack {
    pub storage: EphemeralStorage,
    pub index: TantivyIndex,
    pub project: ProjectId,
}

impl EphemeralStack {
    pub fn new(project: &str) -> Self {
        Self {
            storage: EphemeralStorage::new(),
            index: TantivyIndex::new(),
            project: sanitize_project_id(project),
        }
    }

    pub fn save_all(&self, memories: &[Memory]) {
        for memory in memories {
            self.storage
                .save(&self.project, memory)
                .expect("storage save");
            self.index
                .update(&self.project, memory)
                .expect("index update");
        }
    }
}

pub struct LocalStack {
    pub storage: LocalStorage,
    pub index: TantivyIndex,
    pub project: ProjectId,
    pub root: tempfile::TempDir,
}

impl LocalStack {
    pub fn new(project: &str) -> Self {
        let root = tempfile::tempdir().expect("create local bench dir");
        let storage = LocalStorage::new(root.path());
        let index = TantivyIndex::new();
        Self {
            storage,
            index,
            project: sanitize_project_id(project),
            root,
        }
    }

    pub fn save_all(&self, memories: &[Memory]) {
        for memory in memories {
            self.storage
                .save(&self.project, memory)
                .expect("storage save");
            self.index
                .update(&self.project, memory)
                .expect("index update");
        }
    }
}

pub fn measure_search<I>(index: &I, project: &ProjectId, query: &str) -> usize
where
    I: Index,
{
    let params = mcp_gitmem_core::traits::SearchParams {
        query: query.to_string(),
        types: None,
        tags: None,
        limit: Some(20),
        offset: Some(0),
        sort: None,
        from_time: None,
        to_time: None,
    };
    index.search(project, &params).expect("search").items.len()
}

pub fn measure_save<S, I>(storage: &S, index: &I, project: &ProjectId, memories: &[Memory])
where
    S: Storage,
    I: Index,
{
    for memory in memories {
        storage.save(project, memory).expect("storage save");
        index.update(project, memory).expect("index update");
    }
}

pub fn save_with_timing<S, I>(
    storage: &S,
    index: &I,
    project: &ProjectId,
    memories: &[Memory],
) -> u128
where
    S: Storage,
    I: Index,
{
    let start = Instant::now();
    measure_save(storage, index, project, memories);
    start.elapsed().as_micros()
}

pub fn default_project() -> ProjectId {
    DEFAULT_PROJECT_ID.to_string()
}
