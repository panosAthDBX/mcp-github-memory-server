use std::any::Any;
use std::collections::HashMap;

use mcp_gitmem_core::{
    model::Memory,
    project::{ProjectId, DEFAULT_PROJECT_ID},
    traits::Storage,
};
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EphemeralError {
    #[error("not found: {0}")]
    NotFound(String),
}

pub struct EphemeralStorage {
    map: RwLock<HashMap<ProjectId, HashMap<String, Memory>>>,
}

impl EphemeralStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ensure_project(&self, project: &ProjectId) {
        let mut map = self.map.write();
        map.entry(project.clone()).or_default();
    }

    pub fn delete_project(&self, project: &ProjectId) -> bool {
        self.map.write().remove(project).is_some()
    }

    pub fn list_directory(&self, project: &ProjectId) -> Vec<String> {
        let map = self.map.read();
        map.get(project)
            .map(|inner| inner.keys().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for EphemeralStorage {
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }
}

impl Storage for EphemeralStorage {
    type Error = EphemeralError;

    fn save(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error> {
        let mut map = self.map.write();
        let entry = map.entry(project.clone()).or_default();
        entry.insert(memory.id.clone(), memory.clone());
        Ok(())
    }

    fn get(&self, project: &ProjectId, id: &str) -> Result<Option<Memory>, Self::Error> {
        let map = self.map.read();
        Ok(map.get(project).and_then(|inner| inner.get(id).cloned()))
    }

    fn update(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error> {
        let mut map = self.map.write();
        let inner = map.entry(project.clone()).or_default();
        if let Some(existing) = inner.get_mut(&memory.id) {
            *existing = memory.clone();
            Ok(())
        } else {
            Err(EphemeralError::NotFound(memory.id.clone()))
        }
    }

    fn delete(&self, project: &ProjectId, id: &str, _hard: bool) -> Result<(), Self::Error> {
        let mut map = self.map.write();
        match map.get_mut(project) {
            Some(inner) => {
                if inner.remove(id).is_some() {
                    Ok(())
                } else {
                    Err(EphemeralError::NotFound(id.to_string()))
                }
            }
            None => Err(EphemeralError::NotFound(id.to_string())),
        }
    }

    fn list_recent_ids(
        &self,
        project: &ProjectId,
        limit: usize,
    ) -> Result<Vec<String>, Self::Error> {
        let map = self.map.read();
        let mut v: Vec<String> = map
            .get(project)
            .map(|inner| inner.keys().cloned().collect())
            .unwrap_or_default();
        v.sort();
        v.truncate(limit);
        Ok(v)
    }

    fn list_projects(&self) -> Result<Vec<ProjectId>, Self::Error> {
        let map = self.map.read();
        let mut projects: Vec<ProjectId> = map.keys().cloned().collect();
        if projects.is_empty() {
            projects.push(DEFAULT_PROJECT_ID.to_string());
        }
        Ok(projects)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
