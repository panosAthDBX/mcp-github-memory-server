use std::{
    any::Any,
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(feature = "remote-git")]
use std::sync::Arc;

use chrono::{DateTime, Datelike, Utc};
use mcp_gitmem_core::{
    model::{Memory, SourceMeta},
    project::{sanitize_project_id, ProjectId, DEFAULT_PROJECT_ID},
    traits::Storage,
};
use mcp_gitmem_storage_local::{LinkedFolderInfo, RescanReport};
use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use fs4::FileExt;

#[derive(Debug, Error)]
pub enum GithubError {
    #[error("io: {0}")]
    Io(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("git: {0}")]
    Git(String),
    #[error("conflict: {0}")]
    Conflict(String),
}

#[derive(Clone)]
pub enum CredentialMode {
    Helper,
    UserPass,
    Token,
    SshAgent,
}

#[derive(Clone)]
#[allow(dead_code)]
struct CredentialConfig {
    mode: CredentialMode,
    username: Option<String>,
    secret_env: Option<String>,
    // Cached credential value (resolved at initialization)
    cached_secret: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Clone)]
struct Manifest {
    ids: HashMap<String, String>,
    recent: VecDeque<String>,
}

// External folder linking structures
#[derive(Default, Serialize, Deserialize, Clone)]
struct LinkRegistry {
    entries: Vec<LinkEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct LinkEntry {
    #[serde(default = "LinkEntry::generate_id")]
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display: Option<String>,
    path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    include: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exclude: Option<Vec<String>>,
    #[serde(default)]
    mappings: HashMap<String, String>, // relative file -> memory id
    watch: LinkWatchSettings,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "lastScan", default, skip_serializing_if = "Option::is_none")]
    last_scan: Option<String>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    #[serde(rename = "fileCount", default)]
    file_count: u64,
    #[serde(rename = "totalBytes", default)]
    total_bytes: u64,
    #[serde(
        rename = "lastRuntimeMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    last_runtime_ms: Option<u64>,
}

impl LinkEntry {
    fn generate_id() -> String {
        format!("lf_{}", uuid::Uuid::new_v4().simple())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum WatchMode {
    #[serde(rename = "poll")]
    Poll,
}

impl Default for WatchMode {
    fn default() -> Self {
        Self::Poll
    }
}

impl WatchMode {
    fn parse(input: &str) -> Result<Self, GithubError> {
        match input.to_lowercase().as_str() {
            "poll" => Ok(WatchMode::Poll),
            other => Err(GithubError::Io(format!(
                "unknown watch mode '{}'; supported: poll",
                other
            ))),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            WatchMode::Poll => "poll",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LinkWatchSettings {
    #[serde(default)]
    mode: WatchMode,
    #[serde(rename = "pollIntervalMs")]
    poll_interval_ms: u64,
    #[serde(rename = "jitterPct")]
    jitter_pct: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
}

impl Default for LinkWatchSettings {
    fn default() -> Self {
        Self {
            mode: WatchMode::Poll,
            poll_interval_ms: 30_000,
            jitter_pct: 20,
            platform: None,
        }
    }
}

#[derive(Default)]
struct LinkScanStats {
    scanned: usize,
    created: usize,
    updated: usize,
    deleted: usize,
    total_bytes: u64,
    file_count: u64,
}

#[derive(Default, Clone, Deserialize)]
struct FrontMatter {
    title: Option<String>,
    tags: Option<Vec<String>>,
    r#type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GithubDirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
}

#[derive(Debug, Clone)]
pub struct GithubSyncState {
    pub dirty: bool,
    pub commit_batch_ms: u64,
    pub device_branch: String,
    pub since_last_commit: Option<Duration>,
}

/// Local clone mode (working tree path). gix commit/push are stubbed for M3.
pub struct GithubStorage {
    workdir: PathBuf,
    meta_root: PathBuf,
    manifests: RwLock<HashMap<ProjectId, Manifest>>,
    commit_batch_ms: u64,
    last_commit: RwLock<Option<Instant>>,
    dirty: RwLock<bool>,
    remote_name: String,
    cred: Option<CredentialConfig>,
    device_branch: RwLock<String>,
    auto_push_enabled: RwLock<bool>,
    remote_url: RwLock<Option<String>>,
    bulk_operation_in_progress: RwLock<bool>,
}

impl GithubStorage {
    pub fn new<P: AsRef<Path>>(workdir: P) -> Result<Self, GithubError> {
        let workdir = workdir.as_ref().to_path_buf();
        let meta_root = workdir.join("meta");
        fs::create_dir_all(&meta_root).map_err(|e| GithubError::Io(e.to_string()))?;
        fs::create_dir_all(workdir.join("memories")).map_err(|e| GithubError::Io(e.to_string()))?;
        let mut manifests = HashMap::new();
        let default_project = DEFAULT_PROJECT_ID.to_string();
        let manifest = Self::load_manifest(&meta_root.join(&default_project).join("MANIFEST.json"))
            .unwrap_or_default();
        manifests.insert(default_project, manifest);
        Ok(Self {
            workdir,
            meta_root,
            manifests: RwLock::new(manifests),
            commit_batch_ms: 1500,
            last_commit: RwLock::new(None),
            dirty: RwLock::new(false),
            remote_name: "sync".into(),
            cred: None,
            device_branch: RwLock::new(Self::default_device_branch()),
            auto_push_enabled: RwLock::new(false),
            remote_url: RwLock::new(None),
            bulk_operation_in_progress: RwLock::new(false),
        })
    }

    pub fn set_commit_batch_ms(&mut self, ms: u64) {
        self.commit_batch_ms = ms;
    }
    pub fn set_remote_name(&mut self, name: String) {
        if !name.trim().is_empty() {
            self.remote_name = name;
        }
    }
    pub fn set_credentials(
        &mut self,
        mode: CredentialMode,
        username: Option<String>,
        secret_env: Option<String>,
    ) {
        // Cache the secret value NOW (when credentials are set) rather than looking it up later
        let cached_secret = secret_env.as_deref().and_then(|k| std::env::var(k).ok());
        
        if cached_secret.is_none() && secret_env.is_some() {
            tracing::warn!(
                env_var = ?secret_env,
                "credential secret environment variable not found or empty"
            );
        }
        
        self.cred = Some(CredentialConfig {
            mode,
            username,
            secret_env,
            cached_secret,
        });
    }

    pub fn enable_auto_push(&self, remote_url: String) {
        *self.auto_push_enabled.write() = true;
        *self.remote_url.write() = Some(remote_url);
    }

    pub fn disable_auto_push(&self) {
        *self.auto_push_enabled.write() = false;
    }

    pub fn is_auto_push_enabled(&self) -> bool {
        *self.auto_push_enabled.read()
    }

    pub fn get_remote_url(&self) -> Option<String> {
        self.remote_url.read().clone()
    }

    /// Acquire global push lock to coordinate between multiple gitmem instances.
    /// Uses a file lock in /tmp to ensure FIFO ordering and prevent concurrent pushes.
    fn acquire_push_lock() -> Result<File, GithubError> {
        let lock_path = std::env::temp_dir().join("gitmem-push.lock");
        
        // Open or create the lock file
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| GithubError::Io(format!("failed to open push lock file: {}", e)))?;
        
        tracing::debug!("acquiring push lock");
        
        // Acquire exclusive lock (blocks until available, FIFO order)
        lock_file
            .lock_exclusive()
            .map_err(|e| GithubError::Io(format!("failed to acquire push lock: {}", e)))?;
        
        tracing::debug!("push lock acquired");
        
        Ok(lock_file)
    }

    fn auto_push_if_enabled(&self) {
        if !self.is_auto_push_enabled() {
            return;
        }

        // Skip auto-push entirely during bulk operations (folder scans)
        // The bulk operation will do a single push at the end
        if *self.bulk_operation_in_progress.read() {
            *self.dirty.write() = true;
            return;
        }

        let remote_url = match self.get_remote_url() {
            Some(url) => url,
            None => {
                tracing::warn!("auto-push enabled but no remote URL configured");
                return;
            }
        };

        // Rate limit: Skip if we pushed less than 5 seconds ago to avoid
        // hundreds of push attempts during bulk imports
        let last_push = *self.last_commit.read();
        if let Some(last) = last_push {
            if Instant::now().duration_since(last) < Duration::from_secs(5) {
                tracing::trace!("skipping auto-push: too recent");
                *self.dirty.write() = true; // Mark dirty so next push includes this change
                return;
            }
        }

        // Acquire lock ONLY for the flush + push sequence
        let _lock_guard = match Self::acquire_push_lock() {
            Ok(lock) => lock,
            Err(e) => {
                tracing::error!(error = %e, "failed to acquire push lock, skipping auto-push");
                return;
            }
        };

        // Flush any pending commits while holding the lock
        if let Err(e) = self.flush() {
            tracing::error!(error = %e, "auto-push: flush failed");
            return;
        }

        // Push to remote while holding the lock
        let span = tracing::info_span!("storage.github.auto_push", remote = %remote_url);
        let _guard = span.enter();

        match self.push(&remote_url, None) {
            Ok(()) => {
                tracing::debug!("auto-push succeeded");
            }
            Err(e) => {
                tracing::error!(error = %e, remote = %remote_url, "auto-push failed");
            }
        }

        // Lock is automatically released when _lock_guard is dropped
    }

    fn load_manifest(path: &Path) -> Result<Manifest, GithubError> {
        if !path.exists() {
            return Ok(Manifest::default());
        }
        let mut s = String::new();
        File::open(path)
            .map_err(|e| GithubError::Io(e.to_string()))?
            .read_to_string(&mut s)
            .map_err(|e| GithubError::Io(e.to_string()))?;
        serde_json::from_str(&s).map_err(|e| GithubError::Serde(e.to_string()))
    }

    fn manifest_path(&self, project: &ProjectId) -> PathBuf {
        self.meta_root.join(project).join("MANIFEST.json")
    }

    fn ensure_project_dirs(&self, project: &ProjectId) -> Result<(), GithubError> {
        let memories = self.workdir.join("memories").join(project);
        fs::create_dir_all(&memories).map_err(|e| GithubError::Io(e.to_string()))?;
        let meta = self.meta_root.join(project);
        fs::create_dir_all(&meta).map_err(|e| GithubError::Io(e.to_string()))?;
        Ok(())
    }

    fn load_or_cache_manifest(&self, project: &ProjectId) -> Result<Manifest, GithubError> {
        {
            let manifests = self.manifests.read();
            if let Some(man) = manifests.get(project) {
                return Ok(man.clone());
            }
        }
        self.ensure_project_dirs(project)?;
        let path = self.manifest_path(project);
        let loaded = Self::load_manifest(&path).unwrap_or_default();
        {
            let mut manifests = self.manifests.write();
            manifests.insert(project.clone(), loaded.clone());
        }
        Ok(loaded)
    }

    fn save_manifest(&self, project: &ProjectId, m: &Manifest) -> Result<(), GithubError> {
        self.ensure_project_dirs(project)?;
        let path = self.manifest_path(project);
        let dir = path
            .parent()
            .ok_or_else(|| GithubError::Io("manifest parent missing".into()))?;
        let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let tmp = dir.join(format!(".tmp-manifest-{}.json", ts));
        let data = serde_json::to_vec_pretty(m).map_err(|e| GithubError::Serde(e.to_string()))?;
        write_atomic(&tmp, &path, &data)
    }

    pub fn list_directory(
        &self,
        project: &ProjectId,
        rel: &str,
    ) -> Result<Vec<GithubDirEntry>, GithubError> {
        let project = sanitize_project_id(project);
        self.ensure_project_dirs(&project)?;
        let trimmed = rel.trim_matches('/');
        if trimmed.contains("..") {
            return Err(GithubError::Io("path traversal not allowed".into()));
        }
        let base = if trimmed.is_empty() {
            self.workdir.join("memories").join(&project)
        } else {
            self.workdir.join("memories").join(&project).join(trimmed)
        };
        if !base.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(&base).map_err(|e| GithubError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| GithubError::Io(e.to_string()))?;
            let name = entry
                .file_name()
                .into_string()
                .unwrap_or_else(|_| "<invalid>".into());
            let rel_path = if trimmed.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", trimmed, name)
            };
            let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
            entries.push(GithubDirEntry {
                name,
                path: rel_path,
                is_dir,
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    pub fn create_project(&self, project: &ProjectId) -> Result<(), GithubError> {
        let project = sanitize_project_id(project);
        self.ensure_project_dirs(&project)?;
        let manifest_path = self.manifest_path(&project);
        if manifest_path.exists() {
            // Ensure the manifest cache is hydrated when the project already exists.
            let _ = self.load_or_cache_manifest(&project)?;
            return Ok(());
        }
        let manifest = Manifest::default();
        self.save_manifest(&project, &manifest)?;
        self.manifests.write().insert(project.clone(), manifest);
        let msg = format!("chore(mem): create project ({project})");
        self.maybe_commit(&msg)
    }

    pub fn delete_project(&self, project: &ProjectId) -> Result<(), GithubError> {
        let project = sanitize_project_id(project);
        let mut touched = false;
        {
            let mut manifests = self.manifests.write();
            if manifests.remove(&project).is_some() {
                touched = true;
            }
        }
        let memories = self.workdir.join("memories").join(&project);
        if memories.exists() {
            fs::remove_dir_all(&memories).map_err(|e| {
                GithubError::Io(format!("remove_dir_all {}: {}", memories.display(), e))
            })?;
            touched = true;
        }
        let meta = self.meta_root.join(&project);
        if meta.exists() {
            fs::remove_dir_all(&meta).map_err(|e| {
                GithubError::Io(format!("remove_dir_all {}: {}", meta.display(), e))
            })?;
            touched = true;
        }
        if !touched {
            return Ok(());
        }
        let msg = format!("chore(mem): delete project ({project})");
        self.maybe_commit(&msg)
    }

    pub fn sync_state(&self) -> GithubSyncState {
        let dirty = *self.dirty.read();
        let last_commit = *self.last_commit.read();
        let since_last_commit = last_commit.map(|ts| Instant::now().saturating_duration_since(ts));
        GithubSyncState {
            dirty,
            commit_batch_ms: self.commit_batch_ms,
            device_branch: self.current_device_branch(),
            since_last_commit,
        }
    }

    fn path_for_memory(&self, project: &ProjectId, mem: &Memory) -> String {
        let dt = mem.created_at;
        let y = dt.year();
        let m = dt.month();
        let d = dt.day();
        format!(
            "memories/{}/{:04}/{:02}/{:02}/{}.json",
            project, y, m, d, mem.id
        )
    }

    fn persist_memory(&self, project: &ProjectId, memory: &Memory) -> Result<(), GithubError> {
        self.ensure_project_dirs(project)?;
        let rel = self.path_for_memory(project, memory);
        let path = self.abs(&rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                GithubError::Io(format!("create_dir_all {}: {}", parent.display(), e))
            })?;
        }
        let data =
            serde_json::to_vec_pretty(memory).map_err(|e| GithubError::Serde(e.to_string()))?;
        let tmp = path
            .parent()
            .unwrap()
            .join(format!(".tmp-{}.json", memory.id));
        write_atomic(&tmp, &path, &data)?;

        let snapshot = {
            let mut manifests = self.manifests.write();
            let entry = manifests.entry(project.clone()).or_insert_with(|| {
                Self::load_manifest(&self.manifest_path(project)).unwrap_or_default()
            });
            entry.ids.insert(memory.id.clone(), rel.clone());
            if let Some(pos) = entry.recent.iter().position(|x| x == &memory.id) {
                entry.recent.remove(pos);
            }
            entry.recent.push_front(memory.id.clone());
            while entry.recent.len() > 1024 {
                entry.recent.pop_back();
            }
            entry.clone()
        };
        self.save_manifest(project, &snapshot)?;
        Ok(())
    }

    fn abs(&self, rel: &str) -> PathBuf {
        self.workdir.join(rel)
    }

    fn device_branch(&self) -> String {
        self.device_branch.read().clone()
    }

    pub fn current_device_branch(&self) -> String {
        self.device_branch()
    }

    fn default_device_branch() -> String {
        if let Ok(b) = std::env::var("GITMEM_DEVICE_BRANCH") {
            return b;
        }
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "device".to_string());
        format!("devices/{}", host)
    }

    pub fn configure_device_branch(&self, branch: &str) -> Result<(), GithubError> {
        let trimmed = branch.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        {
            let mut guard = self.device_branch.write();
            *guard = trimmed.to_string();
        }
        self.ensure_repo_for(trimmed)
    }

    fn ensure_repo(&self) -> Result<(), GithubError> {
        let branch = self.device_branch();
        self.ensure_repo_for(&branch)
    }

    fn ensure_repo_for(&self, branch: &str) -> Result<(), GithubError> {
        let git_dir = self.workdir.join(".git");
        if !git_dir.exists() {
            std::fs::create_dir_all(git_dir.join("refs/heads"))
                .map_err(|e| GithubError::Io(e.to_string()))?;
        }
        self.ensure_branch(branch)
    }

    fn ensure_branch(&self, branch: &str) -> Result<(), GithubError> {
        let head_path = self.workdir.join(".git/HEAD");
        let content = format!("ref: refs/heads/{}\n", branch);
        std::fs::write(head_path, content).map_err(|e| GithubError::Io(e.to_string()))?;
        // ensure ref file exists
        let ref_path = self.workdir.join(format!(".git/refs/heads/{}", branch));
        if let Some(parent) = ref_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| GithubError::Io(e.to_string()))?;
        }
        if ref_path.exists() {
            if let Ok(existing) = std::fs::read_to_string(&ref_path) {
                let trimmed = existing.trim();
                if !trimmed.is_empty() && trimmed.chars().all(|c| c == '0') {
                    let _ = std::fs::remove_file(&ref_path);
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "remote-git")]
    fn branch_for_operation(&self, override_branch: Option<&str>) -> Result<String, GithubError> {
        if let Some(branch) = override_branch {
            let trimmed = branch.trim();
            if !trimmed.is_empty() {
                self.configure_device_branch(trimmed)?;
                return Ok(trimmed.to_string());
            }
        }
        let branch = self.device_branch();
        self.ensure_repo_for(&branch)?;
        Ok(branch)
    }

    fn git_commit(&self, message: &str) -> Result<(), GithubError> {
        // Stub commit: best-effort repo init and append to a local log. Ignore failures.
        let _ = self.ensure_repo();
        let log_path = self.workdir.join(".git/COMMITS");
        if let Ok(mut f) = File::options().create(true).append(true).open(&log_path) {
            let ts = chrono::Utc::now().to_rfc3339();
            let line = format!("{} {}\n", ts, message);
            let _ = f.write_all(line.as_bytes());
        }
        *self.last_commit.write() = Some(Instant::now());
        *self.dirty.write() = false;
        Ok(())
    }

    fn write_conflict_artifact(
        &self,
        existing: &Memory,
        incoming: &Memory,
    ) -> Result<(), GithubError> {
        let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let dir = self
            .workdir
            .join("conflicts")
            .join(&incoming.id)
            .join(format!("{}", ts));
        fs::create_dir_all(&dir).map_err(|e| GithubError::Io(e.to_string()))?;
        let before =
            serde_json::to_vec_pretty(existing).map_err(|e| GithubError::Serde(e.to_string()))?;
        let after =
            serde_json::to_vec_pretty(incoming).map_err(|e| GithubError::Serde(e.to_string()))?;
        write_atomic(&dir.join("before.json"), &dir.join("before.json"), &before)?;
        write_atomic(&dir.join("after.json"), &dir.join("after.json"), &after)?;
        Ok(())
    }

    fn maybe_commit(&self, message: &str) -> Result<(), GithubError> {
        let now = Instant::now();
        let last = *self.last_commit.read();
        let batch = Duration::from_millis(self.commit_batch_ms);
        
        // Always defer commits when auto-push is enabled OR within batch window
        if self.is_auto_push_enabled() || last.map_or(false, |l| now.duration_since(l) < batch) {
            *self.dirty.write() = true;
            return Ok(());
        }
        
        // If dirty, squash into a batch commit
        if *self.dirty.read() {
            self.git_commit("chore(mem): batch changes")
        } else {
            self.git_commit(message)
        }
    }

    pub fn flush(&self) -> Result<(), GithubError> {
        if *self.dirty.read() {
            self.git_commit("chore(mem): batch flush")
        } else {
            Ok(())
        }
    }

    pub fn push(&self, remote: &str, branch: Option<&str>) -> Result<(), GithubError> {
        if let Some(path) = remote.strip_prefix("file://") {
            let dst = PathBuf::from(path);
            copy_tree(&self.workdir.join("memories"), &dst.join("memories"))?;
            copy_tree(&self.workdir.join("meta"), &dst.join("meta"))?;
            return Ok(());
        }
        #[cfg(feature = "remote-git")]
        {
            use git2::{IndexAddOption, Repository, Signature};
            let branch = self.branch_for_operation(branch)?;
            // Init or open repository
            let repo = match Repository::open(&self.workdir) {
                Ok(r) => r,
                Err(_) => {
                    Repository::init(&self.workdir).map_err(|e| GithubError::Git(e.to_string()))?
                }
            };
            // Stage files under memories/ and meta/
            let mut index = repo.index().map_err(|e| GithubError::Git(e.to_string()))?;
            let _ = index
                .add_all(["memories", "meta"], IndexAddOption::DEFAULT, None)
                .map_err(|e| GithubError::Git(e.to_string()))?;
            index.write().map_err(|e| GithubError::Git(e.to_string()))?;
            let tree_id = index
                .write_tree()
                .map_err(|e| GithubError::Git(e.to_string()))?;
            let tree = repo
                .find_tree(tree_id)
                .map_err(|e| GithubError::Git(e.to_string()))?;
            // Prepare commit
            let sig = Signature::now("gitmem", "gitmem@example.com")
                .map_err(|e| GithubError::Git(e.to_string()))?;
            let refname = format!("refs/heads/{}", branch);
            let parent: Option<git2::Commit> = match repo.refname_to_id(&refname) {
                Ok(oid) => repo.find_commit(oid).ok(),
                Err(_) => None,
            };
            let parents: Vec<&git2::Commit> = parent.as_ref().map(|c| vec![c]).unwrap_or_default();
            let message = "chore(mem): sync push";
            let _commit_oid = repo
                .commit(Some(&refname), &sig, &sig, message, &tree, &parents)
                .map_err(|e| GithubError::Git(e.to_string()))?;
            // Ensure HEAD points to branch
            let _ = repo.set_head(&refname);
            // Add or configure remote
            let remote_name = self.remote_name.clone();
            let mut remote = match repo.find_remote(&remote_name) {
                Ok(r) => r,
                Err(_) => repo
                    .remote(&remote_name, remote)
                    .map_err(|e| GithubError::Git(e.to_string()))?,
            };
            // Connect and push
            let repo_config = repo.config().ok().map(Arc::new);
            let fallback_config = git2::Config::open_default().ok().map(Arc::new);
            let helper_repo_config = repo_config.clone();
            let helper_fallback_config = fallback_config.clone();
            let cred_cfg = self.cred.clone();
            let mut callbacks = git2::RemoteCallbacks::new();
            callbacks.credentials(move |url, username_from_url, _allowed_types| {
                let helper_config = || {
                    helper_repo_config
                        .as_ref()
                        .map(|cfg| cfg.as_ref())
                        .or_else(|| helper_fallback_config.as_ref().map(|cfg| cfg.as_ref()))
                };
                match &cred_cfg {
                    Some(c) => match c.mode {
                        CredentialMode::Helper => {
                            if let Some(cfg) = helper_config() {
                                git2::Cred::credential_helper(cfg, url, username_from_url)
                            } else {
                                git2::Cred::default()
                            }
                        }
                        CredentialMode::UserPass => {
                            let user = c
                                .username
                                .clone()
                                .or_else(|| username_from_url.map(|s| s.to_string()))
                                .unwrap_or_else(|| "git".into());
                            // Prefer cached secret, fall back to environment lookup
                            let pass = c.cached_secret.clone()
                                .or_else(|| c.secret_env.as_deref().and_then(|k| std::env::var(k).ok()));
                            if let Some(p) = pass {
                                git2::Cred::userpass_plaintext(&user, &p)
                            } else {
                                git2::Cred::default()
                            }
                        }
                        CredentialMode::Token => {
                            let user = c
                                .username
                                .clone()
                                .unwrap_or_else(|| "x-access-token".into());
                            // Prefer cached secret, fall back to environment lookup
                            let token = c.cached_secret.clone()
                                .or_else(|| c.secret_env.as_deref().and_then(|k| std::env::var(k).ok()))
                                .unwrap_or_default();
                            git2::Cred::userpass_plaintext(&user, &token)
                        }
                        CredentialMode::SshAgent => {
                            let user = c
                                .username
                                .clone()
                                .or_else(|| username_from_url.map(|s| s.to_string()))
                                .unwrap_or_else(|| "git".into());
                            git2::Cred::ssh_key_from_agent(&user)
                        }
                    },
                    None => {
                        if let Some(cfg) = helper_config() {
                            git2::Cred::credential_helper(cfg, url, username_from_url)
                        } else {
                            git2::Cred::default()
                        }
                    }
                }
            });
            let mut push_opts = git2::PushOptions::new();
            push_opts.remote_callbacks(callbacks);
            // Don't call connect() separately - push() handles the connection with callbacks
            let spec = format!("+{}:{}", refname, refname);
            remote
                .push(&[spec.as_str()], Some(&mut push_opts))
                .map_err(|e| GithubError::Git(e.to_string()))?;
            return Ok(());
        }
        #[cfg(not(feature = "remote-git"))]
        {
            let _ = branch;
            Err(GithubError::Git(
                "remote push not supported; build with feature remote-git".into(),
            ))
        }
    }

    pub fn pull(&self, remote: &str, branch: Option<&str>) -> Result<(), GithubError> {
        if let Some(path) = remote.strip_prefix("file://") {
            let src = PathBuf::from(path);
            copy_tree(&src.join("memories"), &self.workdir.join("memories"))?;
            copy_tree(&src.join("meta"), &self.workdir.join("meta"))?;
            self.rebuild_manifest_from_disk()?;
            return Ok(());
        }
        #[cfg(feature = "remote-git")]
        {
            use git2::Repository;
            let branch = self.branch_for_operation(branch)?;
            let repo = match Repository::open(&self.workdir) {
                Ok(r) => r,
                Err(_) => {
                    Repository::init(&self.workdir).map_err(|e| GithubError::Git(e.to_string()))?
                }
            };
            // Add or locate remote
            let remote_name = self.remote_name.clone();
            let mut remote = match repo.find_remote(&remote_name) {
                Ok(r) => r,
                Err(_) => repo
                    .remote(&remote_name, remote)
                    .map_err(|e| GithubError::Git(e.to_string()))?,
            };
            let repo_config = repo.config().ok().map(Arc::new);
            let fallback_config = git2::Config::open_default().ok().map(Arc::new);
            let helper_repo_config = repo_config.clone();
            let helper_fallback_config = fallback_config.clone();
            let cred_cfg = self.cred.clone();
            let mut callbacks = git2::RemoteCallbacks::new();
            callbacks.credentials(move |url, username_from_url, _allowed_types| {
                let helper_config = || {
                    helper_repo_config
                        .as_ref()
                        .map(|cfg| cfg.as_ref())
                        .or_else(|| helper_fallback_config.as_ref().map(|cfg| cfg.as_ref()))
                };
                match &cred_cfg {
                    Some(c) => match c.mode {
                        CredentialMode::Helper => {
                            if let Some(cfg) = helper_config() {
                                git2::Cred::credential_helper(cfg, url, username_from_url)
                            } else {
                                git2::Cred::default()
                            }
                        }
                        CredentialMode::UserPass => {
                            let user = c
                                .username
                                .clone()
                                .or_else(|| username_from_url.map(|s| s.to_string()))
                                .unwrap_or_else(|| "git".into());
                            // Prefer cached secret, fall back to environment lookup
                            let pass = c.cached_secret.clone()
                                .or_else(|| c.secret_env.as_deref().and_then(|k| std::env::var(k).ok()));
                            if let Some(p) = pass {
                                git2::Cred::userpass_plaintext(&user, &p)
                            } else {
                                git2::Cred::default()
                            }
                        }
                        CredentialMode::Token => {
                            let user = c
                                .username
                                .clone()
                                .unwrap_or_else(|| "x-access-token".into());
                            // Prefer cached secret, fall back to environment lookup
                            let token = c.cached_secret.clone()
                                .or_else(|| c.secret_env.as_deref().and_then(|k| std::env::var(k).ok()))
                                .unwrap_or_default();
                            git2::Cred::userpass_plaintext(&user, &token)
                        }
                        CredentialMode::SshAgent => {
                            let user = c
                                .username
                                .clone()
                                .or_else(|| username_from_url.map(|s| s.to_string()))
                                .unwrap_or_else(|| "git".into());
                            git2::Cred::ssh_key_from_agent(&user)
                        }
                    },
                    None => {
                        if let Some(cfg) = helper_config() {
                            git2::Cred::credential_helper(cfg, url, username_from_url)
                        } else {
                            git2::Cred::default()
                        }
                    }
                }
            });
            let mut fetch_opts = git2::FetchOptions::new();
            fetch_opts.remote_callbacks(callbacks);
            // Fetch the device branch
            let refspec = format!(
                "refs/heads/{}:refs/remotes/{}/{}",
                branch, remote_name, branch
            );
            remote
                .fetch(&[refspec.as_str()], Some(&mut fetch_opts), None)
                .map_err(|e| GithubError::Git(e.to_string()))?;
            // Fast-forward local branch to fetched
            let local_ref = format!("refs/heads/{}", branch);
            let remote_ref = format!("refs/remotes/{}/{}", remote_name, branch);
            let remote_oid = match repo.refname_to_id(&remote_ref) {
                Ok(oid) => Some(oid),
                Err(e) if e.code() == git2::ErrorCode::NotFound => None,
                Err(e) => return Err(GithubError::Git(e.to_string())),
            };
            if remote_oid.is_none() {
                // Nothing upstream yet; ensure local branch metadata and exit gracefully.
                self.ensure_repo_for(&branch)?;
                return Ok(());
            }
            let remote_oid = remote_oid.unwrap();
            let mut reference = match repo.find_reference(&local_ref) {
                Ok(r) => r,
                Err(_) => repo
                    .reference(&local_ref, remote_oid, true, "set branch")
                    .map_err(|e| GithubError::Git(e.to_string()))?,
            };
            reference
                .set_target(remote_oid, "fast-forward")
                .map_err(|e| GithubError::Git(e.to_string()))?;
            // Checkout the tree
            let commit = repo
                .find_commit(remote_oid)
                .map_err(|e| GithubError::Git(e.to_string()))?;
            let tree = commit.tree().map_err(|e| GithubError::Git(e.to_string()))?;
            repo.checkout_tree(tree.as_object(), None)
                .map_err(|e| GithubError::Git(e.to_string()))?;
            repo.set_head(&local_ref)
                .map_err(|e| GithubError::Git(e.to_string()))?;
            self.rebuild_manifest_from_disk()?;
            return Ok(());
        }
        #[cfg(not(feature = "remote-git"))]
        {
            let _ = branch;
            Err(GithubError::Git(
                "remote pull not supported; build with feature remote-git".into(),
            ))
        }
    }
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), GithubError> {
    if !src.exists() {
        return Ok(());
    }
    fs::create_dir_all(dst).map_err(|e| GithubError::Io(e.to_string()))?;
    for entry in walkdir::WalkDir::new(src) {
        let entry = entry.map_err(|e| GithubError::Io(e.to_string()))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(src)
            .map_err(|e| GithubError::Io(e.to_string()))?;
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target).map_err(|e| GithubError::Io(e.to_string()))?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| GithubError::Io(e.to_string()))?;
            }
            fs::copy(path, &target).map_err(|e| GithubError::Io(e.to_string()))?;
        }
    }
    Ok(())
}

impl Storage for GithubStorage {
    type Error = GithubError;

    fn save(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error> {
        let project = sanitize_project_id(project);
        self.persist_memory(&project, memory)?;
        let msg = format!(
            "feat(mem): add {} [mem:{}] ({project})",
            memory.title, memory.id
        );
        self.maybe_commit(&msg)?;
        self.auto_push_if_enabled();
        Ok(())
    }

    fn get(&self, project: &ProjectId, id: &str) -> Result<Option<Memory>, Self::Error> {
        let project = sanitize_project_id(project);
        let rel = {
            let manifests = self.manifests.read();
            manifests.get(&project).and_then(|m| m.ids.get(id).cloned())
        };
        let rel = match rel {
            Some(r) => r,
            None => {
                let manifest = self.load_or_cache_manifest(&project)?;
                match manifest.ids.get(id) {
                    Some(r) => r.clone(),
                    None => return Ok(None),
                }
            }
        };
        let path = self.abs(&rel);
        let mut s = String::new();
        match File::open(&path) {
            Ok(mut f) => {
                f.read_to_string(&mut s)
                    .map_err(|e| GithubError::Io(e.to_string()))?;
                let mem: Memory =
                    serde_json::from_str(&s).map_err(|e| GithubError::Serde(e.to_string()))?;
                Ok(Some(mem))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(GithubError::Io(e.to_string())),
        }
    }

    fn update(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error> {
        let project = sanitize_project_id(project);
        let manifest = self.load_or_cache_manifest(&project)?;
        let rel = match manifest.ids.get(&memory.id) {
            Some(p) => p.clone(),
            None => return Err(GithubError::NotFound(memory.id.clone())),
        };
        let path = self.abs(&rel);
        let mut s = String::new();
        if let Ok(mut f) = File::open(&path) {
            f.read_to_string(&mut s)
                .map_err(|e| GithubError::Io(e.to_string()))?;
            if let Ok(existing) = serde_json::from_str::<Memory>(&s) {
                if memory.version <= existing.version || memory.updated_at <= existing.updated_at {
                    let _ = self.write_conflict_artifact(&existing, memory);
                    return Err(GithubError::Conflict(format!(
                        "memory {} version/updated_at stale",
                        memory.id
                    )));
                }
            }
        }
        self.persist_memory(&project, memory)?;
        let msg = format!(
            "fix(mem): update {} [mem:{}] ({project})",
            memory.title, memory.id
        );
        self.maybe_commit(&msg)?;
        self.auto_push_if_enabled();
        Ok(())
    }

    fn delete(&self, project: &ProjectId, id: &str, hard: bool) -> Result<(), Self::Error> {
        let project = sanitize_project_id(project);
        let (rel, snapshot) = {
            let mut manifests = self.manifests.write();
            let entry = manifests.entry(project.clone()).or_insert_with(|| {
                Self::load_manifest(&self.manifest_path(&project)).unwrap_or_default()
            });
            let rel = entry
                .ids
                .remove(id)
                .ok_or_else(|| GithubError::NotFound(id.to_string()))?;
            if let Some(pos) = entry.recent.iter().position(|x| x == id) {
                entry.recent.remove(pos);
            }
            let snapshot = entry.clone();
            (rel, snapshot)
        };
        self.save_manifest(&project, &snapshot)?;
        let path = self.abs(&rel);
        if hard {
            fs::remove_file(&path)
                .map_err(|e| GithubError::Io(format!("remove_file {}: {}", path.display(), e)))?;
        } else {
            let del_dir = self.workdir.join("memories").join(&project).join("deleted");
            fs::create_dir_all(&del_dir).map_err(|e| {
                GithubError::Io(format!("create_dir_all {}: {}", del_dir.display(), e))
            })?;
            let dest = del_dir.join(format!("{}.json", id));
            fs::rename(&path, &dest).map_err(|e| {
                GithubError::Io(format!(
                    "rename {} -> {}: {}",
                    path.display(),
                    dest.display(),
                    e
                ))
            })?;
        }
        let msg = format!("chore(mem): delete [mem:{id}] ({project})", id = id);
        self.maybe_commit(&msg)?;
        self.auto_push_if_enabled();
        Ok(())
    }

    fn list_recent_ids(
        &self,
        project: &ProjectId,
        limit: usize,
    ) -> Result<Vec<String>, Self::Error> {
        let project = sanitize_project_id(project);
        let manifest = self.load_or_cache_manifest(&project)?;
        Ok(manifest.recent.iter().take(limit).cloned().collect())
    }

    fn list_projects(&self) -> Result<Vec<ProjectId>, Self::Error> {
        let mut projects: HashSet<ProjectId> = {
            let manifests = self.manifests.read();
            manifests.keys().cloned().collect()
        };
        let memories_root = self.workdir.join("memories");
        if let Ok(entries) = fs::read_dir(&memories_root) {
            for entry in entries.flatten() {
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    if let Some(name) = entry.file_name().to_str() {
                        projects.insert(name.to_string());
                    }
                }
            }
        }
        if projects.is_empty() {
            projects.insert(DEFAULT_PROJECT_ID.to_string());
        }
        Ok(projects.into_iter().collect())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gitmem_core::{model::Memory, project::DEFAULT_PROJECT_ID};

    fn temp_repo_path() -> PathBuf {
        let base = std::env::temp_dir().join(format!("gitmem-gh-{}", unique_suffix()));
        let _ = fs::create_dir_all(&base);
        base
    }

    fn unique_suffix() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        now.as_nanos()
    }

    #[test]
    fn save_get_delete_and_repo_initialized() {
        let root = temp_repo_path();
        let store = GithubStorage::new(&root).unwrap();
        let m = Memory::new("title", "content", "note");
        let id = m.id.clone();
        let project = DEFAULT_PROJECT_ID.to_string();
        store.save(&project, &m).unwrap();
        // ensure file exists and get works
        let got = store.get(&project, &id).unwrap().unwrap();
        assert_eq!(got.title, "title");
        // ensure .git exists and HEAD is set
        assert!(root.join(".git").exists());
        let head = std::fs::read_to_string(root.join(".git/HEAD")).unwrap();
        assert!(head.contains("refs/heads/"));
        // delete
        store.delete(&project, &id, true).unwrap();
        let out = store.get(&project, &id).unwrap();
        assert!(out.is_none());
        let manifest_path = root.join("meta").join(project).join("MANIFEST.json");
        assert!(manifest_path.exists());
    }

    #[test]
    fn pull_and_push_noop_ok() {
        let root = temp_repo_path();
        let store = GithubStorage::new(&root).unwrap();
        // create remote path
        let remote_dir = temp_repo_path();
        fs::create_dir_all(remote_dir.join("memories")).unwrap();
        fs::create_dir_all(remote_dir.join("meta")).unwrap();
        let remote_uri = format!("file://{}", remote_dir.display());

        let m = Memory::new("t", "c", "note");
        let id = m.id.clone();
        let project = DEFAULT_PROJECT_ID.to_string();
        store.save(&project, &m).unwrap();
        store.flush().unwrap();
        // push to remote path
        assert!(store.push(&remote_uri, None).is_ok());
        // ensure remote has the file
        let mut found = false;
        for entry in walkdir::WalkDir::new(remote_dir.join("memories")) {
            let entry = entry.unwrap();
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|e| e.to_str()) == Some("json")
            {
                let p = entry.path().to_path_buf();
                let s = std::fs::read_to_string(&p).unwrap();
                if s.contains(&id) {
                    found = true;
                    break;
                }
            }
        }
        assert!(found);
        // pull back into a fresh store
        let root2 = temp_repo_path();
        let store2 = GithubStorage::new(&root2).unwrap();
        assert!(store2.pull(&remote_uri, None).is_ok());
        // manifest should exist and contain the id
        let man_path = root2
            .join("meta")
            .join(DEFAULT_PROJECT_ID)
            .join("MANIFEST.json");
        assert!(man_path.exists());
        let ms = std::fs::read_to_string(&man_path).unwrap();
        assert!(ms.contains(&id));
        // ensure pulled memory exists
        let got = store2.get(&project, &id).unwrap();
        assert!(got.is_some());
    }

    #[test]
    fn list_directory_exposes_project_tree() {
        let root = temp_repo_path();
        let store = GithubStorage::new(&root).unwrap();
        let project = "alpha".to_string();
        let memory = Memory::new("dir note", "body", "note");
        let created = memory.created_at;
        store.save(&project, &memory).unwrap();

        let year = format!("{:04}", created.year());
        let month = format!("{:02}", created.month());
        let day = format!("{:02}", created.day());

        let top = store.list_directory(&project, "").unwrap();
        assert!(top.iter().any(|e| e.is_dir && e.name == year));

        let months = store.list_directory(&project, &year).unwrap();
        assert!(months.iter().any(|e| e.is_dir && e.name == month));

        let days = store
            .list_directory(&project, &format!("{}/{}", year, month))
            .unwrap();
        assert!(days.iter().any(|e| e.is_dir && e.name == day));

        let files = store
            .list_directory(&project, &format!("{}/{}/{}", year, month, day))
            .unwrap();
        assert!(files.iter().any(|e| !e.is_dir && e.name.ends_with(".json")));
    }

    #[cfg(feature = "remote-git")]
    #[test]
    fn remote_git_branch_created_when_missing() {
        use git2::Repository;

        let root = temp_repo_path();
        let store = GithubStorage::new(&root).unwrap();
        let branch = "devices/test-sync";
        store.configure_device_branch(branch).unwrap();

        let remote_dir = temp_repo_path();
        let remote_repo_path = remote_dir.join("remote.git");
        Repository::init_bare(&remote_repo_path).unwrap();
        let remote_uri = remote_repo_path.to_string_lossy().to_string();

        store
            .pull(&remote_uri, Some(branch))
            .expect("initial pull should succeed");

        let project = DEFAULT_PROJECT_ID.to_string();
        let m = Memory::new("branch", "content", "note");
        store.save(&project, &m).unwrap();
        store.flush().unwrap();

        store
            .push(&remote_uri, Some(branch))
            .expect("push should succeed and create remote branch");

        let remote_repo = Repository::open_bare(&remote_repo_path).unwrap();
        let reference_name = format!("refs/heads/{}", branch);
        assert!(remote_repo.find_reference(&reference_name).is_ok());
    }

    #[test]
    fn supports_multiple_projects() {
        let root = temp_repo_path();
        let store = GithubStorage::new(&root).unwrap();
        let m_default = Memory::new("default note", "body", "note");
        store
            .save(&DEFAULT_PROJECT_ID.to_string(), &m_default)
            .unwrap();

        let mut m_alpha = Memory::new("alpha note", "alpha body", "note");
        m_alpha.updated_at = m_alpha.updated_at + chrono::Duration::minutes(5);
        store.save(&"alpha".to_string(), &m_alpha).unwrap();

        // Files should live under per-project subdirectories
        assert!(root.join("memories").join("alpha").exists());
        assert!(root
            .join("meta")
            .join("alpha")
            .join("MANIFEST.json")
            .exists());

        // list_projects returns both
        let mut projects = store.list_projects().unwrap();
        projects.sort();
        assert!(projects.contains(&"alpha".to_string()));
        assert!(projects.contains(&DEFAULT_PROJECT_ID.to_string()));

        // Recent IDs scoped per project
        let recent_alpha = store.list_recent_ids(&"alpha".to_string(), 10).unwrap();
        assert_eq!(recent_alpha, vec![m_alpha.id.clone()]);

        // Delete from non-default project moves into project deleted folder
        store
            .delete(&"alpha".to_string(), &m_alpha.id, false)
            .unwrap();
        assert!(root
            .join("memories")
            .join("alpha")
            .join("deleted")
            .join(format!("{}.json", m_alpha.id))
            .exists());
        let recent_after = store.list_recent_ids(&"alpha".to_string(), 10).unwrap();
        assert!(recent_after.is_empty());
    }

    #[test]
    fn create_project_initializes_manifest() {
        let root = temp_repo_path();
        let store = GithubStorage::new(&root).unwrap();
        let project = "delta".to_string();

        store.create_project(&project).unwrap();

        let memories_dir = root.join("memories").join(&project);
        let manifest_path = root.join("meta").join(&project).join("MANIFEST.json");
        assert!(memories_dir.is_dir());
        assert!(manifest_path.exists());

        // Project should appear in listings and repeated creation should be a no-op.
        let mut projects = store.list_projects().unwrap();
        projects.sort();
        assert!(projects.contains(&project));
        store.create_project(&project).unwrap();
    }

    #[test]
    fn delete_project_removes_all_content() {
        let root = temp_repo_path();
        let store = GithubStorage::new(&root).unwrap();
        let project = "alpha".to_string();
        let memory = Memory::new("title", "content", "note");
        store.save(&project, &memory).unwrap();

        let project_memories = root.join("memories").join(&project);
        let project_meta = root.join("meta").join(&project);
        assert!(project_memories.exists());
        assert!(project_meta.exists());

        store.delete_project(&project).unwrap();

        assert!(!project_memories.exists());
        assert!(!project_meta.exists());

        let projects = store.list_projects().unwrap();
        assert!(!projects.contains(&project));

        // Deleting again succeeds without side effects.
        assert!(store.delete_project(&project).is_ok());
    }

    #[test]
    fn sync_state_tracks_dirty_flag() {
        let root = temp_repo_path();
        let mut store = GithubStorage::new(&root).unwrap();
        store.set_commit_batch_ms(60_000);
        let project = DEFAULT_PROJECT_ID.to_string();

        let m1 = Memory::new("t1", "c1", "note");
        store.save(&project, &m1).unwrap();
        let m2 = Memory::new("t2", "c2", "note");
        store.save(&project, &m2).unwrap();

        let state = store.sync_state();
        assert!(state.dirty, "expected pending commit state");
        assert_eq!(state.commit_batch_ms, 60_000);
        assert_eq!(state.device_branch, store.current_device_branch());
        assert!(state.since_last_commit.is_some());

        store.flush().unwrap();
        let flushed = store.sync_state();
        assert!(!flushed.dirty, "flush should clear pending commit flag");
    }

    #[test]
    fn update_conflict_writes_artifact() {
        let root = temp_repo_path();
        let store = GithubStorage::new(&root).unwrap();
        let m = Memory::new("t", "c1", "note");
        let id = m.id.clone();
        let project = DEFAULT_PROJECT_ID.to_string();
        store.save(&project, &m).unwrap();
        // simulate a stale update: lower version and older updated_at
        let mut stale = m.clone();
        stale.version = 1; // same as initial
        stale.updated_at = m.created_at; // not newer
        stale.content = "c2".to_string();
        let res = store.update(&project, &stale);
        assert!(matches!(res, Err(GithubError::Conflict(_))));
        // verify conflict artifact exists
        let cdir = root.join("conflicts").join(id);
        assert!(cdir.exists());
    }
}

fn write_atomic(tmp: &Path, final_path: &Path, data: &[u8]) -> Result<(), GithubError> {
    {
        let parent = tmp
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none>".to_string());
        let mut f = File::create(tmp).map_err(|e| {
            GithubError::Io(format!(
                "create tmp {} (parent {}): {}",
                tmp.display(),
                parent,
                e
            ))
        })?;
        f.write_all(data)
            .map_err(|e| GithubError::Io(format!("write tmp {}: {}", tmp.display(), e)))?;
        f.sync_all()
            .map_err(|e| GithubError::Io(format!("sync tmp {}: {}", tmp.display(), e)))?;
    }
    fs::rename(tmp, final_path).map_err(|e| {
        GithubError::Io(format!(
            "rename {} -> {}: {}",
            tmp.display(),
            final_path.display(),
            e
        ))
    })?;
    if let Some(dir) = final_path.parent() {
        let dir_file = File::open(dir)
            .map_err(|e| GithubError::Io(format!("open dir {}: {}", dir.display(), e)))?;
        dir_file
            .sync_all()
            .map_err(|e| GithubError::Io(format!("sync dir {}: {}", dir.display(), e)))?;
    }
    Ok(())
}

impl GithubStorage {
    fn rebuild_manifest_from_disk(&self) -> Result<(), GithubError> {
        let mut per_project: HashMap<ProjectId, Vec<(String, Memory)>> = HashMap::new();
        let memories_root = self.workdir.join("memories");
        if memories_root.exists() {
            for entry in walkdir::WalkDir::new(&memories_root) {
                let entry = entry.map_err(|e| GithubError::Io(e.to_string()))?;
                if entry.file_type().is_file()
                    && entry.path().extension().and_then(|e| e.to_str()) == Some("json")
                {
                    let rel = entry
                        .path()
                        .strip_prefix(&self.workdir)
                        .map_err(|e| GithubError::Io(e.to_string()))?;
                    let rel_str = rel.to_string_lossy().to_string();
                    // try reading id from file
                    let mut s = String::new();
                    if let Ok(mut f) = File::open(entry.path()) {
                        let _ = f.read_to_string(&mut s);
                        if let Ok(mem) = serde_json::from_str::<Memory>(&s) {
                            let mut components = rel.components();
                            let project_raw = components
                                .nth(1)
                                .and_then(|c| c.as_os_str().to_str())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| DEFAULT_PROJECT_ID.to_string());
                            let project = sanitize_project_id(&project_raw);
                            per_project
                                .entry(project)
                                .or_default()
                                .push((rel_str.clone(), mem));
                        }
                    }
                }
            }
        }
        let mut manifests_map = HashMap::new();
        for (project, mut entries) in per_project {
            entries.sort_by(|a, b| b.1.updated_at.cmp(&a.1.updated_at));
            let mut manifest = Manifest::default();
            for (rel, mem) in entries {
                manifest.ids.insert(mem.id.clone(), rel.clone());
                manifest.recent.push_back(mem.id);
            }
            self.save_manifest(&project, &manifest)?;
            manifests_map.insert(project, manifest);
        }
        if manifests_map.is_empty() {
            // ensure default manifest exists even if empty
            let default = DEFAULT_PROJECT_ID.to_string();
            let manifest = Manifest::default();
            self.save_manifest(&default, &manifest)?;
            manifests_map.insert(default, manifest);
        }
        *self.manifests.write() = manifests_map;
        Ok(())
    }

    // External folder linking support with GitHub commit/push integration
    pub fn link_external_folder(
        &self,
        project: &ProjectId,
        path: &str,
        include: Option<Vec<String>>,
        exclude: Option<Vec<String>>,
        watch_mode: Option<&str>,
        poll_interval_ms: Option<u64>,
        jitter_pct: Option<u32>,
    ) -> Result<LinkedFolderInfo, GithubError> {
        let project = sanitize_project_id(project);
        self.ensure_project_dirs(&project)?;
        
        let resolved = Self::resolve_external_path(path)?;
        if !resolved.is_dir() {
            return Err(GithubError::Io(format!(
                "linked path {} is not a directory",
                resolved.display()
            )));
        }
        if resolved.starts_with(&self.workdir) {
            return Err(GithubError::Io(
                "cannot link a directory inside the GitHub storage root".into(),
            ));
        }

        let mut registry = self.load_links(&project)?;
        if registry
            .entries
            .iter()
            .any(|entry| Path::new(&entry.path) == resolved)
        {
            return Err(GithubError::Io("folder already linked".into()));
        }

        let watch = Self::create_watch_settings(watch_mode, poll_interval_ms, jitter_pct)?;
        let include_clean = include.clone().filter(|v| !v.is_empty());
        let exclude_clean = exclude.clone().filter(|v| !v.is_empty());
        let now = Self::now_timestamp();
        let link_id = LinkEntry::generate_id();
        let display = Some(path.to_string());
        
        let entry = LinkEntry {
            id: link_id.clone(),
            display: display.clone(),
            path: resolved.to_string_lossy().to_string(),
            include: include_clean.clone(),
            exclude: exclude_clean.clone(),
            mappings: HashMap::new(),
            watch: watch.clone(),
            created_at: now.clone(),
            last_scan: None,
            last_error: None,
            file_count: 0,
            total_bytes: 0,
            last_runtime_ms: None,
        };
        
        registry.entries.push(entry);
        self.save_links(&project, &registry)?;

        Ok(LinkedFolderInfo {
            project,
            path: display.clone().unwrap_or_else(|| path.to_string()),
            display_path: display,
            resolved_path: resolved.to_string_lossy().to_string(),
            include,
            exclude,
            link_id,
            watch: mcp_gitmem_storage_local::LinkWatchSettings::default(), // Convert from our internal type
            created_at: now,
            last_scan: None,
            last_error: None,
            file_count: 0,
            total_bytes: 0,
            status: "idle".into(),
            last_runtime_ms: None,
        })
    }

    pub fn unlink_external_folder(
        &self,
        project: &ProjectId,
        path: Option<&str>,
    ) -> Result<Vec<String>, GithubError> {
        let project = sanitize_project_id(project);
        let mut registry = self.load_links(&project)?;
        if registry.entries.is_empty() {
            return Ok(Vec::new());
        }
        
        let mut removed = Vec::new();
        match path {
            Some(p) => {
                let resolved = Self::resolve_external_path(p)?;
                registry.entries.retain(|entry| {
                    let keep = Path::new(&entry.path) != resolved;
                    if !keep {
                        removed.push(entry.display.clone().unwrap_or_else(|| entry.path.clone()));
                    }
                    keep
                });
            }
            None => {
                removed.extend(
                    registry
                        .entries
                        .iter()
                        .map(|e| e.display.clone().unwrap_or_else(|| e.path.clone())),
                );
                registry.entries.clear();
            }
        }
        self.save_links(&project, &registry)?;
        Ok(removed)
    }

    pub fn list_external_folders(
        &self,
        project: Option<&ProjectId>,
    ) -> Result<Vec<LinkedFolderInfo>, GithubError> {
        let mut out = Vec::new();
        if let Some(project) = project {
            let project = sanitize_project_id(project);
            let registry = self.load_links(&project)?;
            out.extend(self.links_to_info(&project, &registry));
            return Ok(out);
        }

        let projects = self.list_projects()?;
        for proj in projects {
            let registry = self.load_links(&proj)?;
            out.extend(self.links_to_info(&proj, &registry));
        }
        Ok(out)
    }

    pub fn rescan_external_folders(
        &self,
        project: &ProjectId,
        filter_paths: Option<&[String]>,
    ) -> Result<Vec<RescanReport>, GithubError> {
        // Acquire file lock at the START to protect entire scan+commit+push operation
        // This prevents concurrent rescans from ANY gitmem process (poller, manual calls, other instances)
        let _lock_guard = Self::acquire_push_lock().map_err(|e| {
            GithubError::Io(format!("failed to acquire lock for rescan: {}", e))
        })?;
        
        let project = sanitize_project_id(project);
        self.ensure_project_dirs(&project)?;
        let mut registry = self.load_links(&project)?;
        if registry.entries.is_empty() {
            return Ok(Vec::new());
        }

        // Set bulk operation flag to disable auto-push during scan
        *self.bulk_operation_in_progress.write() = true;

        let filter: Option<HashSet<PathBuf>> = filter_paths.map(|paths| {
            paths
                .iter()
                .filter_map(|p| Self::resolve_external_path(p).ok())
                .collect()
        });

        let mut reports = Vec::new();
        
        for entry in registry.entries.iter_mut() {
            if let Some(ref filter) = filter {
                if !filter.contains(Path::new(&entry.path)) {
                    continue;
                }
            }
            
            let started = Instant::now();
            let now_ts = Self::now_timestamp();
            let mut report = RescanReport {
                project: project.clone(),
                path: entry.path.clone(),
                display_path: entry.display.clone(),
                link_id: entry.id.clone(),
                scanned: 0,
                created: 0,
                updated: 0,
                deleted: 0,
                include: entry.include.clone(),
                exclude: entry.exclude.clone(),
                total_bytes: 0,
                runtime_ms: 0,
                last_error: None,
            };

            let dir_path = PathBuf::from(&entry.path);
            if !dir_path.exists() {
                let err = format!("directory missing: {}", entry.path);
                entry.last_error = Some(err.clone());
                entry.last_scan = Some(now_ts.clone());
                let runtime_ms = started.elapsed().as_millis() as u64;
                entry.last_runtime_ms = Some(runtime_ms);
                report.runtime_ms = runtime_ms;
                report.last_error = Some(err);
                reports.push(report);
                continue;
            }

            let scan_result = self.scan_linked_directory(&project, entry);
            let runtime_ms = started.elapsed().as_millis() as u64;
            entry.last_scan = Some(now_ts.clone());
            entry.last_runtime_ms = Some(runtime_ms);

            match scan_result {
                Ok(stats) => {
                    entry.last_error = None;
                    entry.file_count = stats.file_count;
                    entry.total_bytes = stats.total_bytes;
                    report.scanned = stats.scanned;
                    report.created = stats.created;
                    report.updated = stats.updated;
                    report.deleted = stats.deleted;
                    report.total_bytes = stats.total_bytes;
                    report.runtime_ms = runtime_ms;
                }
                Err(err) => {
                    let message = err.to_string();
                    entry.last_error = Some(message.clone());
                    report.runtime_ms = runtime_ms;
                    report.last_error = Some(message);
                }
            }

            reports.push(report);
        }
        
        self.save_links(&project, &registry)?;
        
        // Do a single flush and push after processing all files
        // Lock is already held for the entire rescan operation
        if self.is_auto_push_enabled() {
            if let Some(remote_url) = self.get_remote_url() {
                // Flush any pending commits
                if let Err(e) = self.flush() {
                    tracing::error!(error = %e, "rescan: flush failed");
                }
                
                // Push to remote
                if let Err(e) = self.push(&remote_url, None) {
                    tracing::error!(error = %e, remote = %remote_url, "rescan: push failed");
                }
            }
        }
        
        // Clear bulk operation flag AFTER push completes
        *self.bulk_operation_in_progress.write() = false;
        
        Ok(reports)
    }

    // Helper methods for folder linking
    fn load_links(&self, project: &ProjectId) -> Result<LinkRegistry, GithubError> {
        let path = self.meta_root.join(project).join("links.json");
        if !path.exists() {
            return Ok(LinkRegistry::default());
        }
        let data = fs::read(&path).map_err(|e| GithubError::Io(e.to_string()))?;
        serde_json::from_slice(&data).map_err(|e| GithubError::Serde(e.to_string()))
    }

    fn save_links(&self, project: &ProjectId, registry: &LinkRegistry) -> Result<(), GithubError> {
        let dir = self.meta_root.join(project);
        fs::create_dir_all(&dir).map_err(|e| GithubError::Io(e.to_string()))?;
        let path = dir.join("links.json");
        let data = serde_json::to_vec_pretty(registry)
            .map_err(|e| GithubError::Serde(e.to_string()))?;
        fs::write(&path, &data).map_err(|e| GithubError::Io(e.to_string()))
    }

    fn links_to_info(&self, project: &ProjectId, registry: &LinkRegistry) -> Vec<LinkedFolderInfo> {
        registry
            .entries
            .iter()
            .map(|entry| LinkedFolderInfo {
                project: project.clone(),
                path: entry.display.clone().unwrap_or_else(|| entry.path.clone()),
                display_path: entry.display.clone(),
                resolved_path: entry.path.clone(),
                include: entry.include.clone(),
                exclude: entry.exclude.clone(),
                link_id: entry.id.clone(),
                watch: mcp_gitmem_storage_local::LinkWatchSettings::default(),
                created_at: entry.created_at.clone(),
                last_scan: entry.last_scan.clone(),
                last_error: entry.last_error.clone(),
                file_count: entry.file_count,
                total_bytes: entry.total_bytes,
                status: if entry.last_error.is_some() {
                    "error".into()
                } else {
                    "polling".into()
                },
                last_runtime_ms: entry.last_runtime_ms,
            })
            .collect()
    }

    fn scan_linked_directory(
        &self,
        project: &ProjectId,
        entry: &mut LinkEntry,
    ) -> Result<LinkScanStats, GithubError> {
        let mut stats = LinkScanStats::default();
        let dir_path = PathBuf::from(&entry.path);
        let include_patterns = Self::compile_patterns(entry.include.as_ref())?;
        let exclude_patterns = Self::compile_patterns(entry.exclude.as_ref())?;

        let mut new_mappings = HashMap::new();
        let mut visited_files = HashSet::new();
        
        for walk_entry in walkdir::WalkDir::new(&dir_path).into_iter().filter_map(Result::ok) {
            if walk_entry.file_type().is_dir() {
                continue;
            }
            let file_path = walk_entry.path();
            if Self::should_skip(file_path) {
                continue;
            }
            let rel = match file_path.strip_prefix(&dir_path) {
                Ok(r) => r.to_path_buf(),
                Err(_) => continue,
            };
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if !Self::pattern_matches(&include_patterns, &rel_str, true) {
                continue;
            }
            if Self::pattern_matches(&exclude_patterns, &rel_str, false) {
                continue;
            }
            
            visited_files.insert(rel_str.clone());
            stats.scanned += 1;
            
            let mem_id = Self::linked_memory_id(project, &entry.path, &rel_str);
            let memory = self.memory_from_file(project, &mem_id, &entry.id, &rel_str, file_path)?;
            
            let existed = self.get(project, &mem_id).map_err(|e| GithubError::Io(e.to_string()))?;
            if let Some(mut existing) = existed {
                if existing.content != memory.content
                    || existing.title != memory.title
                    || existing.tags != memory.tags
                {
                    existing.content = memory.content;
                    existing.title = memory.title;
                    existing.tags = memory.tags;
                    existing.updated_at = memory.updated_at;
                    existing.source = memory.source.clone();
                    existing.version += 1;
                    self.update(project, &existing)?;
                    stats.updated += 1;
                }
            } else {
                self.save(project, &memory)?;
                stats.created += 1;
            }
            
            new_mappings.insert(rel_str, mem_id);
            if let Some(size) = memory.source.as_ref().and_then(|src| src.file_size) {
                stats.total_bytes = stats.total_bytes.saturating_add(size);
            }
        }

        // Delete memories for files that no longer exist
        for (rel, mem_id) in entry.mappings.iter() {
            if !visited_files.contains(rel) {
                if self.delete(project, mem_id, true).is_ok() {
                    stats.deleted += 1;
                }
            }
        }

        entry.mappings = new_mappings;
        stats.file_count = visited_files.len() as u64;
        Ok(stats)
    }

    fn memory_from_file(
        &self,
        project: &ProjectId,
        mem_id: &str,
        link_id: &str,
        rel_path: &str,
        path: &Path,
    ) -> Result<Memory, GithubError> {
        let mut data = String::new();
        File::open(path)
            .map_err(|e| GithubError::Io(e.to_string()))?
            .read_to_string(&mut data)
            .map_err(|e| GithubError::Io(e.to_string()))?;

        let (front_matter_raw, body) = Self::extract_front_matter(&data);
        let parsed_front = front_matter_raw
            .and_then(|fm| Self::parse_front_matter(fm).transpose())
            .transpose()?;

        let mut memory = Memory::new(mem_id, &body, "note");
        memory.tags.push(format!("project:{}", project));
        memory.tags.push("linked".into());

        if let Some((front, json_value)) = parsed_front {
            if let Some(title) = front.title {
                memory.title = title;
            }
            if let Some(tags) = front.tags {
                memory.tags.extend(tags);
            }
            if let Some(mem_type) = front.r#type {
                memory.r#type = mem_type;
            }
            memory.source = Some(SourceMeta {
                agent: Some("gitmem-linked-folder".into()),
                session: None,
                origin: Some("linked_folder".into()),
                app: None,
                front_matter: Some(json_value),
                file_uri: None,
                relative_path: Some(rel_path.to_string()),
                checksum_sha256: None,
                linked_folder_id: Some(link_id.to_string()),
                file_mtime: None,
                file_size: None,
            });
        } else {
            memory.source = Some(SourceMeta {
                agent: Some("gitmem-linked-folder".into()),
                session: None,
                origin: Some("linked_folder".into()),
                app: None,
                front_matter: None,
                file_uri: None,
                relative_path: Some(rel_path.to_string()),
                checksum_sha256: None,
                linked_folder_id: Some(link_id.to_string()),
                file_mtime: None,
                file_size: None,
            });
        }

        // Compute checksum
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(data.as_bytes());
        let checksum = hex::encode(hasher.finalize());
        if let Some(ref mut source_meta) = memory.source {
            source_meta.checksum_sha256 = Some(checksum);
        }

        // Set file URI and metadata
        if let Some(ref mut source_meta) = memory.source {
            if let Ok(abs) = path.canonicalize() {
                if let Ok(url) = Url::from_file_path(&abs) {
                    source_meta.file_uri = Some(url.to_string());
                }
            }

            let metadata = path.metadata().map_err(|e| GithubError::Io(e.to_string()))?;
            source_meta.file_size = Some(metadata.len());
            if let Ok(modified) = metadata.modified() {
                let dt: DateTime<Utc> = modified.into();
                source_meta.file_mtime = Some(dt.to_rfc3339());
                memory.created_at = dt;
                memory.updated_at = dt;
            }
        }

        Ok(memory)
    }

    // Static helper methods
    fn resolve_external_path(path: &str) -> Result<PathBuf, GithubError> {
        let expanded = if path.starts_with('~') {
            if path == "~" {
                Self::home_dir()?
            } else {
                let home = Self::home_dir()?;
                home.join(path.trim_start_matches("~/"))
            }
        } else {
            PathBuf::from(path)
        };
        let canonical = fs::canonicalize(&expanded).unwrap_or(expanded.clone());
        Ok(canonical)
    }

    fn should_skip(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|name| name.starts_with('.') || name.ends_with('~'))
            .unwrap_or(false)
    }

    fn compile_patterns(patterns: Option<&Vec<String>>) -> Result<Option<Vec<Regex>>, GithubError> {
        let patterns = match patterns {
            Some(list) if !list.is_empty() => list,
            _ => return Ok(None),
        };
        let mut compiled = Vec::with_capacity(patterns.len());
        for pat in patterns {
            let regex = Regex::new(&Self::wildcard_to_regex(pat))
                .map_err(|e| GithubError::Io(e.to_string()))?;
            compiled.push(regex);
        }
        Ok(Some(compiled))
    }

    fn pattern_matches(
        patterns: &Option<Vec<Regex>>,
        candidate: &str,
        default_value: bool,
    ) -> bool {
        match patterns {
            Some(list) if !list.is_empty() => list.iter().any(|re| re.is_match(candidate)),
            _ => default_value,
        }
    }

    fn wildcard_to_regex(pattern: &str) -> String {
        let mut regex = String::from("^");
        for ch in pattern.chars() {
            match ch {
                '*' => regex.push_str(".*"),
                '?' => regex.push('.'),
                '.' => regex.push_str("\\."),
                '\\' => regex.push_str("\\\\"),
                other => regex.push_str(&regex::escape(&other.to_string())),
            }
        }
        regex.push('$');
        regex
    }

    fn home_dir() -> Result<PathBuf, GithubError> {
        if let Ok(path) = std::env::var("HOME") {
            return Ok(PathBuf::from(path));
        }
        if let Ok(path) = std::env::var("USERPROFILE") {
            return Ok(PathBuf::from(path));
        }
        Err(GithubError::Io("HOME not set".into()))
    }

    fn now_timestamp() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    fn linked_memory_id(project: &str, root: &str, rel: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(project.as_bytes());
        hasher.update(b"::");
        hasher.update(root.as_bytes());
        hasher.update(b"::");
        hasher.update(rel.as_bytes());
        format!("mem_link_{}", hex::encode(hasher.finalize()))
    }

    fn extract_front_matter(data: &str) -> (Option<&str>, String) {
        if !data.starts_with("---") {
            return (None, data.to_string());
        }
        let mut cursor = &data[3..];
        if cursor.starts_with('\r') {
            cursor = &cursor[1..];
        }
        if cursor.starts_with('\n') {
            cursor = &cursor[1..];
        } else {
            return (None, data.to_string());
        }
        if let Some((front, remainder)) = cursor.split_once("\n---") {
            let mut body = remainder;
            if body.starts_with('\r') {
                body = &body[1..];
            }
            if body.starts_with('\n') {
                body = &body[1..];
            }
            return (Some(front.trim_end()), body.to_string());
        }
        (None, data.to_string())
    }

    fn parse_front_matter(
        fm: &str,
    ) -> Result<Option<(FrontMatter, serde_json::Value)>, GithubError> {
        if fm.trim().is_empty() {
            return Ok(None);
        }
        let yaml: serde_yaml::Value = serde_yaml::from_str(fm)
            .map_err(|e| GithubError::Serde(format!("front matter parse error: {}", e)))?;
        let front: FrontMatter = serde_yaml::from_value(yaml.clone())
            .map_err(|e| GithubError::Serde(format!("front matter decode error: {}", e)))?;
        let json = serde_json::to_value(yaml)
            .map_err(|e| GithubError::Serde(format!("front matter json error: {}", e)))?;
        Ok(Some((front, json)))
    }

    fn create_watch_settings(
        watch_mode: Option<&str>,
        poll_interval_ms: Option<u64>,
        jitter_pct: Option<u32>,
    ) -> Result<LinkWatchSettings, GithubError> {
        let mode = if let Some(mode_str) = watch_mode {
            WatchMode::parse(mode_str)?
        } else {
            WatchMode::default()
        };
        
        Ok(LinkWatchSettings {
            mode,
            poll_interval_ms: poll_interval_ms.unwrap_or(30_000),
            jitter_pct: jitter_pct.unwrap_or(20),
            platform: None,
        })
    }

}
