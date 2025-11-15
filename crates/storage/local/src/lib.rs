use chrono::{DateTime, Datelike, Utc};
use std::{
    any::Any,
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime},
};

use mcp_gitmem_core::{
    model::Memory,
    project::{sanitize_project_id, ProjectId, DEFAULT_PROJECT_ID},
    traits::Storage,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
// use fs4 fully qualified to avoid unused import warnings
use regex::Regex;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};
use url::Url;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum LocalError {
    #[error("io error: {0}")]
    Io(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("serde error: {0}")]
    Serde(String),
}

#[derive(Default, Serialize, Deserialize, Clone)]
struct Manifest {
    ids: HashMap<String, String>, // id -> relative path under root
    recent: VecDeque<String>,     // most-recent touch at front
}

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

#[derive(Default)]
struct LinkScanStats {
    scanned: usize,
    created: usize,
    updated: usize,
    deleted: usize,
    total_bytes: u64,
    file_count: u64,
}

#[derive(Clone)]
pub struct LinkedFolderInfo {
    pub project: ProjectId,
    pub path: String,
    pub display_path: Option<String>,
    pub resolved_path: String,
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    pub link_id: String,
    pub watch: LinkWatchSettings,
    pub created_at: String,
    pub last_scan: Option<String>,
    pub last_error: Option<String>,
    pub file_count: u64,
    pub total_bytes: u64,
    pub status: String,
    pub last_runtime_ms: Option<u64>,
}

#[derive(Default, Clone, Debug, Serialize)]
pub struct RescanReport {
    pub project: ProjectId,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_path: Option<String>,
    #[serde(rename = "linkId")]
    pub link_id: String,
    pub scanned: usize,
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    #[serde(rename = "totalBytes")]
    pub total_bytes: u64,
    #[serde(rename = "runtimeMs")]
    pub runtime_ms: u64,
    #[serde(rename = "lastError", skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Default, Clone, Deserialize)]
struct FrontMatter {
    title: Option<String>,
    tags: Option<Vec<String>>,
    r#type: Option<String>,
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
    fn parse(input: &str) -> Result<Self, LocalError> {
        match input.to_lowercase().as_str() {
            "poll" => Ok(WatchMode::Poll),
            other => Err(LocalError::Io(format!(
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
pub struct LinkWatchSettings {
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

impl LinkWatchSettings {
    pub fn mode_str(&self) -> &'static str {
        self.mode.as_str()
    }

    pub fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms
    }

    pub fn jitter_pct(&self) -> u32 {
        self.jitter_pct
    }

    pub fn platform(&self) -> Option<&String> {
        self.platform.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct LocalWatchConfig {
    mode: WatchMode,
    poll_interval_ms: u64,
    jitter_pct: u32,
    max_concurrent: usize,
    allow_outside_home: bool,
}

impl Default for LocalWatchConfig {
    fn default() -> Self {
        Self {
            mode: WatchMode::Poll,
            poll_interval_ms: 30_000,
            jitter_pct: 20,
            max_concurrent: 4,
            allow_outside_home: false,
        }
    }
}

impl LocalWatchConfig {
    pub fn set_allow_outside_home(&mut self, allow: bool) {
        self.allow_outside_home = allow;
    }

    pub fn apply_overrides(
        &mut self,
        mode: Option<&str>,
        poll_interval_ms: Option<u64>,
        jitter_pct: Option<u32>,
        max_concurrent: Option<usize>,
    ) -> Result<(), LocalError> {
        if let Some(mode_str) = mode {
            self.mode = WatchMode::parse(mode_str)?;
        }
        if let Some(interval) = poll_interval_ms {
            self.poll_interval_ms = interval.max(1_000);
        }
        if let Some(jitter) = jitter_pct {
            self.jitter_pct = jitter.min(100);
        }
        if let Some(max) = max_concurrent {
            self.max_concurrent = max.max(1);
        }
        Ok(())
    }

    fn to_link_settings(&self) -> LinkWatchSettings {
        LinkWatchSettings {
            mode: self.mode.clone(),
            poll_interval_ms: self.poll_interval_ms,
            jitter_pct: self.jitter_pct,
            platform: None,
        }
    }

    fn with_overrides(&self, overrides: &LinkWatchOverrides) -> LinkWatchSettings {
        let mode = overrides.mode.clone().unwrap_or(self.mode.clone());
        let poll_interval_ms = overrides
            .poll_interval_ms
            .unwrap_or(self.poll_interval_ms)
            .max(1_000);
        let jitter_pct = overrides.jitter_pct.unwrap_or(self.jitter_pct).min(100);
        LinkWatchSettings {
            mode,
            poll_interval_ms,
            jitter_pct,
            platform: None,
        }
    }
}

#[derive(Default)]
struct LinkWatchOverrides {
    mode: Option<WatchMode>,
    poll_interval_ms: Option<u64>,
    jitter_pct: Option<u32>,
}

pub struct LocalDirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
}

pub struct LocalStorage {
    root: PathBuf,
    manifests: RwLock<HashMap<ProjectId, Manifest>>,
    links: RwLock<HashMap<ProjectId, LinkRegistry>>,
    watch_defaults: LocalWatchConfig,
    allow_outside_home: bool,
}

impl LocalStorage {
    fn apply_watch_overrides(&self, overrides: &LinkWatchOverrides) -> LinkWatchSettings {
        self.watch_defaults.with_overrides(overrides)
    }

    pub fn max_concurrent(&self) -> usize {
        self.watch_defaults.max_concurrent
    }

    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self::with_config(root, LocalWatchConfig::default())
    }

    pub fn with_config<P: AsRef<Path>>(root: P, config: LocalWatchConfig) -> Self {
        let root = root.as_ref().to_path_buf();
        let _ = fs::create_dir_all(root.join("memories"));
        let _ = fs::create_dir_all(root.join("meta"));
        Self {
            root,
            manifests: RwLock::new(HashMap::new()),
            links: RwLock::new(HashMap::new()),
            watch_defaults: config.clone(),
            allow_outside_home: config.allow_outside_home,
        }
    }

    fn manifest_path(&self, project: &ProjectId) -> PathBuf {
        self.root.join("meta").join(project).join("MANIFEST.json")
    }

    fn lock_path(&self, project: &ProjectId) -> PathBuf {
        self.root.join("meta").join(project).join("LOCK")
    }

    fn links_path(&self, project: &ProjectId) -> PathBuf {
        self.root.join("meta").join(project).join("links.json")
    }

    pub fn ensure_project_dirs(&self, project: &ProjectId) -> Result<(), LocalError> {
        let meta = self.root.join("meta").join(project);
        let memories = self.root.join("memories").join(project);
        fs::create_dir_all(&meta).map_err(|e| LocalError::Io(e.to_string()))?;
        fs::create_dir_all(&memories).map_err(|e| LocalError::Io(e.to_string()))?;
        Ok(())
    }

    fn load_manifest(path: &Path) -> Result<Manifest, LocalError> {
        if !path.exists() {
            return Ok(Manifest::default());
        }
        let mut s = String::new();
        File::open(path)
            .map_err(|e| LocalError::Io(e.to_string()))?
            .read_to_string(&mut s)
            .map_err(|e| LocalError::Io(e.to_string()))?;
        serde_json::from_str(&s).map_err(|e| LocalError::Serde(e.to_string()))
    }

    fn save_manifest(&self, project: &ProjectId, m: &Manifest) -> Result<(), LocalError> {
        let path = self.manifest_path(project);
        let dir = path.parent().unwrap();
        let tmp = dir.join(format!(
            ".tmp-manifest-{}-{}.json",
            std::process::id(),
            unique_suffix()
        ));
        let data = serde_json::to_vec_pretty(m).map_err(|e| LocalError::Serde(e.to_string()))?;
        write_atomic(&tmp, &path, &data)
    }

    fn load_links(&self, project: &ProjectId) -> Result<LinkRegistry, LocalError> {
        {
            let links = self.links.read();
            if let Some(existing) = links.get(project) {
                return Ok(existing.clone());
            }
        }
        self.ensure_project_dirs(project)?;
        let path = self.links_path(project);
        let mut registry = if path.exists() {
            let mut buf = String::new();
            File::open(&path)
                .map_err(|e| LocalError::Io(e.to_string()))?
                .read_to_string(&mut buf)
                .map_err(|e| LocalError::Io(e.to_string()))?;
            serde_json::from_str(&buf).map_err(|e| LocalError::Serde(e.to_string()))?
        } else {
            LinkRegistry::default()
        };
        if self.normalize_links(project, &mut registry) {
            self.save_links(project, &registry)?;
        }
        let mut links = self.links.write();
        links.insert(project.clone(), registry.clone());
        Ok(registry)
    }

    fn save_links(&self, project: &ProjectId, registry: &LinkRegistry) -> Result<(), LocalError> {
        self.ensure_project_dirs(project)?;
        let path = self.links_path(project);
        let dir = path.parent().unwrap();
        let tmp = dir.join(format!(
            ".tmp-links-{}-{}.json",
            std::process::id(),
            unique_suffix()
        ));
        let data =
            serde_json::to_vec_pretty(registry).map_err(|e| LocalError::Serde(e.to_string()))?;
        write_atomic(&tmp, &path, &data)?;
        let mut links = self.links.write();
        links.insert(project.clone(), registry.clone());
        Ok(())
    }

    fn path_for_memory(&self, project: &ProjectId, mem: &Memory) -> String {
        let dt = mem.created_at;
        let year = dt.year();
        let month = dt.month();
        let day = dt.day();
        format!(
            "memories/{}/{:04}/{:02}/{:02}/{}.json",
            project, year, month, day, mem.id
        )
    }

    fn abs(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn ensure_parent(&self, project: &ProjectId, rel: &str) -> Result<(), LocalError> {
        self.ensure_project_dirs(project)?;
        let p = self.abs(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| LocalError::Io(e.to_string()))?;
        }
        Ok(())
    }

    pub fn create_project(&self, project: &ProjectId) -> Result<(), LocalError> {
        let project = sanitize_project_id(project);
        self.ensure_project_dirs(&project)?;
        let path = self.manifest_path(&project);
        if !path.exists() {
            self.save_manifest(&project, &Manifest::default())?;
        }
        self.manifests
            .write()
            .entry(project.clone())
            .or_insert_with(Manifest::default);
        Ok(())
    }

    pub fn delete_project(&self, project: &ProjectId) -> Result<(), LocalError> {
        let project = sanitize_project_id(project);
        {
            let mut manifests = self.manifests.write();
            manifests.remove(&project);
        }
        let memories = self.root.join("memories").join(&project);
        if memories.exists() {
            fs::remove_dir_all(&memories).map_err(|e| LocalError::Io(e.to_string()))?;
        }
        let meta = self.root.join("meta").join(&project);
        if meta.exists() {
            fs::remove_dir_all(&meta).map_err(|e| LocalError::Io(e.to_string()))?;
        }
        Ok(())
    }

    pub fn list_directory(
        &self,
        project: &ProjectId,
        rel: &str,
    ) -> Result<Vec<LocalDirEntry>, LocalError> {
        let project = sanitize_project_id(project);
        self.ensure_project_dirs(&project)?;
        let trimmed = rel.trim_matches('/');
        if trimmed.contains("..") {
            return Err(LocalError::Io("path traversal not allowed".into()));
        }
        let base = if trimmed.is_empty() {
            self.root.join("memories").join(&project)
        } else {
            self.root.join("memories").join(&project).join(trimmed)
        };
        if !base.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(&base).map_err(|e| LocalError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| LocalError::Io(e.to_string()))?;
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
            entries.push(LocalDirEntry {
                name,
                path: rel_path,
                is_dir,
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    pub fn link_external_folder(
        &self,
        project: &ProjectId,
        path: &str,
        include: Option<Vec<String>>,
        exclude: Option<Vec<String>>,
        watch_mode: Option<&str>,
        poll_interval_ms: Option<u64>,
        jitter_pct: Option<u32>,
    ) -> Result<LinkedFolderInfo, LocalError> {
        let project = sanitize_project_id(project);
        self.ensure_project_dirs(&project)?;
        let resolved = self.resolve_external_path(path)?;
        if !resolved.is_dir() {
            return Err(LocalError::Io(format!(
                "linked path {} is not a directory",
                resolved.display()
            )));
        }
        if resolved.starts_with(&self.root) {
            return Err(LocalError::Io(
                "cannot link a directory inside the local storage root".into(),
            ));
        }
        if !self.allow_outside_home && !Self::is_within_home(&resolved) {
            return Err(LocalError::Io(
                "linking outside the user home directory is disabled".into(),
            ));
        }

        let mut registry = self.load_links(&project)?;
        if registry
            .entries
            .iter()
            .any(|entry| Path::new(&entry.path) == resolved)
        {
            return Err(LocalError::Io("folder already linked".into()));
        }

        let overrides = LinkWatchOverrides {
            mode: watch_mode.map(|mode| WatchMode::parse(mode)).transpose()?,
            poll_interval_ms,
            jitter_pct,
        };
        let watch = self.apply_watch_overrides(&overrides);
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
            include: include,
            exclude: exclude,
            link_id,
            watch,
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
    ) -> Result<Vec<String>, LocalError> {
        let project = sanitize_project_id(project);
        let mut registry = self.load_links(&project)?;
        if registry.entries.is_empty() {
            return Ok(Vec::new());
        }
        let mut removed = Vec::new();
        match path {
            Some(p) => {
                let resolved = self.resolve_external_path(p)?;
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
    ) -> Result<Vec<LinkedFolderInfo>, LocalError> {
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
                watch: entry.watch.clone(),
                created_at: entry.created_at.clone(),
                last_scan: entry.last_scan.clone(),
                last_error: entry.last_error.clone(),
                file_count: entry.file_count,
                total_bytes: entry.total_bytes,
                status: if entry.last_error.is_some() {
                    "error".into()
                } else {
                    match entry.watch.mode {
                        WatchMode::Poll => "polling".into(),
                    }
                },
                last_runtime_ms: entry.last_runtime_ms,
            })
            .collect()
    }

    fn normalize_links(&self, _project: &ProjectId, registry: &mut LinkRegistry) -> bool {
        let mut changed = false;
        for entry in registry.entries.iter_mut() {
            if entry.id.is_empty() {
                entry.id = LinkEntry::generate_id();
                changed = true;
            }
            if entry.watch.poll_interval_ms == 0 {
                entry.watch = self.watch_defaults.to_link_settings();
                changed = true;
            }
            if entry.created_at.is_empty() {
                entry.created_at = Self::now_timestamp();
                changed = true;
            }
        }
        changed
    }

    pub fn rescan_external_folders(
        &self,
        project: &ProjectId,
        filter_paths: Option<&[String]>,
    ) -> Result<Vec<RescanReport>, LocalError> {
        let project = sanitize_project_id(project);
        self.ensure_project_dirs(&project)?;
        let mut registry = self.load_links(&project)?;
        if registry.entries.is_empty() {
            return Ok(Vec::new());
        }

        let filter: Option<HashSet<PathBuf>> = filter_paths.map(|paths| {
            paths
                .iter()
                .filter_map(|p| self.resolve_external_path(p).ok())
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
                warn!(path = %entry.path, "linked directory missing during rescan");
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
        Ok(reports)
    }

    fn resolve_external_path(&self, path: &str) -> Result<PathBuf, LocalError> {
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

    fn scan_linked_directory(
        &self,
        project: &ProjectId,
        entry: &mut LinkEntry,
    ) -> Result<LinkScanStats, LocalError> {
        let mut stats = LinkScanStats::default();
        let dir_path = PathBuf::from(&entry.path);
        let include_patterns = Self::compile_patterns(entry.include.as_ref())?;
        let exclude_patterns = Self::compile_patterns(entry.exclude.as_ref())?;

        let mut new_mappings = HashMap::new();
        let mut visited_files = HashSet::new();
        for walk_entry in WalkDir::new(&dir_path).into_iter().filter_map(Result::ok) {
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
            let existed = self
                .get(project, &mem_id)
                .map_err(|e| LocalError::Io(e.to_string()))?;
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
    ) -> Result<Memory, LocalError> {
        let mut data = String::new();
        File::open(path)
            .map_err(|e| LocalError::Io(e.to_string()))?
            .read_to_string(&mut data)
            .map_err(|e| LocalError::Io(e.to_string()))?;

        let (front_matter_raw, body) = Self::extract_front_matter(&data);
        let parsed_front = front_matter_raw
            .and_then(|fm| Self::parse_front_matter(fm).transpose())
            .transpose()?;
        let mut memory = Memory::new(
            "",
            &body,
            parsed_front
                .as_ref()
                .and_then(|(meta, _)| meta.r#type.as_deref())
                .unwrap_or("note"),
        );
        memory.id = mem_id.to_string();
        if let Some((meta, _)) = parsed_front.as_ref() {
            if let Some(title) = &meta.title {
                memory.title = title.clone();
            }
            if let Some(tags) = &meta.tags {
                memory.tags = tags.clone();
            }
        }
        if memory.title.is_empty() {
            memory.title = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("untitled")
                .to_string();
        }
        memory.tags.push(format!("project:{}", project));
        memory.tags.push("linked".into());
        memory.tags.sort();
        memory.tags.dedup();

        let mut source_meta = memory.source.take().unwrap_or_default();
        source_meta.origin = Some("linked_folder".into());
        source_meta.linked_folder_id = Some(link_id.to_string());
        source_meta.relative_path = Some(rel_path.to_string());

        if let Some((_, front_json)) = parsed_front.as_ref() {
            source_meta.front_matter = Some(front_json.clone());
        }

        let checksum = {
            let mut hasher = Sha256::new();
            hasher.update(data.as_bytes());
            hex::encode(hasher.finalize())
        };
        source_meta.checksum_sha256 = Some(checksum);

        if let Ok(abs) = path.canonicalize() {
            if let Ok(url) = Url::from_file_path(&abs) {
                source_meta.file_uri = Some(url.to_string());
            }
        }

        let metadata = path.metadata().map_err(|e| LocalError::Io(e.to_string()))?;
        source_meta.file_size = Some(metadata.len());
        if let Ok(modified) = metadata.modified() {
            let dt: DateTime<Utc> = modified.into();
            source_meta.file_mtime = Some(dt.to_rfc3339());
            memory.created_at = dt;
            memory.updated_at = dt;
        }

        memory.source = Some(source_meta);
        Ok(memory)
    }

    fn should_skip(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|name| name.starts_with('.') || name.ends_with('~'))
            .unwrap_or(false)
    }

    fn compile_patterns(patterns: Option<&Vec<String>>) -> Result<Option<Vec<Regex>>, LocalError> {
        let patterns = match patterns {
            Some(list) if !list.is_empty() => list,
            _ => return Ok(None),
        };
        let mut compiled = Vec::with_capacity(patterns.len());
        for pat in patterns {
            let regex = Regex::new(&Self::wildcard_to_regex(pat))
                .map_err(|e| LocalError::Io(e.to_string()))?;
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

    fn home_dir() -> Result<PathBuf, LocalError> {
        if let Ok(path) = std::env::var("HOME") {
            return Ok(PathBuf::from(path));
        }
        if let Ok(path) = std::env::var("USERPROFILE") {
            return Ok(PathBuf::from(path));
        }
        Err(LocalError::Io("HOME not set".into()))
    }

    fn is_within_home(path: &Path) -> bool {
        match Self::home_dir() {
            Ok(home) => path.starts_with(home),
            Err(_) => true,
        }
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
    ) -> Result<Option<(FrontMatter, serde_json::Value)>, LocalError> {
        if fm.trim().is_empty() {
            return Ok(None);
        }
        let yaml: serde_yaml::Value = serde_yaml::from_str(fm)
            .map_err(|e| LocalError::Serde(format!("front matter parse error: {}", e)))?;
        let front: FrontMatter = serde_yaml::from_value(yaml.clone())
            .map_err(|e| LocalError::Serde(format!("front matter decode error: {}", e)))?;
        let json = serde_json::to_value(yaml)
            .map_err(|e| LocalError::Serde(format!("front matter json error: {}", e)))?;
        if front.title.is_none() && front.r#type.is_none() && front.tags.is_none() {
            return Ok(Some((front, json)));
        }
        Ok(Some((front, json)))
    }
}

impl Storage for LocalStorage {
    type Error = LocalError;

    fn save(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error> {
        let project = sanitize_project_id(project);
        self.ensure_project_dirs(&project)?;
        let lockf = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_path(&project))
            .map_err(|e| LocalError::Io(e.to_string()))?;
        fs4::FileExt::lock_exclusive(&lockf).map_err(|e| LocalError::Io(e.to_string()))?;
        let res = (|| {
            let rel = self.path_for_memory(&project, memory);
            self.ensure_parent(&project, &rel)?;
            let path = self.abs(&rel);
            let data =
                serde_json::to_vec_pretty(memory).map_err(|e| LocalError::Serde(e.to_string()))?;
            let tmp =
                path.parent()
                    .unwrap()
                    .join(format!(".tmp-{}-{}.json", memory.id, unique_suffix()));
            debug!(
                memory_id = %memory.id,
                project = %project,
                rel_path = %rel,
                "local save start"
            );
            write_atomic(&tmp, &path, &data)?;

            let snapshot = {
                let mut manifests = self.manifests.write();
                let entry = manifests.entry(project.clone()).or_insert_with(|| {
                    Self::load_manifest(&self.manifest_path(&project)).unwrap_or_default()
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
            let manifest_res = self.save_manifest(&project, &snapshot);
            if manifest_res.is_ok() {
                debug!(
                    memory_id = %memory.id,
                    project = %project,
                    rel_path = %rel,
                    "local save committed"
                );
            }
            manifest_res
        })();
        let _ = fs4::FileExt::unlock(&lockf);
        res
    }

    fn get(&self, project: &ProjectId, id: &str) -> Result<Option<Memory>, Self::Error> {
        let project = sanitize_project_id(project);
        debug!(memory_id = id, project = %project, "local get requested");
        let rel_opt = {
            let mut manifests = self.manifests.write();
            let entry = manifests.entry(project.clone()).or_insert_with(|| {
                Self::load_manifest(&self.manifest_path(&project)).unwrap_or_default()
            });
            entry.ids.get(id).cloned()
        };
        let rel = match rel_opt {
            Some(r) => r,
            None => return Ok(None),
        };
        debug!(memory_id = id, project = %project, rel_path = %rel, "local get loading");
        let path = self.abs(&rel);
        let mut s = String::new();
        match File::open(&path) {
            Ok(mut f) => {
                f.read_to_string(&mut s)
                    .map_err(|e| LocalError::Io(e.to_string()))?;
                let mem: Memory =
                    serde_json::from_str(&s).map_err(|e| LocalError::Serde(e.to_string()))?;
                debug!(memory_id = id, project = %project, "local get hit");
                Ok(Some(mem))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(memory_id = id, project = %project, "local get miss: file vanished");
                Ok(None)
            }
            Err(e) => {
                debug!(memory_id = id, project = %project, error = %e, "local get io error");
                Err(LocalError::Io(e.to_string()))
            }
        }
    }

    fn update(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error> {
        self.save(project, memory)
    }

    fn delete(&self, project: &ProjectId, id: &str, hard: bool) -> Result<(), Self::Error> {
        let project = sanitize_project_id(project);
        debug!(memory_id = id, project = %project, hard, "local delete requested");
        self.ensure_project_dirs(&project)?;
        let lockf = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_path(&project))
            .map_err(|e| LocalError::Io(e.to_string()))?;
        fs4::FileExt::lock_exclusive(&lockf).map_err(|e| LocalError::Io(e.to_string()))?;
        let res = (|| {
            let (rel, snapshot) = {
                let mut manifests = self.manifests.write();
                let entry = manifests.entry(project.clone()).or_insert_with(|| {
                    Self::load_manifest(&self.manifest_path(&project)).unwrap_or_default()
                });
                let rel = entry
                    .ids
                    .remove(id)
                    .ok_or_else(|| LocalError::NotFound(id.to_string()))?;
                if let Some(pos) = entry.recent.iter().position(|x| x == id) {
                    entry.recent.remove(pos);
                }
                (rel, entry.clone())
            };
            self.save_manifest(&project, &snapshot)?;
            let path = self.abs(&rel);
            if hard {
                fs::remove_file(&path).map_err(|e| LocalError::Io(e.to_string()))?;
                debug!(memory_id = id, project = %project, "local delete removed file");
            } else {
                let del_dir = self.root.join("memories").join(&project).join("deleted");
                fs::create_dir_all(&del_dir).map_err(|e| LocalError::Io(e.to_string()))?;
                let dest = del_dir.join(format!("{}.json", id));
                fs::rename(&path, &dest).map_err(|e| LocalError::Io(e.to_string()))?;
                debug!(memory_id = id, project = %project, "local delete archived file");
            }
            Ok(())
        })();
        let _ = fs4::FileExt::unlock(&lockf);
        res
    }

    fn list_recent_ids(
        &self,
        project: &ProjectId,
        limit: usize,
    ) -> Result<Vec<String>, Self::Error> {
        let project = sanitize_project_id(project);
        let ids = {
            let mut manifests = self.manifests.write();
            let entry = manifests.entry(project.clone()).or_insert_with(|| {
                Self::load_manifest(&self.manifest_path(&project)).unwrap_or_default()
            });
            entry.recent.iter().take(limit).cloned().collect::<Vec<_>>()
        };
        debug!(
            project = %project,
            returned = ids.len(),
            limit,
            "local list_recent_ids returning"
        );
        Ok(ids)
    }

    fn list_projects(&self) -> Result<Vec<ProjectId>, Self::Error> {
        let mut projects: HashSet<ProjectId> = {
            let manifests = self.manifests.read();
            manifests.keys().cloned().collect()
        };
        let memories_root = self.root.join("memories");
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

fn write_atomic(tmp: &Path, final_path: &Path, data: &[u8]) -> Result<(), LocalError> {
    // write to tmp
    {
        let mut f = File::create(tmp).map_err(|e| LocalError::Io(e.to_string()))?;
        f.write_all(data)
            .map_err(|e| LocalError::Io(e.to_string()))?;
        f.sync_all().map_err(|e| LocalError::Io(e.to_string()))?;
    }
    // rename to final
    fs::rename(tmp, final_path).map_err(|e| LocalError::Io(e.to_string()))?;
    // fsync directory
    if let Some(dir) = final_path.parent() {
        let dir_file = File::open(dir).map_err(|e| LocalError::Io(e.to_string()))?;
        dir_file
            .sync_all()
            .map_err(|e| LocalError::Io(e.to_string()))?;
    }
    Ok(())
}

fn unique_suffix() -> u128 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();
    nanos ^ (std::thread::current().name().unwrap_or("").as_ptr() as usize as u128)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gitmem_core::{model::Memory, project::DEFAULT_PROJECT_ID};

    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!("gitmem-local-{}", unique_suffix()));
        let _ = fs::create_dir_all(&base);
        base
    }

    fn external_dir() -> PathBuf {
        let base = std::env::temp_dir().join(format!("gitmem-external-{}", unique_suffix()));
        let _ = fs::create_dir_all(&base);
        base
    }

    #[test]
    fn save_get_delete_roundtrip() {
        let root = tempdir();
        let store = LocalStorage::new(&root);
        let project = "proj".to_string();
        let m = Memory::new("title", "content", "note");
        let id = m.id.clone();
        store.save(&project, &m).unwrap();
        let got = store.get(&project, &id).unwrap().unwrap();
        assert_eq!(got.title, "title");
        store.delete(&project, &id, false).unwrap();
        let res = store.get(&project, &id).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn link_rescan_and_unlink_folder() {
        let root = tempdir();
        let mut watch_config = LocalWatchConfig::default();
        watch_config.set_allow_outside_home(true);
        let store = LocalStorage::with_config(&root, watch_config);
        let project = DEFAULT_PROJECT_ID.to_string();
        let external = external_dir().join("vault");
        fs::create_dir_all(&external).unwrap();
        let file_path = external.join("note.md");
        fs::write(
            &file_path,
            "---\ntitle: External Note\ntags:\n  - ext\n---\ninitial body",
        )
        .unwrap();

        let info = store
            .link_external_folder(
                &project,
                external.to_str().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(info.project, project);
        let reports = store.rescan_external_folders(&project, None).unwrap();
        assert_eq!(reports.len(), 1);
        let ids = store.list_recent_ids(&project, 10).unwrap();
        assert_eq!(ids.len(), 1);
        let mem_id = ids[0].clone();
        let mut memory = store.get(&project, &mem_id).unwrap().unwrap();
        assert_eq!(memory.title, "External Note");
        assert!(memory.tags.contains(&"linked".to_string()));

        fs::write(
            &file_path,
            "---\ntitle: Updated Note\ntags:\n  - ext\n  - refreshed\n---\nupdated body",
        )
        .unwrap();
        store.rescan_external_folders(&project, None).unwrap();
        memory = store.get(&project, &mem_id).unwrap().unwrap();
        assert_eq!(memory.title, "Updated Note");
        assert!(memory.tags.contains(&"refreshed".to_string()));

        fs::remove_file(&file_path).unwrap();
        store.rescan_external_folders(&project, None).unwrap();
        let deleted = store.get(&project, &mem_id).unwrap();
        assert!(deleted.is_none());

        let removed = store
            .unlink_external_folder(&project, Some(external.to_str().unwrap()))
            .unwrap();
        assert_eq!(removed.len(), 1);
    }
}
