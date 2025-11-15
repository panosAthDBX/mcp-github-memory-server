//! Server runtime: minimal JSON-RPC over stdio for M1 vertical slice.

use axum::{routing::get, Json};
use chrono::{DateTime, SecondsFormat, Utc};
#[cfg(feature = "encryption")]
use mcp_gitmem_core::model::EncryptionMeta;
use mcp_gitmem_core::{
    model::Memory,
    project::{sanitize_project_id, ProjectId, DEFAULT_PROJECT_ID},
    traits::{Index, SearchParams, Storage},
    validate::{normalize_type, ttl_not_expired},
};
#[cfg(feature = "encryption")]
use mcp_gitmem_crypto::{CryptoConfig, CryptoError, CryptoFacade};
use mcp_gitmem_proto as proto;
use rmcp::{
    model::{
        CallToolRequestParam, CallToolResult, ErrorCode, Implementation, ListResourcesResult,
        ListToolsResult, PaginatedRequestParam, ReadResourceRequestParam, ReadResourceResult,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    transport::{
        io,
        sse_server::{SseServer, SseServerConfig},
    },
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
};
use schemars::schema::RootSchema;
use schemars::schema_for;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
#[cfg(feature = "backend-local")]
use sha2::{Digest, Sha256};
#[allow(unused_imports)]
use std::any::Any;
use std::collections::BTreeMap;
use std::future::IntoFuture;
use std::net::SocketAddr;
#[cfg(feature = "encryption")]
use std::sync::Arc as StdArc;
use std::sync::Arc;
use thiserror::Error;
#[cfg(feature = "backend-local")]
use tokio::time::{interval, Duration, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
#[cfg(feature = "backend-local")]
use tracing::warn;
use tracing::{debug, error, info};

#[cfg(any(feature = "backend-ephemeral", test))]
use mcp_gitmem_storage_ephemeral::EphemeralStorage;
#[cfg(feature = "backend-github")]
use mcp_gitmem_storage_github::GithubStorage;
#[cfg(feature = "backend-local")]
use mcp_gitmem_storage_local::{LinkWatchSettings, LinkedFolderInfo, LocalStorage};

fn memory_to_json(memory: &Memory) -> serde_json::Value {
    serde_json::to_value(memory).unwrap_or_else(|_| json!({}))
}

fn truncate_text_for_snippet(text: &str, max_chars: usize) -> String {
    let mut snippet = String::new();
    for (i, ch) in text.chars().enumerate() {
        if i >= max_chars {
            snippet.push('…');
            break;
        }
        snippet.push(ch);
    }
    snippet.trim().to_string()
}

fn format_timestamp(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn project_tag(project: &ProjectId) -> String {
    format!("project:{project}")
}

fn ensure_project_tag(memory: &mut Memory, project: &ProjectId) {
    let tag = project_tag(project);
    if !memory.tags.iter().any(|existing| existing == &tag) {
        memory.tags.push(tag);
    }
}

fn replace_project_tag(memory: &mut Memory, src: &ProjectId, dest: &ProjectId) {
    let src_tag = project_tag(src);
    memory.tags.retain(|t| t != &src_tag);
    ensure_project_tag(memory, dest);
}

#[cfg(feature = "encryption")]
fn redact_encrypted_for_index(memory: &Memory) -> Memory {
    let mut sanitized = memory.clone();
    sanitized.title.clear();
    sanitized.content.clear();
    sanitized
}

#[cfg(feature = "encryption")]
fn encryption_error_response(id: Option<serde_json::Value>, err: CryptoError) -> JsonRpcResponse {
    mcp_error_response(id, "E_ENCRYPTION", &err.to_string())
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("rmcp: {0}")]
    Rmcp(String),
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[serde(default)]
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

/// Message type for async index update queue
#[derive(Debug, Clone)]
enum IndexUpdate {
    Update {
        project: ProjectId,
        memory: Memory,
    },
    Delete {
        project: ProjectId,
        id: String,
    },
}

pub struct Server<S, I> {
    storage: Arc<S>,
    index: Arc<I>,
    default_project: ProjectId,
    #[cfg(feature = "encryption")]
    encryption: Option<EncryptionConfig>,
    index_queue_tx: Option<tokio::sync::mpsc::UnboundedSender<IndexUpdate>>,
    index_worker_cancel: Option<Arc<CancellationToken>>,
}

impl<S, I> Clone for Server<S, I> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            index: Arc::clone(&self.index),
            default_project: self.default_project.clone(),
            #[cfg(feature = "encryption")]
            encryption: self.encryption.clone(),
            index_queue_tx: self.index_queue_tx.clone(),
            index_worker_cancel: self.index_worker_cancel.clone(),
        }
    }
}

#[cfg(feature = "encryption")]
#[derive(Clone)]
struct EncryptionConfig {
    facade: StdArc<CryptoFacade>,
}

#[cfg(feature = "encryption")]
impl EncryptionConfig {
    fn new(recipients: Vec<String>) -> Option<Self> {
        if recipients.is_empty() {
            return None;
        }
        Some(Self {
            facade: StdArc::new(CryptoFacade::new(CryptoConfig {
                recipients,
                enabled: true,
            })),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub default_project: ProjectId,
    #[cfg(feature = "encryption")]
    pub encryption_recipients: Vec<String>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            default_project: DEFAULT_PROJECT_ID.to_string(),
            #[cfg(feature = "encryption")]
            encryption_recipients: Vec::new(),
        }
    }
}

impl<S, I> Server<S, I>
where
    S: Storage + Send + Sync + 'static,
    I: Index + Send + Sync + 'static,
{
    #[must_use]
    pub fn new(storage: S, index: I) -> Self {
        Self::new_with_options(storage, index, ServerOptions::default())
    }

    #[must_use]
    pub fn new_with_project(storage: S, index: I, project: impl Into<String>) -> Self {
        let mut options = ServerOptions::default();
        options.default_project = project.into();
        Self::new_with_options(storage, index, options)
    }

    #[must_use]
    pub fn new_with_options(storage: S, index: I, options: ServerOptions) -> Self {
        let default_project = sanitize_project_id(&options.default_project);
        #[cfg(feature = "encryption")]
        let encryption = EncryptionConfig::new(
            options
                .encryption_recipients
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        );
        
        // Create unbounded channel for async index updates
        let (index_queue_tx, index_queue_rx) = tokio::sync::mpsc::unbounded_channel();
        let index_worker_cancel = Arc::new(CancellationToken::new());
        
        // Spawn background worker for index updates
        let index_arc = Arc::new(index);
        let cancel_token = index_worker_cancel.clone();
        Self::spawn_index_worker(index_arc.clone(), index_queue_rx, cancel_token);
        
        Self {
            storage: Arc::new(storage),
            index: index_arc,
            default_project,
            #[cfg(feature = "encryption")]
            encryption,
            index_queue_tx: Some(index_queue_tx),
            index_worker_cancel: Some(index_worker_cancel),
        }
    }

    fn spawn_index_worker(
        index: Arc<I>,
        mut rx: tokio::sync::mpsc::UnboundedReceiver<IndexUpdate>,
        cancel: Arc<CancellationToken>,
    ) {
        tokio::spawn(async move {
            let mut queue_size = 0usize;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("index worker received cancellation signal");
                        break;
                    }
                    update = rx.recv() => {
                        match update {
                            Some(IndexUpdate::Update { project, memory }) => {
                                queue_size = queue_size.saturating_sub(1);
                                let index_clone = index.clone();
                                let project_clone = project.clone();
                                let memory_clone = memory.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    index_clone.update(&project_clone, &memory_clone)
                                }).await;
                                
                                match result {
                                    Ok(Ok(())) => {
                                        tracing::debug!(memory_id = %memory.id, project = %project, "index updated");
                                    }
                                    Ok(Err(e)) => {
                                        tracing::error!(error = %e, memory_id = %memory.id, project = %project, "index update failed");
                                    }
                                    Err(e) => {
                                        tracing::error!(error = %e, "index update task panicked");
                                    }
                                }
                            }
                            Some(IndexUpdate::Delete { project, id }) => {
                                queue_size = queue_size.saturating_sub(1);
                                let index_clone = index.clone();
                                let project_clone = project.clone();
                                let id_clone = id.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    index_clone.delete(&project_clone, &id_clone)
                                }).await;
                                
                                match result {
                                    Ok(Ok(())) => {
                                        tracing::debug!(memory_id = %id, project = %project, "index deleted");
                                    }
                                    Ok(Err(e)) => {
                                        tracing::error!(error = %e, memory_id = %id, project = %project, "index delete failed");
                                    }
                                    Err(e) => {
                                        tracing::error!(error = %e, "index delete task panicked");
                                    }
                                }
                            }
                            None => {
                                tracing::info!("index queue closed, worker exiting");
                                break;
                            }
                        }
                        
                        // Log warning if queue is getting large
                        if queue_size > 5000 {
                            tracing::warn!(queue_size, "index queue is growing large");
                        }
                    }
                }
                // Update queue size estimate
                queue_size = rx.len();
            }
        });
    }

    fn default_project(&self) -> ProjectId {
        self.default_project.clone()
    }

    fn queue_index_update(&self, project: ProjectId, memory: Memory) {
        if let Some(tx) = &self.index_queue_tx {
            if let Err(e) = tx.send(IndexUpdate::Update { project, memory }) {
                tracing::error!(error = ?e, "failed to queue index update");
            }
        }
    }

    fn queue_index_delete(&self, project: ProjectId, id: String) {
        if let Some(tx) = &self.index_queue_tx {
            if let Err(e) = tx.send(IndexUpdate::Delete { project, id }) {
                tracing::error!(error = ?e, "failed to queue index delete");
            }
        }
    }

    async fn graceful_shutdown(&self) {
        tracing::info!("initiating graceful shutdown");
        
        // Cancel the index worker
        if let Some(cancel) = &self.index_worker_cancel {
            cancel.cancel();
        }
        
        // Give the worker time to drain the queue (up to 5 seconds)
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        
        // Flush any pending commits in GitHub storage
        #[cfg(feature = "backend-github")]
        {
            if let Some(github) = self.storage.as_any().downcast_ref::<GithubStorage>() {
                if let Err(e) = github.flush() {
                    tracing::error!(error = %e, "failed to flush commits during shutdown");
                } else {
                    tracing::info!("flushed pending commits");
                }
            }
        }
        
        tracing::info!("graceful shutdown complete");
    }

    fn resolve_project_param(&self, value: Option<&str>) -> ProjectId {
        match value {
            Some(raw) => sanitize_project_id(raw),
            None => self.default_project(),
        }
    }

    #[cfg(feature = "encryption")]
    fn prepare_memory_for_storage(
        &self,
        id: &Option<serde_json::Value>,
        memory: &mut Memory,
    ) -> Result<Memory, JsonRpcResponse> {
        match &self.encryption {
            None => Ok(memory.clone()),
            Some(enc) => {
                if memory
                    .encryption
                    .as_ref()
                    .map(|meta| meta.encrypted)
                    .unwrap_or(false)
                {
                    return Ok(redact_encrypted_for_index(memory));
                }
                let encrypted_title = enc
                    .facade
                    .encrypt(&memory.title)
                    .map_err(|err| encryption_error_response(id.clone(), err))?;
                let encrypted_content = enc
                    .facade
                    .encrypt(&memory.content)
                    .map_err(|err| encryption_error_response(id.clone(), err))?;
                memory.title = encrypted_title;
                memory.content = encrypted_content;
                match memory.encryption.as_mut() {
                    Some(meta) => {
                        meta.algo = Some("age-x25519".into());
                        meta.kid = None;
                        meta.encrypted = true;
                    }
                    None => {
                        memory.encryption = Some(EncryptionMeta {
                            algo: Some("age-x25519".into()),
                            kid: None,
                            encrypted: true,
                        });
                    }
                }
                Ok(redact_encrypted_for_index(memory))
            }
        }
    }

    pub async fn run_stdio(&self) -> Result<(), ServerError> {
        info!("server running (stdio rmcp)");
        #[cfg(feature = "backend-local")]
        let poller = self.spawn_link_poller();
        let adapter = RmcpAdapter::new(self.clone());
        let service = adapter
            .serve(io::stdio())
            .await
            .map_err(|e| ServerError::Rmcp(e.to_string()))?;
        service
            .waiting()
            .await
            .map_err(|e| ServerError::Rmcp(e.to_string()))?;
        
        // Graceful shutdown: drain index queue and flush commits
        self.graceful_shutdown().await;
        
        #[cfg(feature = "backend-local")]
        if let Some(token) = poller {
            token.cancel();
        }
        Ok(())
    }

    pub async fn run_http(&self, addr: &str) -> Result<(), ServerError> {
        let bind_addr: SocketAddr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| ServerError::Io(e.to_string()))?;

        let shutdown_token = CancellationToken::new();
        let config = SseServerConfig {
            bind: bind_addr,
            sse_path: "/sse".to_string(),
            post_path: "/message".to_string(),
            ct: shutdown_token.clone(),
            sse_keep_alive: None,
        };

        let (sse_server, router) = SseServer::new(config);
        let app = router.route("/healthz", get(healthz));

        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| ServerError::Io(e.to_string()))?;

        #[cfg(feature = "backend-local")]
        let poller = self.spawn_link_poller();
        let adapter = RmcpAdapter::new(self.clone());
        sse_server.with_service(move || adapter.clone());

        info!(%addr, "http server listening (SSE transport)");
        let server_shutdown = shutdown_token.child_token();
        let server = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                server_shutdown.cancelled().await;
            })
            .into_future();
        tokio::pin!(server);

        let http_result: Result<(), ServerError> = tokio::select! {
            res = &mut server => {
                res.map_err(|e| ServerError::Io(e.to_string()))
            }
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl_c received; shutting down http server");
                shutdown_token.cancel();
                server.as_mut().await.map_err(|e| ServerError::Io(e.to_string()))
            }
        };
        http_result?;
        
        // Graceful shutdown: drain index queue and flush commits
        self.graceful_shutdown().await;
        
        #[cfg(feature = "backend-local")]
        if let Some(token) = poller {
            token.cancel();
        }
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let method_name = req.method.clone();
        let id_repr = req.id.as_ref().map(|v| v.to_string());
        debug!(method = %method_name, id = %id_repr.as_deref().unwrap_or("null"), "handling JSON-RPC request");
        match req.method.as_str() {
            proto::METHOD_TOOLS_LIST => self.handle_tools_list(req).await,
            proto::METHOD_TOOLS_CALL => self.handle_tools_call(req).await,
            proto::TOOL_INITIALIZE => self.handle_initialize(req).await,
            proto::TOOL_MEMORY_SAVE => self.handle_save(req).await,
            proto::TOOL_MEMORY_GET => self.handle_get(req).await,
            proto::TOOL_MEMORY_DELETE => self.handle_delete(req).await,
            proto::TOOL_MEMORY_UPDATE => self.handle_update(req).await,
            proto::TOOL_MEMORY_SEARCH => self.handle_search(req).await,
            proto::METHOD_RESOURCES_LIST | proto::TOOL_RESOURCE_LIST => {
                self.handle_resource_list(req).await
            }
            proto::METHOD_RESOURCES_READ | proto::TOOL_RESOURCE_READ => {
                self.handle_resource_read(req).await
            }
            proto::TOOL_MEMORY_IMPORT_BASIC => self.handle_import_basic(req).await,
            proto::TOOL_MEMORY_SYNC => self.handle_sync(req).await,
            #[cfg(feature = "encryption")]
            proto::TOOL_MEMORY_ENCRYPT => self.handle_encrypt(req).await,
            #[cfg(feature = "encryption")]
            proto::TOOL_MEMORY_DECRYPT => self.handle_decrypt(req).await,
            proto::TOOL_LIST_MEMORY_PROJECTS => self.handle_list_memory_projects(req).await,
            _ => {
                debug!(method = %method_name, "unknown method");
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32601,
                        message: "Method not found".into(),
                        data: None,
                    }),
                }
            }
        }
    }

    #[cfg(feature = "encryption")]
    async fn handle_encrypt(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::EncryptParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        // load
        let storage = Arc::clone(&self.storage);
        let idc = params.id.clone();
        let project = self.resolve_project_param(params.project.as_deref());
        let project_for_get = project.clone();
        let existing =
            match tokio::task::spawn_blocking(move || storage.get(&project_for_get, &idc)).await {
                Ok(Ok(Some(m))) => m,
                Ok(Ok(None)) => return mcp_error_response(idv, "E_NOT_FOUND", "not found"),
                Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
                Err(join_err) => {
                    return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string())
                }
            };
        let crypto = mcp_gitmem_crypto::CryptoFacade::new(mcp_gitmem_crypto::CryptoConfig {
            recipients: params.recipients.clone(),
            enabled: true,
        });
        let mut mem = existing.clone();
        match crypto
            .encrypt(&mem.title)
            .and_then(|t| Ok((t, crypto.encrypt(&mem.content)?)))
        {
            Ok((t, c)) => {
                mem.title = t;
                mem.content = c;
            }
            Err(e) => return mcp_error_response(idv, "E_ENCRYPTION", &e.to_string()),
        }
        mem.encryption = Some(mcp_gitmem_core::model::EncryptionMeta {
            algo: Some("age-x25519".into()),
            kid: None,
            encrypted: true,
        });
        mem.version = mem.version.saturating_add(1);
        mem.updated_at = chrono::Utc::now();
        // persist
        let storage = Arc::clone(&self.storage);
        let project_for_update = project.clone();
        let mem_cloned = mem.clone();
        let res =
            tokio::task::spawn_blocking(move || storage.update(&project_for_update, &mem_cloned))
                .await;
        if let Err(join_err) = res {
            return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string());
        }
        if let Err(e) = res.unwrap() {
            return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string());
        }
        // Queue index update asynchronously: metadata only (avoid indexing ciphertext)
        let meta_only = redact_encrypted_for_index(&mem);
        self.queue_index_update(project.clone(), meta_only);
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(true)),
            error: None,
        }
    }

    #[cfg(feature = "encryption")]
    async fn handle_decrypt(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::DecryptParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        // load
        let storage = Arc::clone(&self.storage);
        let idc = params.id.clone();
        let project = self.resolve_project_param(params.project.as_deref());
        let project_for_get = project.clone();
        let existing =
            match tokio::task::spawn_blocking(move || storage.get(&project_for_get, &idc)).await {
                Ok(Ok(Some(m))) => m,
                Ok(Ok(None)) => return mcp_error_response(idv, "E_NOT_FOUND", "not found"),
                Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
                Err(join_err) => {
                    return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string())
                }
            };
        let crypto = mcp_gitmem_crypto::CryptoFacade::new(mcp_gitmem_crypto::CryptoConfig {
            recipients: vec![],
            enabled: true,
        });
        let mut mem = existing.clone();
        match crypto
            .decrypt(
                &mem.title,
                &secrecy::SecretString::new(params.identity.clone()),
            )
            .and_then(|t| {
                Ok((
                    t,
                    crypto.decrypt(&mem.content, &secrecy::SecretString::new(params.identity))?,
                ))
            }) {
            Ok((t, c)) => {
                mem.title = t;
                mem.content = c;
            }
            Err(e) => return mcp_error_response(idv, "E_ENCRYPTION", &e.to_string()),
        }
        mem.encryption = Some(mcp_gitmem_core::model::EncryptionMeta {
            algo: Some("age-x25519".into()),
            kid: None,
            encrypted: false,
        });
        mem.version = mem.version.saturating_add(1);
        mem.updated_at = chrono::Utc::now();
        // persist and reindex all fields
        let storage = Arc::clone(&self.storage);
        let project_for_update = project.clone();
        let mem_cloned = mem.clone();
        let res =
            tokio::task::spawn_blocking(move || storage.update(&project_for_update, &mem_cloned))
                .await;
        if let Err(join_err) = res {
            return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string());
        }
        if let Err(e) = res.unwrap() {
            return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string());
        }
        // Queue index update asynchronously
        self.queue_index_update(project.clone(), mem.clone());
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(true)),
            error: None,
        }
    }

    async fn handle_save(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id.clone();
        let params: proto::SaveParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(id, e),
        };

        if params.content.trim().is_empty() {
            return mcp_error_response(id, "E_VALIDATION", "content must not be empty");
        }
        let r#type = match normalize_type(params.r#type.as_deref()) {
            Ok(t) => t,
            Err(e) => return mcp_error_response(id, "E_VALIDATION", &e.to_string()),
        };
        let title = params.title.unwrap_or_default();
        let mut mem = Memory::new(&title, &params.content, &r#type);
        if let Some(tags) = params.tags {
            mem.tags = tags;
        }
        mem.score = params.score;
        mem.ttl = params.ttl;
        let project = self.resolve_project_param(params.project.as_deref());
        ensure_project_tag(&mut mem, &project);
        debug!(memory_id = %mem.id, project = %project, memory_type = %mem.r#type, tags = ?mem.tags, ttl = ?mem.ttl, score = ?mem.score, "saving memory");
        #[cfg(feature = "encryption")]
        let index_doc = match self.prepare_memory_for_storage(&id, &mut mem) {
            Ok(doc) => doc,
            Err(resp) => return resp,
        };
        #[cfg(not(feature = "encryption"))]
        let index_doc = mem.clone();
        let storage = Arc::clone(&self.storage);
        let project_for_save = project.clone();
        let mem_for_save = mem.clone();
        let res =
            tokio::task::spawn_blocking(move || storage.save(&project_for_save, &mem_for_save))
                .await;
        if let Err(join_err) = res {
            error!(error=%join_err, "spawn_blocking join error");
            return mcp_error_response(id, "E_STORAGE_IO", &join_err.to_string());
        }
        if let Err(e) = res.unwrap() {
            error!(error=%e, "storage.save failed");
            return mcp_error_response(id, "E_STORAGE_IO", &e.to_string());
        }
        // Queue index update asynchronously
        self.queue_index_update(project.clone(), index_doc);
        debug!(memory_id = %mem.id, project = %project, "memory saved, index update queued");
        JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!(mem)),
            error: None,
        }
    }

    async fn handle_get(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::GetParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let id = params.id;
        let project = self.resolve_project_param(params.project.as_deref());
        debug!(memory_id = %id, project = %project, "fetching memory");
        let storage = Arc::clone(&self.storage);
        let project_for_get = project.clone();
        let id_for_log = id.clone();
        let res = tokio::task::spawn_blocking(move || storage.get(&project_for_get, &id)).await;
        if let Err(join_err) = res {
            return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string());
        }
        match res.unwrap() {
            Ok(Some(mem)) => {
                debug!(memory_id = %id_for_log, project = %project, "memory loaded");
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: idv,
                    result: Some(json!(mem)),
                    error: None,
                }
            }
            Ok(None) => {
                debug!(memory_id = %id_for_log, project = %project, "memory not found");
                mcp_error_response(idv, "E_NOT_FOUND", "not found")
            }
            Err(e) => mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
        }
    }

    async fn handle_delete(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::DeleteParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let hard = params.hard.unwrap_or(false);
        let idc = params.id.clone();
        let project = self.resolve_project_param(params.project.as_deref());
        debug!(memory_id = %idc, project = %project, hard, "deleting memory");
        let idx_id = idc.clone();
        let storage = Arc::clone(&self.storage);
        let project_for_delete = project.clone();
        let res =
            tokio::task::spawn_blocking(move || storage.delete(&project_for_delete, &idc, hard))
                .await;
        if let Err(join_err) = res {
            return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string());
        }
        match res.unwrap() {
            Ok(()) => {
                // Queue index delete asynchronously
                self.queue_index_delete(project.clone(), idx_id);
                debug!(memory_id = %params.id, project = %project, hard, "memory deleted, index delete queued");
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: idv,
                    result: Some(json!({"ok": true})),
                    error: None,
                }
            }
            Err(e) => mcp_error_response(idv, "E_NOT_FOUND", &e.to_string()),
        }
    }

    async fn handle_update(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::UpdateParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let patch_keys: Vec<String> = params
            .patch
            .as_object()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        let project = self.resolve_project_param(params.project.as_deref());
        debug!(
            memory_id = %params.id,
            project = %project,
            ?patch_keys,
            "updating memory"
        );

        // Load existing
        let storage = Arc::clone(&self.storage);
        let idc = params.id.clone();
        let project_for_get = project.clone();
        let existing =
            match tokio::task::spawn_blocking(move || storage.get(&project_for_get, &idc)).await {
                Ok(Ok(Some(m))) => m,
                Ok(Ok(None)) => return mcp_error_response(idv, "E_NOT_FOUND", "not found"),
                Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
                Err(join_err) => {
                    return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string())
                }
            };

        let mut mem = existing;
        #[cfg(feature = "encryption")]
        let mut content_changed = false;
        if let Some(v) = params.patch.get("content").and_then(|v| v.as_str()) {
            if v.trim().is_empty() {
                return mcp_error_response(idv, "E_VALIDATION", "content must not be empty");
            }
            mem.content = v.to_string();
            #[cfg(feature = "encryption")]
            {
                content_changed = true;
            }
        }
        if let Some(v) = params.patch.get("title").and_then(|v| v.as_str()) {
            mem.title = v.to_string();
            #[cfg(feature = "encryption")]
            {
                content_changed = true;
            }
        }
        if let Some(v) = params.patch.get("tags").and_then(|v| v.as_array()) {
            mem.tags = v
                .iter()
                .filter_map(|e| e.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(v) = params.patch.get("type").and_then(|v| v.as_str()) {
            match normalize_type(Some(v)) {
                Ok(t) => mem.r#type = t,
                Err(e) => return mcp_error_response(idv, "E_VALIDATION", &e.to_string()),
            }
        }
        if let Some(v) = params.patch.get("ttl").and_then(|v| {
            if v.is_string() {
                v.as_str().map(|s| s.to_string())
            } else {
                None
            }
        }) {
            mem.ttl = Some(v);
        } else if params
            .patch
            .get("ttl")
            .map(|v| v.is_null())
            .unwrap_or(false)
        {
            mem.ttl = None;
        }
        if let Some(v) = params.patch.get("score").and_then(|v| v.as_f64()) {
            mem.score = Some(v as f32);
        }
        mem.version = mem.version.saturating_add(1);
        mem.updated_at = Utc::now();
        ensure_project_tag(&mut mem, &project);
        #[cfg(feature = "encryption")]
        if content_changed {
            if let Some(meta) = mem.encryption.as_mut() {
                meta.encrypted = false;
                meta.algo = None;
                meta.kid = None;
            } else {
                mem.encryption = Some(EncryptionMeta {
                    algo: None,
                    kid: None,
                    encrypted: false,
                });
            }
        }
        #[cfg(feature = "encryption")]
        let index_doc = match self.prepare_memory_for_storage(&idv, &mut mem) {
            Ok(doc) => doc,
            Err(resp) => return resp,
        };
        #[cfg(not(feature = "encryption"))]
        let index_doc = mem.clone();

        // Persist and reindex
        let storage = Arc::clone(&self.storage);
        let project_for_update = project.clone();
        let mem_cloned = mem.clone();
        let res =
            tokio::task::spawn_blocking(move || storage.update(&project_for_update, &mem_cloned))
                .await;
        if let Err(join_err) = res {
            return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string());
        }
        if let Err(e) = res.unwrap() {
            let msg = e.to_string();
            if msg.to_lowercase().contains("conflict") {
                return mcp_error_response(idv, "E_CONFLICT", &msg);
            }
            return mcp_error_response(idv, "E_STORAGE_IO", &msg);
        }
        // Queue index update asynchronously
        self.queue_index_update(project.clone(), index_doc);
        debug!(
            memory_id = %mem.id,
            project = %project,
            ?patch_keys,
            "memory updated, index update queued"
        );
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(mem)),
            error: None,
        }
    }

    async fn handle_search(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::SearchParamsWire = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        // Extract filters for types and tags if present
        let mut types: Option<Vec<String>> = None;
        let mut tags: Option<Vec<String>> = None;
        if let Some(f) = &params.filters {
            if let Some(arr) = f.get("type").and_then(|v| v.as_array()) {
                types = Some(
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                );
            }
            if let Some(arr) = f.get("tags").and_then(|v| v.as_array()) {
                tags = Some(
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                );
            }
        }
        // time_range parsing
        let mut from_time = None;
        let mut to_time = None;
        if let Some(tr) = &params.time_range {
            if let Some(s) = tr.get("from").and_then(|v| v.as_str()) {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                    from_time = Some(dt.with_timezone(&chrono::Utc));
                }
            }
            if let Some(s) = tr.get("to").and_then(|v| v.as_str()) {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                    to_time = Some(dt.with_timezone(&chrono::Utc));
                }
            }
        }

        let sort_opt = params.sort.clone();
        let project = self.resolve_project_param(params.project.as_deref());
        let from_time_local = from_time;
        let to_time_local = to_time;
        let filter_types_count = types.as_ref().map(|v| v.len()).unwrap_or(0);
        let filter_tags_count = tags.as_ref().map(|v| v.len()).unwrap_or(0);
        let core = SearchParams {
            query: params.query.clone(),
            types,
            tags,
            limit: params.limit,
            offset: params.offset,
            sort: params.sort,
            from_time: from_time_local,
            to_time: to_time_local,
        };
        let query_preview: String = params.query.chars().take(64).collect();
        let query_len = params.query.chars().count();
        debug!(
            query_preview = %query_preview,
            query_len,
            limit = ?params.limit,
            offset = ?params.offset,
            sort = ?sort_opt,
            filter_types = filter_types_count,
            filter_tags = filter_tags_count,
            project = %project,
            "search request"
        );

        // Run index search in a blocking task if needed
        let index = Arc::clone(&self.index);
        let project_for_search = project.clone();
        let res =
            tokio::task::spawn_blocking(move || index.search(&project_for_search, &core)).await;
        let results = match res {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
            Err(join_err) => return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string()),
        };

        // Fetch full memory objects and carry forward index score for sorting if needed
        let mut out: Vec<(Option<f32>, Memory)> = Vec::new();
        for item in results.items.iter() {
            let storage = Arc::clone(&self.storage);
            let idc = item.id.clone();
            let project_for_get = project.clone();
            match tokio::task::spawn_blocking(move || storage.get(&project_for_get, &idc)).await {
                Ok(Ok(Some(m))) => out.push((item.score, m)),
                Ok(Ok(None)) => continue,
                Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
                Err(join_err) => {
                    return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string())
                }
            }
        }
        // TTL filtering at query time
        let now = chrono::Utc::now();
        out.retain(|(_, m)| match &m.ttl {
            Some(ttl) => ttl_not_expired(m.created_at, ttl, now),
            None => true,
        });
        // Time range filtering (server-side fallback for simple index)
        if let Some(ft) = from_time_local {
            out.retain(|(_, m)| m.updated_at >= ft);
        }
        if let Some(tt) = to_time_local {
            out.retain(|(_, m)| m.updated_at <= tt);
        }

        // Sorting
        match sort_opt.as_deref() {
            Some("recency") => out.sort_by(|a, b| b.1.updated_at.cmp(&a.1.updated_at)),
            Some("score") => out.sort_by(|a, b| {
                let ascore = a.1.score.unwrap_or(a.0.unwrap_or(0.0));
                let bscore = b.1.score.unwrap_or(b.0.unwrap_or(0.0));
                bscore
                    .partial_cmp(&ascore)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            _ => { /* default relevance = index score order already applied */ }
        }

        let items_only: Vec<Memory> = out.into_iter().map(|(_, m)| m).collect();
        let total = items_only.len() as u64;
        debug!(total_results = total, project = %project, "search completed");
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!({"items": items_only, "total": total})),
            error: None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn handle_initialize(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::InitializeParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };

        let protocol_version = params
            .protocol_version
            .unwrap_or_else(|| proto::MCP_PROTOCOL_VERSION.to_string());
        debug!(protocol_version = %protocol_version, "initialize handshake");

        let metadata = serde_json::Value::Object(RmcpAdapter::<S, I>::metadata());

        let capabilities = json!({
            "experimental": {
                "gitmem": metadata.clone()
            },
            "resources": {
                "list": {
                    "available": true
                },
                "read": {
                    "available": true
                }
            },
            "tools": {
                "list": {
                    "available": true
                },
                "call": {
                    "available": true
                }
            }
        });
        let result = proto::InitializeResult {
            protocol_version,
            capabilities,
            server_info: proto::ServerInfo {
                name: "gitmem".into(),
                title: Some("GitMem MCP server".into()),
                version: env!("CARGO_PKG_VERSION").into(),
                website_url: None,
                icons: None,
            },
            instructions: None,
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(result)),
            error: None,
        }
    }

    async fn handle_write_note(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::WriteNoteParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let save_params = proto::SaveParams {
            title: params.title,
            content: params.content,
            r#type: Some(params.note_type.unwrap_or_else(|| "note".to_string())),
            tags: params.tags,
            ttl: None,
            score: None,
            project: params.project,
        };
        let save_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!(save_params)),
        };
        self.handle_save(save_req).await
    }

    async fn handle_read_note(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ReadNoteParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let get_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_MEMORY_GET.into(),
            params: Some(json!({
                "id": params.id,
                "project": params.project
            })),
        };
        self.handle_get(get_req).await
    }

    async fn handle_view_note(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        self.handle_read_note(req).await
    }

    async fn handle_edit_note(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::EditNoteParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let mut patch = serde_json::Map::new();
        if let Some(title) = params.title {
            patch.insert("title".into(), json!(title));
        }
        if let Some(content) = params.content {
            patch.insert("content".into(), json!(content));
        }
        if let Some(tags) = params.tags {
            patch.insert("tags".into(), json!(tags));
        }
        if let Some(note_type) = params.note_type {
            patch.insert("type".into(), json!(note_type));
        }
        let update_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_MEMORY_UPDATE.into(),
            params: Some(json!({
                "id": params.id,
                "project": params.project,
                "patch": serde_json::Value::Object(patch)
            })),
        };
        self.handle_update(update_req).await
    }

    async fn handle_delete_note(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::DeleteNoteParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let delete_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_MEMORY_DELETE.into(),
            params: Some(json!({
                "id": params.id,
                "hard": params.hard,
                "project": params.project
            })),
        };
        self.handle_delete(delete_req).await
    }

    async fn handle_move_note(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::MoveNoteParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let src_project = self.resolve_project_param(params.project.as_deref());
        let dest_project = sanitize_project_id(&params.target_project);
        let note_id = params.id.clone();
        if src_project == dest_project {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: Some(json!({"ok": true, "id": note_id})),
                error: None,
            };
        }

        let storage_get = Arc::clone(&self.storage);
        let src_for_get = src_project.clone();
        let note_id_for_get = note_id.clone();
        let existing =
            tokio::task::spawn_blocking(move || storage_get.get(&src_for_get, &note_id_for_get))
                .await;
        let memory = match existing {
            Ok(Ok(Some(mem))) => mem,
            Ok(Ok(None)) => return mcp_error_response(idv, "E_NOT_FOUND", "not found"),
            Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
            Err(join_err) => return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string()),
        };

        let storage_delete = Arc::clone(&self.storage);
        let delete_project = src_project.clone();
        let delete_id = note_id.clone();
        let delete_res = tokio::task::spawn_blocking(move || {
            storage_delete.delete(&delete_project, &delete_id, true)
        })
        .await;
        if let Err(join_err) = delete_res {
            return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string());
        }
        if let Err(e) = delete_res.unwrap() {
            return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string());
        }

        // Queue index delete asynchronously
        self.queue_index_delete(src_project.clone(), note_id.clone());

        let mut moved = memory;
        moved.updated_at = Utc::now();
        replace_project_tag(&mut moved, &src_project, &dest_project);

        let storage_save = Arc::clone(&self.storage);
        let dest_for_save = dest_project.clone();
        let moved_for_save = moved.clone();
        let save_res =
            tokio::task::spawn_blocking(move || storage_save.save(&dest_for_save, &moved_for_save))
                .await;
        if let Err(join_err) = save_res {
            return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string());
        }
        if let Err(e) = save_res.unwrap() {
            return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string());
        }

        // Queue index update asynchronously
        #[cfg(feature = "encryption")]
        let moved_index_doc = if self.encryption.is_some() {
            redact_encrypted_for_index(&moved)
        } else {
            moved.clone()
        };
        #[cfg(not(feature = "encryption"))]
        let moved_index_doc = moved.clone();
        self.queue_index_update(dest_project.clone(), moved_index_doc);

        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!({
                "ok": true,
                "id": moved.id,
                "project": dest_project,
            })),
            error: None,
        }
    }

    async fn handle_search_notes(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::SearchNotesParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let mut filters = serde_json::Map::new();
        if let Some(tags) = params.tags.clone() {
            filters.insert("tags".into(), json!(tags));
        }
        if let Some(types) = params.note_types.clone() {
            filters.insert("type".into(), json!(types));
        }
        let search_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({
                "query": params.query.unwrap_or_default(),
                "filters": if filters.is_empty() { None } else { Some(serde_json::Value::Object(filters)) },
                "limit": params.limit,
                "offset": params.offset,
                "project": params.project
            })),
        };
        let resp = self.handle_search(search_req).await;
        if resp.error.is_some() {
            return resp;
        }
        let value = resp
            .result
            .unwrap_or_else(|| json!({"items": [], "total": 0}));
        let notes_value = value.get("items").cloned().unwrap_or_else(|| json!([]));
        let note_vec = notes_value
            .as_array()
            .map(|arr| arr.clone())
            .unwrap_or_default();
        let total = value.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(proto::SearchNotesResult {
                notes: note_vec,
                total,
            })),
            error: None,
        }
    }

    async fn handle_recent_activity(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::RecentActivityParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = self.resolve_project_param(params.project.as_deref());
        let limit = params.limit.unwrap_or(10) as usize;
        let storage = Arc::clone(&self.storage);
        let project_for_list = project.clone();
        let res =
            tokio::task::spawn_blocking(move || storage.list_recent_ids(&project_for_list, limit))
                .await;
        let ids = match res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
            Err(join_err) => return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string()),
        };
        let mut notes = Vec::new();
        for id in ids {
            let storage = Arc::clone(&self.storage);
            let project_for_get = project.clone();
            match tokio::task::spawn_blocking(move || storage.get(&project_for_get, &id)).await {
                Ok(Ok(Some(mem))) => notes.push(memory_to_json(&mem)),
                Ok(Ok(None)) => continue,
                Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
                Err(join_err) => {
                    return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string())
                }
            }
        }
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(proto::RecentActivityResult { notes })),
            error: None,
        }
    }

    async fn handle_build_context(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::BuildContextParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        if let Some(query) = params.query.clone() {
            let search_req = JsonRpcRequest {
                jsonrpc: Some("2.0".into()),
                id: idv.clone(),
                method: proto::TOOL_SEARCH_NOTES.into(),
                params: Some(json!({
                    "query": query,
                    "project": params.project,
                    "limit": params.limit,
                })),
            };
            let resp = self.handle_search_notes(search_req).await;
            if resp.error.is_some() {
                return resp;
            }
            let result_value = resp.result.unwrap_or_else(|| json!({"notes": []}));
            let search: proto::SearchNotesResult =
                serde_json::from_value(result_value).unwrap_or(proto::SearchNotesResult {
                    notes: Vec::new(),
                    total: 0,
                });
            let ctx = proto::BuildContextResult {
                notes: search.notes,
            };
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: Some(json!(ctx)),
                error: None,
            };
        }
        let recent_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_RECENT_ACTIVITY.into(),
            params: Some(json!({
                "project": params.project,
                "limit": params.limit,
            })),
        };
        let resp = self.handle_recent_activity(recent_req).await;
        if resp.error.is_some() {
            return resp;
        }
        let recent_value = resp.result.unwrap_or_else(|| json!({"notes": []}));
        let recent: proto::RecentActivityResult = serde_json::from_value(recent_value)
            .unwrap_or(proto::RecentActivityResult { notes: Vec::new() });
        let ctx = proto::BuildContextResult {
            notes: recent.notes,
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(ctx)),
            error: None,
        }
    }

    async fn handle_read_content(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ReadContentParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = self.resolve_project_param(params.project.as_deref());
        let storage = Arc::clone(&self.storage);
        let project_for_get = project.clone();
        let id = params.id.clone();
        let res = tokio::task::spawn_blocking(move || storage.get(&project_for_get, &id)).await;
        match res {
            Ok(Ok(Some(mem))) => JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: Some(json!(proto::ReadContentResult {
                    id: mem.id,
                    content: mem.content,
                })),
                error: None,
            },
            Ok(Ok(None)) => mcp_error_response(idv, "E_NOT_FOUND", "not found"),
            Ok(Err(e)) => mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
            Err(join_err) => mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string()),
        }
    }

    async fn handle_search_prompt(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::SearchPromptParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let proto::SearchPromptParams {
            query,
            project: project_opt,
            limit: limit_opt,
        } = params;
        let project = self.resolve_project_param(project_opt.as_deref());
        let limit = limit_opt.unwrap_or(5).clamp(1, 25);
        let search_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_SEARCH_NOTES.into(),
            params: Some(json!({
                "query": query,
                "project": project,
                "limit": limit
            })),
        };
        let resp = self.handle_search_notes(search_req).await;
        if let Some(err) = resp.error {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: None,
                error: Some(err),
            };
        }
        let payload = resp
            .result
            .unwrap_or_else(|| json!({"notes": [], "total": 0}));
        let search: proto::SearchNotesResult = match serde_json::from_value(payload) {
            Ok(r) => r,
            Err(e) => return internal_error(idv, &e.to_string()),
        };
        let mut results = Vec::new();
        for note in search.notes.iter().take(limit as usize) {
            let id = note
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let title = note
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let content = note
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let updated_at = note
                .get("updated_at")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let snippet = truncate_text_for_snippet(&content, 180);
            results.push(json!({
                "id": id,
                "title": title,
                "snippet": snippet,
                "url": format!("mem://{}/{}", project, note.get("id").and_then(|v| v.as_str()).unwrap_or_default()),
                "updatedAt": updated_at
            }));
        }
        let result = proto::SearchPromptResult {
            query,
            project: project.clone(),
            total: search.total,
            results,
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(result)),
            error: None,
        }
    }

    async fn handle_fetch(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::FetchParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = self.resolve_project_param(params.project.as_deref());
        let memory_id = params.id.clone();
        let read_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_READ_NOTE.into(),
            params: Some(json!({
                "id": memory_id,
                "project": project
            })),
        };
        let resp = self.handle_read_note(read_req).await;
        if let Some(err) = resp.error {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: None,
                error: Some(err),
            };
        }
        let payload = resp.result.unwrap_or_else(|| json!({}));
        let mem: Memory = match serde_json::from_value(payload) {
            Ok(m) => m,
            Err(e) => return internal_error(idv, &e.to_string()),
        };
        let result = proto::FetchResult {
            id: mem.id.clone(),
            project: project.clone(),
            title: mem.title.clone(),
            content: mem.content.clone(),
            tags: mem.tags.clone(),
            note_type: mem.r#type.clone(),
            created_at: format_timestamp(mem.created_at),
            updated_at: format_timestamp(mem.updated_at),
            url: format!("mem://{}/{}", project, mem.id),
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(result)),
            error: None,
        }
    }

    async fn handle_project_info(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ProjectInfoParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = self.resolve_project_param(params.project.as_deref());
        let mut recent_limit = params.recent_limit.unwrap_or(10) as usize;
        if recent_limit == 0 {
            recent_limit = 1;
        }
        if recent_limit > 50 {
            recent_limit = 50;
        }
        let storage = Arc::clone(&self.storage);
        let project_for_list = project.clone();
        let ids_res = tokio::task::spawn_blocking(move || {
            storage.list_recent_ids(&project_for_list, recent_limit)
        })
        .await;
        let ids = match ids_res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
            Err(join_err) => return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string()),
        };
        let mut recent_notes = Vec::new();
        let mut last_updated: Option<DateTime<Utc>> = None;
        for id in ids.iter() {
            let storage = Arc::clone(&self.storage);
            let project_for_get = project.clone();
            let note_id = id.clone();
            match tokio::task::spawn_blocking(move || storage.get(&project_for_get, &note_id)).await
            {
                Ok(Ok(Some(mem))) => {
                    if last_updated.map_or(true, |current| mem.updated_at > current) {
                        last_updated = Some(mem.updated_at);
                    }
                    recent_notes.push(json!({
                        "id": mem.id,
                        "title": mem.title,
                        "updatedAt": format_timestamp(mem.updated_at),
                        "url": format!("mem://{}/{}", project, mem.id),
                    }));
                }
                Ok(Ok(None)) => continue,
                Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
                Err(join_err) => {
                    return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string())
                }
            }
        }
        let result = proto::ProjectInfoResult {
            project: project.clone(),
            note_count: ids.len() as u64,
            last_updated: last_updated.map(format_timestamp),
            recent_notes,
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(result)),
            error: None,
        }
    }

    async fn handle_canvas(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::CanvasParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = self.resolve_project_param(params.project.as_deref());
        let title = params.title.clone().unwrap_or_else(|| "Canvas".to_string());
        let payload = json!({
            "nodes": params.nodes,
            "edges": params.edges,
            "folder": params.folder
        });
        let content = match serde_json::to_string_pretty(&payload) {
            Ok(c) => c,
            Err(e) => return internal_error(idv, &e.to_string()),
        };
        let save_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({
                "title": title,
                "content": content,
                "type": "note",
                "tags": ["canvas"],
                "project": project
            })),
        };
        let resp = self.handle_save(save_req).await;
        if let Some(err) = resp.error {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: None,
                error: Some(err),
            };
        }
        let payload = resp.result.unwrap_or_else(|| json!({}));
        let mem: Memory = match serde_json::from_value(payload) {
            Ok(m) => m,
            Err(e) => return internal_error(idv, &e.to_string()),
        };
        let result = proto::CanvasResult {
            id: mem.id,
            project,
            title: mem.title,
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(result)),
            error: None,
        }
    }

    async fn handle_ai_assistant_guide(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::AiAssistantGuideParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let _language = params.language.unwrap_or_else(|| "en".to_string());
        let quick_actions = [
            "• Use `write_note` to capture fresh information.",
            "• Use `search` to find memories across projects.",
            "• Use `fetch` after search to load the full note body.",
        ]
        .join("\n");
        let project_tips = [
            "• Switch projects by passing the `project` field to any tool.",
            "• `project_info` surfaces recent notes and last update times.",
            "• `move_note` can retag a note into a different project.",
        ]
        .join("\n");
        let maintenance = [
            "• Run `sync_status` before and after large updates.",
            "• `search_notes` + `recent_activity` help verify imports.",
            "• For encrypted workspaces ensure recipients are configured before saving.",
        ]
        .join("\n");
        let sections = vec![
            json!({
                "title": "Quick Actions",
                "content": quick_actions
            }),
            json!({
                "title": "Project Tips",
                "content": project_tips
            }),
            json!({
                "title": "Maintenance",
                "content": maintenance
            }),
        ];
        let result = proto::AiAssistantGuideResult {
            title: "GitMem Assistant Guide".to_string(),
            sections,
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(result)),
            error: None,
        }
    }

    async fn handle_continue_conversation(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ContinueConversationParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let proto::ContinueConversationParams {
            topic,
            project: project_opt,
            query,
            limit,
        } = params;
        let project = self.resolve_project_param(project_opt.as_deref());
        let limit = limit.unwrap_or(5).clamp(1, 10);
        let effective_query = query.clone().or_else(|| topic.clone()).unwrap_or_default();
        let mut payload = serde_json::Map::new();
        payload.insert("project".into(), json!(project));
        payload.insert("limit".into(), json!(limit));
        if !effective_query.trim().is_empty() {
            payload.insert("query".into(), json!(effective_query.clone()));
        }
        let ctx_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: idv.clone(),
            method: proto::TOOL_BUILD_CONTEXT.into(),
            params: Some(serde_json::Value::Object(payload)),
        };
        let resp = self.handle_build_context(ctx_req).await;
        if let Some(err) = resp.error {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: None,
                error: Some(err),
            };
        }
        let payload = resp.result.unwrap_or_else(|| json!({"notes": []}));
        let ctx: proto::BuildContextResult = match serde_json::from_value(payload) {
            Ok(c) => c,
            Err(e) => return internal_error(idv, &e.to_string()),
        };
        let mut suggestions = Vec::new();
        for note in ctx.notes {
            let title = note
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let content = note
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let id = note
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            suggestions.push(json!({
                "id": id.clone(),
                "title": title,
                "snippet": truncate_text_for_snippet(&content, 200),
                "url": format!("mem://{}/{}", project, id)
            }));
        }
        let result = proto::ContinueConversationResult {
            topic,
            project,
            suggestions,
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(result)),
            error: None,
        }
    }

    async fn handle_tools_list(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ListToolsParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        // currently unused but parsed for validation
        let _ = params;
        debug!("tools.list requested");
        let tools = match build_tool_definitions() {
            Ok(t) => t,
            Err(e) => {
                error!(error=%e, "failed to build tool definitions");
                return internal_error(idv, "failed to build tool definitions");
            }
        };
        debug!(tool_count = tools.len(), "tools.list returning definitions");
        let result = match serde_json::to_value(proto::ListToolsResult {
            tools,
            next_cursor: None,
        }) {
            Ok(v) => v,
            Err(e) => {
                error!(error=%e, "failed to serialize tool list");
                return internal_error(idv, "failed to serialize tool list");
            }
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(result),
            error: None,
        }
    }

    async fn handle_tools_call(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::CallToolParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let proto::CallToolParams {
            tool_name,
            arguments,
        } = params;
        debug!(requested_tool = %tool_name, "tools.call requested");
        if tool_name == proto::METHOD_TOOLS_CALL
            || tool_name == proto::METHOD_TOOLS_LIST
            || tool_name == proto::exported_tool_name(proto::METHOD_TOOLS_CALL)
            || tool_name == proto::exported_tool_name(proto::METHOD_TOOLS_LIST)
        {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: "Method not found".into(),
                    data: None,
                }),
            };
        }
        let canonical_name = match proto::canonical_tool_name(&tool_name) {
            Some(name) => name,
            None => {
                return JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: idv,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32601,
                        message: "Method not found".into(),
                        data: None,
                    }),
                };
            }
        };
        debug!(requested_tool = %tool_name, canonical_tool = canonical_name, "dispatching tool call");
        let arguments = match normalize_tool_arguments(arguments) {
            Ok(v) => v,
            Err(e) => return invalid_params(idv, e),
        };
        let inner_resp = match canonical_name {
            proto::TOOL_MEMORY_SAVE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MEMORY_SAVE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_save(req).await
            }
            proto::TOOL_MEMORY_GET => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MEMORY_GET.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_get(req).await
            }
            proto::TOOL_MEMORY_SEARCH => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MEMORY_SEARCH.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_search(req).await
            }
            proto::TOOL_MEMORY_UPDATE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MEMORY_UPDATE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_update(req).await
            }
            proto::TOOL_MEMORY_DELETE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MEMORY_DELETE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_delete(req).await
            }
            proto::TOOL_MEMORY_IMPORT_BASIC => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MEMORY_IMPORT_BASIC.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_import_basic(req).await
            }
            proto::TOOL_MEMORY_SYNC => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MEMORY_SYNC.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_sync(req).await
            }
            proto::TOOL_LIST_MEMORY_PROJECTS => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_LIST_MEMORY_PROJECTS.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_list_memory_projects(req).await
            }
            proto::TOOL_CREATE_MEMORY_PROJECT => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_CREATE_MEMORY_PROJECT.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_create_project(req).await
            }
            proto::TOOL_DELETE_MEMORY_PROJECT => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_DELETE_MEMORY_PROJECT.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_delete_project(req).await
            }
            proto::TOOL_LIST_DIRECTORY => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_LIST_DIRECTORY.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_list_directory(req).await
            }
            proto::TOOL_SYNC_STATUS => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_SYNC_STATUS.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_sync_status(req).await
            }
            proto::TOOL_PROJECT_LINK_FOLDER => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_PROJECT_LINK_FOLDER.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_link_folder(req).await
            }
            proto::TOOL_PROJECT_UNLINK_FOLDER => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_PROJECT_UNLINK_FOLDER.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_unlink_folder(req).await
            }
            proto::TOOL_PROJECT_LIST_LINKS => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_PROJECT_LIST_LINKS.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_list_linked_folders(req).await
            }
            proto::TOOL_WRITE_NOTE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_WRITE_NOTE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_write_note(req).await
            }
            proto::TOOL_READ_NOTE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_READ_NOTE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_read_note(req).await
            }
            proto::TOOL_VIEW_NOTE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_VIEW_NOTE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_view_note(req).await
            }
            proto::TOOL_EDIT_NOTE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_EDIT_NOTE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_edit_note(req).await
            }
            proto::TOOL_DELETE_NOTE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_DELETE_NOTE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_delete_note(req).await
            }
            proto::TOOL_MOVE_NOTE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MOVE_NOTE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_move_note(req).await
            }
            proto::TOOL_SEARCH_NOTES => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_SEARCH_NOTES.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_search_notes(req).await
            }
            proto::TOOL_RECENT_ACTIVITY => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_RECENT_ACTIVITY.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_recent_activity(req).await
            }
            proto::TOOL_BUILD_CONTEXT => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_BUILD_CONTEXT.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_build_context(req).await
            }
            proto::TOOL_READ_CONTENT => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_READ_CONTENT.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_read_content(req).await
            }
            proto::TOOL_SEARCH => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_SEARCH.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_search_prompt(req).await
            }
            proto::TOOL_FETCH => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_FETCH.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_fetch(req).await
            }
            proto::TOOL_PROJECT_INFO => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_PROJECT_INFO.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_project_info(req).await
            }
            proto::TOOL_CANVAS => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_CANVAS.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_canvas(req).await
            }
            proto::TOOL_AI_ASSISTANT_GUIDE => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_AI_ASSISTANT_GUIDE.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_ai_assistant_guide(req).await
            }
            proto::TOOL_CONTINUE_CONVERSATION => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_CONTINUE_CONVERSATION.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_continue_conversation(req).await
            }
            #[cfg(feature = "encryption")]
            proto::TOOL_MEMORY_ENCRYPT => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MEMORY_ENCRYPT.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_encrypt(req).await
            }
            #[cfg(feature = "encryption")]
            proto::TOOL_MEMORY_DECRYPT => {
                let req = JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: idv.clone(),
                    method: proto::TOOL_MEMORY_DECRYPT.into(),
                    params: Some(arguments.clone()),
                };
                self.handle_decrypt(req).await
            }
            _ => JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv.clone(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: "Method not found".into(),
                    data: None,
                }),
            },
        };
        let JsonRpcResponse {
            result: inner_result,
            error: inner_error,
            ..
        } = inner_resp;
        if let Some(err) = inner_error {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: None,
                error: Some(err),
            };
        }
        let payload = inner_result.unwrap_or(serde_json::Value::Null);
        let payload_clone = payload.clone();
        let payload_text = serde_json::to_string(&payload).unwrap_or_else(|_| "null".to_string());
        let call_result = json!({
            "structuredContent": payload_clone,
            "content": [
                {
                    "type": "text",
                    "text": payload_text
                }
            ]
        });
        debug!(requested_tool = %tool_name, canonical_tool = canonical_name, "tools.call completed");
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(call_result),
            error: None,
        }
    }

    async fn handle_resource_list(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ResourceListParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let limit = params.limit.unwrap_or(100) as usize;
        let project = self.resolve_project_param(params.project.as_deref());
        debug!(limit, project = %project, "resource.list requested");
        let storage = Arc::clone(&self.storage);
        let project_for_list = project.clone();
        let res =
            tokio::task::spawn_blocking(move || storage.list_recent_ids(&project_for_list, limit))
                .await;
        match res {
            Ok(Ok(ids)) => {
                let resources: Vec<proto::ResourceDescriptor> = ids
                    .into_iter()
                    .map(|id| proto::ResourceDescriptor {
                        uri: format!("mem://{}/{}", project, id),
                        name: Some(id),
                        description: None,
                        mime_type: Some("application/json".into()),
                        metadata: None,
                    })
                    .collect();
                debug!(resource_count = resources.len(), project = %project, "resource.list responding");
                let result = proto::ResourceListResult {
                    resources,
                    next_cursor: None,
                };
                let result_json = match serde_json::to_value(&result) {
                    Ok(value) => value,
                    Err(e) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
                };
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: idv,
                    result: Some(result_json),
                    error: None,
                }
            }
            Ok(Err(e)) => mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
            Err(join_err) => mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string()),
        }
    }

    async fn handle_list_memory_projects(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let _params: proto::ListMemoryProjectsParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let storage = Arc::clone(&self.storage);
        let res = tokio::task::spawn_blocking(move || storage.list_projects()).await;
        let projects = match res {
            Ok(Ok(list)) => list,
            Ok(Err(e)) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
            Err(join_err) => return mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string()),
        };
        let mut descriptors: Vec<proto::MemoryProjectDescriptor> = projects
            .into_iter()
            .map(|p| proto::MemoryProjectDescriptor {
                id: p.clone(),
                name: p,
            })
            .collect();
        descriptors.sort_by(|a, b| a.id.cmp(&b.id));
        let result = proto::ListMemoryProjectsResult {
            projects: descriptors,
            next_cursor: None,
        };
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(result)),
            error: None,
        }
    }

    async fn handle_create_project(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::CreateMemoryProjectParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = sanitize_project_id(&params.id);
        match self.storage_create_project(&project) {
            Ok(()) => {
                let name = params.name.unwrap_or_else(|| project.clone());
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: idv,
                    result: Some(json!({
                        "id": project,
                        "name": name,
                        "ok": true
                    })),
                    error: None,
                }
            }
            Err(e) => mcp_error_response(idv, "E_STORAGE_IO", &e),
        }
    }

    async fn handle_delete_project(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::DeleteProjectParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = sanitize_project_id(&params.id);
        let force = params.force.unwrap_or(false);
        if project == DEFAULT_PROJECT_ID && !force {
            return mcp_error_response(
                idv,
                "E_VALIDATION",
                "cannot delete default project without force=true",
            );
        }
        match self.storage_delete_project(&project) {
            Ok(()) => JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: Some(json!({"ok": true})),
                error: None,
            },
            Err(e) => mcp_error_response(idv, "E_STORAGE_IO", &e),
        }
    }

    async fn handle_list_directory(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ListDirectoryParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = self.resolve_project_param(params.project.as_deref());
        let path = params.path.unwrap_or_default();
        match self.storage_list_directory(&project, &path) {
            Ok(entries) => {
                let result = proto::ListDirectoryResult { entries };
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: idv,
                    result: Some(json!(result)),
                    error: None,
                }
            }
            Err(e) => mcp_error_response(idv, "E_STORAGE_IO", &e),
        }
    }

    async fn handle_sync_status(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::SyncStatusParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = self.resolve_project_param(params.project.as_deref());
        let status = self.storage_sync_status(&project);
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!(status)),
            error: None,
        }
    }

    async fn handle_link_folder(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::LinkFolderParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        debug!(project = %params.project, path = %params.path, "link_folder requested");
        match self.storage_link_folder(&params) {
            Ok(result) => JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: Some(json!(result)),
                error: None,
            },
            Err(err) => mcp_error_response(idv, "E_STORAGE_IO", &err),
        }
    }

    async fn handle_unlink_folder(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::UnlinkFolderParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        debug!(project = %params.project, path = %params.path.as_deref().unwrap_or("<all>"), "unlink_folder requested");
        match self.storage_unlink_folder(&params) {
            Ok(result) => JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: Some(json!(result)),
                error: None,
            },
            Err(err) => mcp_error_response(idv, "E_STORAGE_IO", &err),
        }
    }

    async fn handle_list_linked_folders(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ListLinkedFoldersParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let project = params.project.as_deref().map(sanitize_project_id);
        debug!(project = ?project, "list_linked_folders requested");
        match self.storage_list_linked_folders(project.as_ref()) {
            Ok(links) => JsonRpcResponse {
                jsonrpc: "2.0",
                id: idv,
                result: Some(json!(proto::ListLinkedFoldersResult { links })),
                error: None,
            },
            Err(err) => mcp_error_response(idv, "E_STORAGE_IO", &err),
        }
    }

    #[allow(unused_variables)]
    fn storage_create_project(&self, project: &ProjectId) -> Result<(), String> {
        let storage = self.storage.as_ref();
        #[cfg(feature = "backend-local")]
        if let Some(local) = storage.as_any().downcast_ref::<LocalStorage>() {
            return local.create_project(project).map_err(|e| e.to_string());
        }
        #[cfg(feature = "backend-github")]
        if let Some(github) = storage.as_any().downcast_ref::<GithubStorage>() {
            return github.create_project(project).map_err(|e| e.to_string());
        }
        #[cfg(any(feature = "backend-ephemeral", test))]
        if let Some(ephemeral) = storage.as_any().downcast_ref::<EphemeralStorage>() {
            ephemeral.ensure_project(project);
            return Ok(());
        }
        Err("project management not supported for this backend".into())
    }

    #[allow(unused_variables)]
    fn storage_delete_project(&self, project: &ProjectId) -> Result<(), String> {
        let storage = self.storage.as_ref();
        #[cfg(feature = "backend-local")]
        if let Some(local) = storage.as_any().downcast_ref::<LocalStorage>() {
            return local.delete_project(project).map_err(|e| e.to_string());
        }
        #[cfg(feature = "backend-github")]
        if let Some(github) = storage.as_any().downcast_ref::<GithubStorage>() {
            return github.delete_project(project).map_err(|e| e.to_string());
        }
        #[cfg(any(feature = "backend-ephemeral", test))]
        if let Some(ephemeral) = storage.as_any().downcast_ref::<EphemeralStorage>() {
            if ephemeral.delete_project(project) {
                return Ok(());
            }
            return Err("project not found".into());
        }
        Err("project management not supported for this backend".into())
    }

    #[cfg(feature = "backend-local")]
    fn watch_to_proto(settings: &LinkWatchSettings) -> proto::LinkWatchInfo {
        proto::LinkWatchInfo {
            mode: settings.mode_str().to_string(),
            poll_interval_ms: Some(settings.poll_interval_ms()),
            jitter_pct: Some(settings.jitter_pct()),
            platform: settings.platform().cloned(),
        }
    }

    #[cfg(feature = "backend-local")]
    fn link_result_from_info(info: &LinkedFolderInfo) -> proto::LinkFolderResult {
        proto::LinkFolderResult {
            project: info.project.clone(),
            path: info.path.clone(),
            display_path: info.display_path.clone(),
            resolved_path: info.resolved_path.clone(),
            include: info.include.clone(),
            exclude: info.exclude.clone(),
            link_id: info.link_id.clone(),
            watch: Some(Self::watch_to_proto(&info.watch)),
            created_at: Some(info.created_at.clone()),
            last_scan: info.last_scan.clone(),
            file_count: Some(info.file_count),
            total_bytes: Some(info.total_bytes),
            last_error: info.last_error.clone(),
            status: Some(info.status.clone()),
            last_runtime_ms: info.last_runtime_ms,
        }
    }

    #[cfg(feature = "backend-local")]
    fn link_descriptor_from_info(info: &LinkedFolderInfo) -> proto::LinkedFolderDescriptor {
        proto::LinkedFolderDescriptor {
            project: info.project.clone(),
            path: info.path.clone(),
            display_path: info.display_path.clone(),
            resolved_path: info.resolved_path.clone(),
            include: info.include.clone(),
            exclude: info.exclude.clone(),
            link_id: info.link_id.clone(),
            watch: Some(Self::watch_to_proto(&info.watch)),
            created_at: Some(info.created_at.clone()),
            last_scan: info.last_scan.clone(),
            last_error: info.last_error.clone(),
            file_count: Some(info.file_count),
            total_bytes: Some(info.total_bytes),
            status: Some(info.status.clone()),
            last_runtime_ms: info.last_runtime_ms,
        }
    }

    #[cfg(feature = "backend-local")]
    fn jitter_offset_ms(link_id: &str, interval_ms: u64, jitter_pct: u32) -> i64 {
        if jitter_pct == 0 || interval_ms == 0 {
            return 0;
        }
        let mut hasher = Sha256::new();
        hasher.update(link_id.as_bytes());
        let digest = hasher.finalize();
        // Use first 2 bytes to derive value between 0 and 1
        let raw = u16::from_be_bytes([digest[0], digest[1]]) as f64 / u16::MAX as f64;
        // Map to range [-1, 1]
        let centered = (raw * 2.0) - 1.0;
        let jitter_window = interval_ms as f64 * (jitter_pct as f64 / 100.0);
        let offset = centered * jitter_window;
        offset.round() as i64
    }

    #[allow(unused_variables)]
    fn storage_link_folder(
        &self,
        params: &proto::LinkFolderParams,
    ) -> Result<proto::LinkFolderResult, String> {
        let project = sanitize_project_id(&params.project);
        let storage = self.storage.as_ref();
        #[cfg(feature = "backend-local")]
        if let Some(local) = storage.as_any().downcast_ref::<LocalStorage>() {
            let mut info = local
                .link_external_folder(
                    &project,
                    &params.path,
                    params.include.clone(),
                    params.exclude.clone(),
                    params.watch_mode.as_deref(),
                    params.poll_interval_ms,
                    params.jitter_pct,
                )
                .map_err(|e| e.to_string())?;

            if params.rescan.unwrap_or(true) {
                let filters = vec![info.resolved_path.clone()];
                let _ = local
                    .rescan_external_folders(&project, Some(&filters))
                    .map_err(|e| e.to_string())?;
                if let Some(updated) = local
                    .list_external_folders(Some(&project))
                    .map_err(|e| e.to_string())?
                    .into_iter()
                    .find(|entry| entry.link_id == info.link_id)
                {
                    info = updated;
                }
            }
            return Ok(Self::link_result_from_info(&info));
        }
        Err("external folder linking not supported for this backend".into())
    }

    #[allow(unused_variables)]
    fn storage_unlink_folder(
        &self,
        params: &proto::UnlinkFolderParams,
    ) -> Result<proto::UnlinkFolderResult, String> {
        let project = sanitize_project_id(&params.project);
        let storage = self.storage.as_ref();
        #[cfg(feature = "backend-local")]
        if let Some(local) = storage.as_any().downcast_ref::<LocalStorage>() {
            let removed = local
                .unlink_external_folder(&project, params.path.as_deref())
                .map_err(|e| e.to_string())?;
            return Ok(proto::UnlinkFolderResult {
                project,
                removed: if removed.is_empty() {
                    None
                } else {
                    Some(removed)
                },
            });
        }
        Err("external folder linking not supported for this backend".into())
    }

    #[allow(unused_variables)]
    fn storage_list_linked_folders(
        &self,
        project: Option<&ProjectId>,
    ) -> Result<Vec<proto::LinkedFolderDescriptor>, String> {
        let storage = self.storage.as_ref();
        #[cfg(feature = "backend-local")]
        if let Some(local) = storage.as_any().downcast_ref::<LocalStorage>() {
            let infos = local
                .list_external_folders(project)
                .map_err(|e| e.to_string())?;
            let converted = infos
                .into_iter()
                .map(|info| Self::link_descriptor_from_info(&info))
                .collect();
            return Ok(converted);
        }
        Err("external folder linking not supported for this backend".into())
    }

    #[allow(unused_variables)]
    fn storage_rescan_external(
        &self,
        project: &ProjectId,
        paths: Option<&[String]>,
    ) -> Result<Vec<serde_json::Value>, String> {
        let storage = self.storage.as_ref();
        #[cfg(feature = "backend-local")]
        if let Some(local) = storage.as_any().downcast_ref::<LocalStorage>() {
            let reports = local
                .rescan_external_folders(project, paths)
                .map_err(|e| e.to_string())?;
            let converted = reports
                .into_iter()
                .map(|report| serde_json::to_value(report).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(converted);
        }
        let _ = (&storage, &project, &paths);
        Err("external folder linking not supported for this backend".into())
    }

    #[allow(unused_variables)]
    fn storage_list_directory(
        &self,
        project: &ProjectId,
        path: &str,
    ) -> Result<Vec<proto::DirectoryEntry>, String> {
        let storage = self.storage.as_ref();
        #[cfg(feature = "backend-local")]
        if let Some(local) = storage.as_any().downcast_ref::<LocalStorage>() {
            let entries = local
                .list_directory(project, path)
                .map_err(|e| e.to_string())?;
            let mut converted = Vec::new();
            for entry in entries {
                converted.push(proto::DirectoryEntry {
                    name: entry.name,
                    path: entry.path,
                    kind: if entry.is_dir { "directory" } else { "file" }.into(),
                });
            }
            return Ok(converted);
        }
        #[cfg(feature = "backend-github")]
        if let Some(github) = storage.as_any().downcast_ref::<GithubStorage>() {
            let entries = github
                .list_directory(project, path)
                .map_err(|e| e.to_string())?;
            let mut converted = Vec::with_capacity(entries.len());
            for entry in entries {
                converted.push(proto::DirectoryEntry {
                    name: entry.name,
                    path: entry.path,
                    kind: if entry.is_dir { "directory" } else { "file" }.into(),
                });
            }
            return Ok(converted);
        }
        #[cfg(any(feature = "backend-ephemeral", test))]
        if let Some(ephemeral) = storage.as_any().downcast_ref::<EphemeralStorage>() {
            if !path.is_empty() {
                return Ok(Vec::new());
            }
            let entries = ephemeral.list_directory(project);
            let converted = entries
                .into_iter()
                .map(|id| proto::DirectoryEntry {
                    name: id.clone(),
                    path: id,
                    kind: "file".into(),
                })
                .collect();
            return Ok(converted);
        }
        Err("list_directory not supported for this backend".into())
    }

    fn storage_sync_status(&self, project: &ProjectId) -> proto::SyncStatusResult {
        #[cfg(feature = "backend-github")]
        if let Some(github) = self
            .storage
            .as_ref()
            .as_any()
            .downcast_ref::<GithubStorage>()
        {
            let state = github.sync_state();
            let since_last_commit_ms = state.since_last_commit.map(|d| d.as_millis() as u64);
            let details = json!({
                "deviceBranch": state.device_branch,
                "commitBatchMs": state.commit_batch_ms,
                "dirty": state.dirty,
                "sinceLastCommitMs": since_last_commit_ms,
            });
            return proto::SyncStatusResult {
                project: project.clone(),
                state: if state.dirty {
                    "pending_commit".into()
                } else {
                    "idle".into()
                },
                details: Some(details),
            };
        }
        proto::SyncStatusResult {
            project: project.clone(),
            state: "idle".into(),
            details: None,
        }
    }

    async fn handle_resource_read(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ResourceReadParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        // expect mem://<id>
        let raw = params
            .uri
            .strip_prefix("mem://")
            .unwrap_or(&params.uri)
            .to_string();
        let (project, id) = if let Some(explicit) = params.project.as_deref() {
            let proj = sanitize_project_id(explicit);
            let id_part = raw
                .split_once('/')
                .map(|(_, rest)| rest.to_string())
                .unwrap_or_else(|| raw.clone());
            (proj, id_part)
        } else {
            match raw.split_once('/') {
                Some((proj, rest)) if !rest.is_empty() => {
                    (sanitize_project_id(proj), rest.to_string())
                }
                _ => (self.default_project(), raw.clone()),
            }
        };
        debug!(uri = %params.uri, project = %project, resolved_id = %id, "resource.read requested");
        let storage = Arc::clone(&self.storage);
        let project_for_read = project.clone();
        let res = tokio::task::spawn_blocking(move || storage.get(&project_for_read, &id)).await;
        match res {
            Ok(Ok(Some(mem))) => {
                debug!(memory_id = %mem.id, project = %project, "resource.read found memory");
                let text = match serde_json::to_string(&mem) {
                    Ok(body) => body,
                    Err(e) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
                };
                let contents = proto::ResourceContents {
                    uri: Some(format!("mem://{}/{}", project, mem.id)),
                    mime_type: Some("application/json".into()),
                    text: Some(text),
                    metadata: None,
                };
                let result = proto::ResourceReadResult {
                    contents: vec![contents],
                };
                let result_json = match serde_json::to_value(&result) {
                    Ok(value) => value,
                    Err(e) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
                };
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: idv,
                    result: Some(result_json),
                    error: None,
                }
            }
            Ok(Ok(None)) => {
                debug!(uri = %params.uri, "resource.read not found");
                mcp_error_response(idv, "E_NOT_FOUND", "not found")
            }
            Ok(Err(e)) => mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
            Err(join_err) => mcp_error_response(idv, "E_STORAGE_IO", &join_err.to_string()),
        }
    }

    async fn handle_sync(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::SyncParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let dir = params
            .direction
            .clone()
            .unwrap_or_else(|| "both".to_string())
            .to_lowercase();
        let remote_param = params.remote.clone();
        let branch_param = params.branch.clone();
        let paths_param = params.paths.clone();
        #[cfg(not(feature = "backend-github"))]
        let _ = (&remote_param, &branch_param);
        let project = self.resolve_project_param(params.project.as_deref());
        debug!(direction = %dir, has_remote = remote_param.is_some(), has_branch = branch_param.is_some(), project = %project, "sync requested");

        // Run sync in a blocking task, attempting backend-specific behavior (GitHub)
        let storage_arc = Arc::clone(&self.storage);
        let dir_for_spawn = dir.clone();
        #[cfg(not(feature = "backend-github"))]
        let _ = (&storage_arc, &dir_for_spawn);
        if dir == "external" {
            debug!(project = %project, "external sync requested");
            let effective_paths = paths_param.or_else(|| remote_param.map(|p| vec![p]));
            match self.storage_rescan_external(&project, effective_paths.as_deref()) {
                Ok(reports) => {
                    return JsonRpcResponse {
                        jsonrpc: "2.0",
                        id: idv,
                        result: Some(json!({
                            "ok": true,
                            "direction": dir,
                            "reports": reports
                        })),
                        error: None,
                    };
                }
                Err(err) => {
                    return mcp_error_response(idv, "E_STORAGE_IO", &err);
                }
            }
        }

        let res = tokio::task::spawn_blocking(move || {
            #[cfg(feature = "backend-github")]
            {
                let dir = dir_for_spawn;
                if let Some(gh) = (&*storage_arc as &dyn Any)
                    .downcast_ref::<mcp_gitmem_storage_github::GithubStorage>()
                {
                    let remote = remote_param
                        .or_else(|| std::env::var("GITMEM_REMOTE_NAME").ok())
                        .or_else(|| std::env::var("GITMEM_REMOTE").ok())
                        .unwrap_or_else(|| "origin".to_string());
                    let mut branch: Option<String> =
                        branch_param.and_then(|b| if b.trim().is_empty() { None } else { Some(b) });
                    if branch.is_none() {
                        if let Ok(env_branch) = std::env::var("GITMEM_DEVICE_BRANCH") {
                            if !env_branch.trim().is_empty() {
                                branch = Some(env_branch);
                            }
                        }
                    }
                    if let Some(ref branch_name) = branch {
                        gh.configure_device_branch(branch_name)
                            .map_err(|e| e.to_string())?;
                    }
                    let branch_arg = branch.as_deref();
                    if dir == "pull" || dir == "both" {
                        gh.pull(&remote, branch_arg).map_err(|e| e.to_string())?;
                    }
                    if dir == "push" || dir == "both" {
                        gh.push(&remote, branch_arg).map_err(|e| e.to_string())?;
                    }
                    return Ok(()) as Result<(), String>;
                }
            }
            Err("sync not supported for this backend".to_string())
        })
        .await;

        match res {
            Ok(Ok(())) => {
                debug!(direction = %dir, project = %project, "sync completed");
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: idv,
                    result: Some(json!({"ok": true, "direction": dir})),
                    error: None,
                }
            }
            Ok(Err(e)) => mcp_error_response(idv, "E_STORAGE_IO", &e),
            Err(e) => mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
        }
    }

    #[cfg(feature = "backend-local")]
    fn spawn_link_poller(&self) -> Option<Arc<CancellationToken>> {
        if (&*self.storage as &dyn Any)
            .downcast_ref::<LocalStorage>()
            .is_none()
        {
            return None;
        }
        let storage_arc = Arc::clone(&self.storage);
        let token = Arc::new(CancellationToken::new());
        let poll_token = token.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(5));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = poll_token.cancelled() => break,
                    _ = ticker.tick() => {
                        let storage_ref = &*storage_arc;
                        let Some(local) = (storage_ref as &dyn Any).downcast_ref::<LocalStorage>() else {
                            break;
                        };
                        let Ok(links) = local.list_external_folders(None) else {
                            continue;
                        };
                        if links.is_empty() {
                            continue;
                        }
                        let max_concurrent = local.max_concurrent().max(1);
                        let now = Utc::now();
                        let mut due_links: Vec<(DateTime<Utc>, LinkedFolderInfo)> = Vec::new();
                        for link in links {
                            let interval_ms = link.watch.poll_interval_ms().max(1);
                            let jitter = Self::jitter_offset_ms(&link.link_id, interval_ms, link.watch.jitter_pct());
                            let total_ms = (interval_ms as i64 + jitter).max(1_000);
                            let next_due = link
                                .last_scan
                                .as_ref()
                                .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                                .map(|dt| dt.with_timezone(&Utc) + chrono::Duration::milliseconds(total_ms))
                                .unwrap_or(now);
                            if next_due <= now {
                                due_links.push((next_due, link));
                            }
                        }
                        if due_links.is_empty() {
                            continue;
                        }
                        due_links.sort_by_key(|(due, _)| *due);
                        for (_, link) in due_links.into_iter().take(max_concurrent) {
                            let storage_clone = Arc::clone(&storage_arc);
                            let project = link.project.clone();
                            let link_id = link.link_id.clone();
                            let path = link.resolved_path.clone();
                            tokio::task::spawn_blocking(move || {
                                if let Some(local) = (&*storage_clone as &dyn Any).downcast_ref::<LocalStorage>() {
                                    let filters = vec![path];
                                    if let Err(err) = local.rescan_external_folders(&project, Some(filters.as_slice())) {
                                        warn!(project = %project, link = %link_id, error = %err, "linked folder poller rescan failed");
                                    }
                                }
                            });
                        }
                    }
                }
            }
        });
        Some(token)
    }

    #[cfg(not(feature = "backend-local"))]
    #[allow(dead_code)]
    fn spawn_link_poller(&self) -> Option<Arc<CancellationToken>> {
        None
    }

    async fn handle_import_basic(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let idv = req.id.clone();
        let params: proto::ImportBasicParams = match parse_params(req.params) {
            Ok(p) => p,
            Err(e) => return invalid_params(idv, e),
        };
        let dry_run = params.dry_run.unwrap_or(false);
        let project = self.resolve_project_param(params.project.as_deref());
        debug!(
            path = %params.path,
            project = %project,
            dry_run,
            map_types = params.map_types.as_ref().map(|m| m.len()).unwrap_or(0),
            "import_basic requested"
        );
        // Load records via compat
        let mems = match mcp_gitmem_compat::import_basic_from_path(&params.path) {
            Ok(v) => v,
            Err(e) => return mcp_error_response(idv, "E_STORAGE_IO", &e.to_string()),
        };
        // Optional type remapping
        let mut mems = mems;
        if let Some(map) = params.map_types.as_ref() {
            mcp_gitmem_compat::remap_types(&mut mems, map);
        }
        // dedupe within input by id
        use std::collections::HashSet;
        let total_input = mems.len();
        let mut seen = HashSet::new();
        mems.retain(|m| seen.insert(m.id.clone()));
        let deduped = total_input.saturating_sub(mems.len());
        debug!(total_input, deduped, dry_run, "import_basic after dedupe");
        let mut imported: u64 = 0;
        let mut errors: u64 = 0;
        let mut skipped_existing: u64 = 0;
        for m in mems.iter() {
            if dry_run {
                imported += 1;
                continue;
            }
            // check if exists
            let storage = Arc::clone(&self.storage);
            let idc = m.id.clone();
            let project_for_check = project.clone();
            let exists =
                match tokio::task::spawn_blocking(move || storage.get(&project_for_check, &idc))
                    .await
                {
                    Ok(Ok(Some(_))) => true,
                    Ok(Ok(None)) => false,
                    Ok(Err(_)) => {
                        errors += 1;
                        continue;
                    }
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };
            if exists {
                skipped_existing += 1;
                continue;
            }
            // save and index
            let storage = Arc::clone(&self.storage);
            let mut m_save = m.clone();
            ensure_project_tag(&mut m_save, &project);
            let project_for_save = project.clone();
            let mem_for_save = m_save.clone();
            let sres =
                tokio::task::spawn_blocking(move || storage.save(&project_for_save, &mem_for_save))
                    .await;
            if sres.is_err() || sres.unwrap().is_err() {
                errors += 1;
                continue;
            }
            // Queue index update asynchronously
            self.queue_index_update(project.clone(), m_save);
            imported += 1;
        }
        JsonRpcResponse {
            jsonrpc: "2.0",
            id: idv,
            result: Some(json!({
                "total": total_input as u64,
                "deduped": deduped as u64,
                "skipped_existing": skipped_existing,
                "imported": imported,
                "errors": errors
            })),
            error: None,
        }
    }
}

fn parse_params<T: for<'de> Deserialize<'de>>(v: Option<serde_json::Value>) -> Result<T, String> {
    let value = match v {
        None | Some(serde_json::Value::Null) => json!({}),
        Some(serde_json::Value::Array(items)) if items.is_empty() => json!({}),
        Some(other) => other,
    };
    serde_json::from_value(value).map_err(|e| e.to_string())
}

fn coerce_typed_argument_object(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<serde_json::Value>, String> {
    let kind_value = match map.get("type") {
        Some(value) => value,
        None => return Ok(None),
    };
    let kind = match kind_value.as_str() {
        Some(s) => s,
        None => {
            return Err(format!(
                "tool argument `type` must be a string, got {}",
                kind_value
            ))
        }
    };
    let normalized_kind = kind
        .chars()
        .map(|c| match c {
            'A'..='Z' => c.to_ascii_lowercase(),
            '-' | ' ' => '_',
            other => other,
        })
        .collect::<String>();
    match normalized_kind.as_str() {
        "input_json" | "json" => map
            .get("json")
            .or_else(|| map.get("object"))
            .cloned()
            .ok_or_else(|| format!("{kind} argument missing `json` payload"))
            .map(Some),
        "input_structured" | "structured" | "input_object" | "object" | "spec" | "input_spec" => {
            let value = map
                .get("structured")
                .or_else(|| map.get("json"))
                .or_else(|| map.get("object"))
                .or_else(|| map.get("spec"))
                .cloned()
                .ok_or_else(|| format!("{kind} argument missing structured payload"))?;
            let normalized = match value {
                serde_json::Value::Object(_) => value,
                serde_json::Value::Null => json!({}),
                serde_json::Value::String(s) => {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        json!({})
                    } else if let Ok(serde_json::Value::Object(obj)) =
                        serde_json::from_str::<serde_json::Value>(trimmed)
                    {
                        serde_json::Value::Object(obj)
                    } else {
                        json!({ "query": trimmed })
                    }
                }
                other => json!({ "query": other.to_string() }),
            };
            Ok(Some(normalized))
        }
        "input_text" | "text" | "message" | "string" => {
            let text_value = map
                .get("text")
                .or_else(|| map.get("value"))
                .ok_or_else(|| format!("{kind} argument missing `text` payload"))?;
            let text = extract_text(text_value)
                .ok_or_else(|| format!("{kind} argument `text` must be a string"))?;
            if text.is_empty() {
                return Ok(Some(json!({})));
            }
            if let Ok(serde_json::Value::Object(obj)) =
                serde_json::from_str::<serde_json::Value>(&text)
            {
                return Ok(Some(serde_json::Value::Object(obj)));
            }
            Ok(Some(json!({ "query": text })))
        }
        _ => {
            if let Some(value) = map.get("json").or_else(|| map.get("object")).cloned() {
                return Ok(Some(value));
            }
            if let Some(value) = map.get("structured").cloned() {
                let normalized = match value {
                    serde_json::Value::Object(_) => value,
                    serde_json::Value::Null => json!({}),
                    serde_json::Value::String(s) => {
                        let trimmed = s.trim();
                        if trimmed.is_empty() {
                            json!({})
                        } else if let Ok(serde_json::Value::Object(obj)) =
                            serde_json::from_str::<serde_json::Value>(trimmed)
                        {
                            serde_json::Value::Object(obj)
                        } else {
                            json!({ "query": trimmed })
                        }
                    }
                    other => json!({ "query": other.to_string() }),
                };
                return Ok(Some(normalized));
            }
            if let Some(text_value) = map.get("text").or_else(|| map.get("value")) {
                if let Some(text) = extract_text(text_value) {
                    if text.is_empty() {
                        return Ok(Some(json!({})));
                    }
                    if let Ok(serde_json::Value::Object(obj)) =
                        serde_json::from_str::<serde_json::Value>(&text)
                    {
                        return Ok(Some(serde_json::Value::Object(obj)));
                    }
                    return Ok(Some(json!({ "query": text })));
                }
            }
            Ok(None)
        }
    }
}

fn extract_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
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
                if let Some(seg) = extract_text(item) {
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
            for key in ["text", "value", "string", "content", "message"] {
                if let Some(inner) = map.get(key) {
                    if let Some(result) = extract_text(inner) {
                        if !result.is_empty() {
                            return Some(result);
                        }
                    }
                }
            }
            if let Some(parts) = map.get("parts").and_then(|v| v.as_array()) {
                let mut segments = Vec::new();
                for part in parts {
                    if let Some(seg) = extract_text(part) {
                        if !seg.is_empty() {
                            segments.push(seg);
                        }
                    }
                }
                if !segments.is_empty() {
                    return Some(segments.join(" "));
                }
            }
            None
        }
        other => {
            let text = other.to_string();
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
    }
}

fn normalize_tool_arguments(arguments: serde_json::Value) -> Result<serde_json::Value, String> {
    match arguments {
        serde_json::Value::Null => Ok(json!({})),
        serde_json::Value::Object(map) => {
            if let Some(value) = coerce_typed_argument_object(&map)? {
                return Ok(value);
            }
            Ok(serde_json::Value::Object(map))
        }
        serde_json::Value::Array(items) => {
            if items.is_empty() {
                return Ok(json!({}));
            }
            for item in &items {
                if let serde_json::Value::Object(map) = item {
                    if let Some(value) = coerce_typed_argument_object(map)? {
                        return Ok(value);
                    }
                }
            }
            Err("unsupported tool argument payload".into())
        }
        other => Err(format!("unsupported arguments type: {other}")),
    }
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({"ok": true}))
}

fn internal_error(id: Option<serde_json::Value>, msg: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError {
            code: -32603,
            message: "Internal error".into(),
            data: Some(json!({"code": "E_INTERNAL", "message": msg})),
        }),
    }
}

fn invalid_params(id: Option<serde_json::Value>, msg: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError {
            code: -32602,
            message: "Invalid params".into(),
            data: Some(json!({"code":"E_VALIDATION","message": msg})),
        }),
    }
}

fn mcp_error_response(id: Option<serde_json::Value>, code: &str, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError {
            code: -32000,
            message: message.to_string(),
            data: Some(json!({"code": code})),
        }),
    }
}

fn build_tool_definitions() -> Result<Vec<proto::ToolDefinition>, ServerError> {
    let mut tools = Vec::new();
    push_tool_definition(
        &mut tools,
        proto::TOOL_MEMORY_SAVE,
        "Create a new memory record.",
        schema_for!(proto::SaveParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_MEMORY_GET,
        "Get a memory by id.",
        schema_for!(proto::GetParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_MEMORY_SEARCH,
        "Search memories.",
        schema_for!(proto::SearchParamsWire),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_MEMORY_UPDATE,
        "Patch a memory.",
        schema_for!(proto::UpdateParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_MEMORY_DELETE,
        "Delete a memory.",
        schema_for!(proto::DeleteParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_MEMORY_IMPORT_BASIC,
        "Import from basic memory JSON or JSONL.",
        schema_for!(proto::ImportBasicParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_MEMORY_SYNC,
        "Sync with storage backend.",
        schema_for!(proto::SyncParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_LIST_MEMORY_PROJECTS,
        "List available memory projects.",
        schema_for!(proto::ListMemoryProjectsParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_CREATE_MEMORY_PROJECT,
        "Create a new memory project.",
        schema_for!(proto::CreateMemoryProjectParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_DELETE_MEMORY_PROJECT,
        "Delete a memory project.",
        schema_for!(proto::DeleteProjectParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_LIST_DIRECTORY,
        "List directory contents for a project.",
        schema_for!(proto::ListDirectoryParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_SYNC_STATUS,
        "Retrieve sync status for a project.",
        schema_for!(proto::SyncStatusParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_PROJECT_LINK_FOLDER,
        "Link an external folder to a project.",
        schema_for!(proto::LinkFolderParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_PROJECT_UNLINK_FOLDER,
        "Remove a linked external folder from a project.",
        schema_for!(proto::UnlinkFolderParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_PROJECT_LIST_LINKS,
        "List linked external folders.",
        schema_for!(proto::ListLinkedFoldersParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_WRITE_NOTE,
        "Write a note to the memory store.",
        schema_for!(proto::WriteNoteParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_READ_NOTE,
        "Read a note by id.",
        schema_for!(proto::ReadNoteParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_VIEW_NOTE,
        "View a note by id.",
        schema_for!(proto::ReadNoteParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_EDIT_NOTE,
        "Edit an existing note.",
        schema_for!(proto::EditNoteParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_DELETE_NOTE,
        "Delete a note.",
        schema_for!(proto::DeleteNoteParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_MOVE_NOTE,
        "Move a note between projects.",
        schema_for!(proto::MoveNoteParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_SEARCH_NOTES,
        "Search notes.",
        schema_for!(proto::SearchNotesParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_RECENT_ACTIVITY,
        "List recent notes.",
        schema_for!(proto::RecentActivityParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_BUILD_CONTEXT,
        "Build context from notes.",
        schema_for!(proto::BuildContextParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_READ_CONTENT,
        "Read note content.",
        schema_for!(proto::ReadContentParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_SEARCH,
        "Search notes and return formatted snippets.",
        schema_for!(proto::SearchPromptParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_FETCH,
        "Fetch the full contents of a note for display.",
        schema_for!(proto::FetchParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_PROJECT_INFO,
        "Summarize project statistics and recent notes.",
        schema_for!(proto::ProjectInfoParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_CANVAS,
        "Create a canvas artifact stored as a memory.",
        schema_for!(proto::CanvasParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_AI_ASSISTANT_GUIDE,
        "Return instructions for working with the memory server.",
        schema_for!(proto::AiAssistantGuideParams),
    )?;
    push_tool_definition(
        &mut tools,
        proto::TOOL_CONTINUE_CONVERSATION,
        "Provide contextual notes to continue a conversation.",
        schema_for!(proto::ContinueConversationParams),
    )?;
    #[cfg(feature = "encryption")]
    {
        push_tool_definition(
            &mut tools,
            proto::TOOL_MEMORY_ENCRYPT,
            "Encrypt a memory using configured recipients.",
            schema_for!(proto::EncryptParams),
        )?;
        push_tool_definition(
            &mut tools,
            proto::TOOL_MEMORY_DECRYPT,
            "Decrypt a memory with the provided identity.",
            schema_for!(proto::DecryptParams),
        )?;
    }
    Ok(tools)
}

fn push_tool_definition(
    tools: &mut Vec<proto::ToolDefinition>,
    name: &str,
    description: &str,
    schema: RootSchema,
) -> Result<(), ServerError> {
    let schema_value = root_schema_to_value(schema)?;
    let exported_name = proto::exported_tool_name(name);
    tools.push(proto::ToolDefinition {
        name: exported_name,
        description: Some(description.to_string()),
        input_schema: schema_value,
    });
    Ok(())
}

fn root_schema_to_value(schema: RootSchema) -> Result<serde_json::Value, ServerError> {
    serde_json::to_value(schema).map_err(|e| ServerError::Parse(e.to_string()))
}

struct RmcpAdapter<S, I> {
    inner: Server<S, I>,
}

impl<S, I> Clone for RmcpAdapter<S, I>
where
    S: Storage + Send + Sync + 'static,
    I: Index + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, I> RmcpAdapter<S, I>
where
    S: Storage + Send + Sync + 'static,
    I: Index + Send + Sync + 'static,
{
    fn new(inner: Server<S, I>) -> Self {
        Self { inner }
    }

    fn metadata() -> serde_json::Map<String, serde_json::Value> {
        let mut root = serde_json::Map::new();
        root.insert(
            "memory".into(),
            json!({
                "version": 1,
                "encryption": cfg!(feature = "encryption"),
                "search": "bm25",
                "ttl": true
            }),
        );
        let storage_metadata = json!({
            "github": {
                "enabled": cfg!(feature = "backend-github")
            },
            "local": {
                "enabled": cfg!(feature = "backend-local"),
                "linked_folders": cfg!(feature = "backend-local")
            }
        });
        root.insert("storage".into(), storage_metadata);
        root.insert(
            "transport".into(),
            json!({
                "stdio": true,
                "ws": cfg!(feature = "transport-ws"),
                "http": true
            }),
        );
        root.insert(
            "tools".into(),
            json!({
                "memory.save": true,
                "memory.get": true,
                "memory.update": true,
                "memory.delete": true,
                "memory.search": true,
                "memory.import.basic": true,
                "memory.sync": cfg!(feature = "backend-github"),
                "memory.encrypt": cfg!(feature = "encryption"),
                "memory.decrypt": cfg!(feature = "encryption"),
                "resources.list": true,
                "resources.read": true,
                "resource.list": true,
                "resource.read": true,
                "project.link_folder": cfg!(feature = "backend-local"),
                "project.unlink_folder": cfg!(feature = "backend-local"),
                "project.list_links": cfg!(feature = "backend-local")
            }),
        );
        root
    }
}

impl<S, I> ServerHandler for RmcpAdapter<S, I>
where
    S: Storage + Send + Sync + 'static,
    I: Index + Send + Sync + 'static,
{
    fn get_info(&self) -> ServerInfo {
        let mut capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .build();
        let mut experimental = capabilities.experimental.unwrap_or_else(BTreeMap::new);
        experimental.insert("gitmem".to_string(), Self::metadata());
        capabilities.experimental = Some(experimental);

        ServerInfo {
            server_info: Implementation {
                name: "gitmem".to_string(),
                title: Some("GitMem MCP server".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                icons: None,
                website_url: None,
            },
            capabilities,
            ..ServerInfo::default()
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(0)),
            method: proto::METHOD_TOOLS_LIST.into(),
            params: None,
        };
        let resp = self.inner.handle_tools_list(req).await;
        json_rpc_result_to::<ListToolsResult>(resp)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let CallToolRequestParam { name, arguments } = request;
        let arguments_value = arguments
            .map(serde_json::Value::Object)
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        let params = proto::CallToolParams {
            tool_name: name.to_string(),
            arguments: arguments_value,
        };
        let params_value =
            serde_json::to_value(params).map_err(|e| mcp_internal_error(e.to_string()))?;
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(0)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(params_value),
        };
        let resp = self.inner.handle_tools_call(req).await;
        json_rpc_result_to::<CallToolResult>(resp)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let params = proto::ResourceListParams {
            limit: None,
            cursor: None,
            project: None,
        };
        let params_value =
            serde_json::to_value(params).map_err(|e| mcp_internal_error(e.to_string()))?;
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(0)),
            method: proto::METHOD_RESOURCES_LIST.into(),
            params: Some(params_value),
        };
        let resp = self.inner.handle_resource_list(req).await;
        json_rpc_result_to::<ListResourcesResult>(resp)
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let ReadResourceRequestParam { uri } = request;
        let params = proto::ResourceReadParams { uri, project: None };
        let params_value =
            serde_json::to_value(params).map_err(|e| mcp_internal_error(e.to_string()))?;
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(0)),
            method: proto::METHOD_RESOURCES_READ.into(),
            params: Some(params_value),
        };
        let resp = self.inner.handle_resource_read(req).await;
        json_rpc_result_to::<ReadResourceResult>(resp)
    }
}

fn json_rpc_result_to<T>(resp: JsonRpcResponse) -> Result<T, McpError>
where
    T: DeserializeOwned,
{
    if let Some(err) = resp.error {
        return Err(jsonrpc_error_to_mcp(err));
    }
    let value = resp.result.unwrap_or(serde_json::Value::Null);
    serde_json::from_value(value).map_err(|e| mcp_internal_error(e.to_string()))
}

fn jsonrpc_error_to_mcp(err: JsonRpcError) -> McpError {
    McpError::new(ErrorCode(err.code as i32), err.message, err.data)
}

fn mcp_internal_error(message: impl Into<String>) -> McpError {
    let msg = message.into();
    McpError::new(
        ErrorCode::INTERNAL_ERROR,
        msg.clone(),
        Some(json!({ "code": "E_INTERNAL", "message": msg })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::fs;

    #[cfg(feature = "encryption")]
    use age::x25519;
    use mcp_gitmem_core::project::DEFAULT_PROJECT_ID;
    #[cfg(feature = "encryption")]
    use mcp_gitmem_core::traits::SearchResults;
    #[cfg(feature = "encryption")]
    use mcp_gitmem_crypto::{CryptoConfig as TestCryptoConfig, CryptoFacade as TestCryptoFacade};
    use mcp_gitmem_index_tantivy::TantivyIndex;
    use mcp_gitmem_storage_ephemeral::EphemeralStorage;
    #[cfg(feature = "backend-github")]
    use mcp_gitmem_storage_github::GithubStorage;
    #[cfg(feature = "backend-local")]
    use mcp_gitmem_storage_local::LocalWatchConfig;
    #[cfg(feature = "encryption")]
    use secrecy::{ExposeSecret, SecretString};
    #[cfg(feature = "encryption")]
    use std::convert::Infallible;
    #[cfg(feature = "encryption")]
    use std::sync::{Arc as StdArc, Mutex};
    use tempfile::tempdir;

    fn call_result_json(value: &serde_json::Value) -> serde_json::Value {
        if let Some(structured) = value.get("structuredContent") {
            return structured.clone();
        }
        if let Some(content) = value.get("content").and_then(|c| c.as_array()) {
            if let Some(entry) = content.first() {
                if let Some(text) = entry.get("text").and_then(|t| t.as_str()) {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text) {
                        return parsed;
                    }
                }
            }
        }
        serde_json::Value::Null
    }

    #[cfg(feature = "encryption")]
    #[derive(Clone, Default)]
    struct CapturingIndex {
        docs: StdArc<Mutex<Vec<(ProjectId, Memory)>>>,
    }

    #[cfg(feature = "encryption")]
    impl CapturingIndex {
        fn last(&self) -> Option<(ProjectId, Memory)> {
            self.docs.lock().unwrap().last().cloned()
        }
    }

    #[cfg(feature = "encryption")]
    impl Index for CapturingIndex {
        type Error = Infallible;

        fn update(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error> {
            self.docs
                .lock()
                .unwrap()
                .push((project.clone(), memory.clone()));
            Ok(())
        }

        fn delete(&self, _project: &ProjectId, _id: &str) -> Result<(), Self::Error> {
            Ok(())
        }

        fn search(
            &self,
            _project: &ProjectId,
            _params: &SearchParams,
        ) -> Result<SearchResults, Self::Error> {
            Ok(SearchResults {
                items: Vec::new(),
                total: 0,
            })
        }
    }

    #[test]
    fn normalize_tool_arguments_accepts_input_json_object() {
        let args = json!({
            "type": "input_json",
            "json": { "content": "hello", "type": "note" }
        });
        let normalized = normalize_tool_arguments(args).expect("expected normalization");
        assert_eq!(normalized, json!({ "content": "hello", "type": "note" }));
    }

    #[test]
    fn normalize_tool_arguments_supports_input_text_object() {
        let args = json!({
            "type": "input_text",
            "text": [
                { "type": "text", "text": " hello" },
                { "type": "text", "text": "world " }
            ]
        });
        let normalized = normalize_tool_arguments(args).expect("expected normalization");
        assert_eq!(normalized, json!({ "query": "hello world" }));
    }

    #[test]
    fn normalize_tool_arguments_supports_text_alias() {
        let args = json!({
            "type": "text",
            "text": { "type": "text", "text": "foo bar" }
        });
        let normalized = normalize_tool_arguments(args).expect("expected normalization");
        assert_eq!(normalized, json!({ "query": "foo bar" }));
    }

    #[test]
    fn normalize_tool_arguments_supports_json_alias() {
        let args = json!({
            "type": "json",
            "json": { "content": "hi", "title": "there" }
        });
        let normalized = normalize_tool_arguments(args).expect("expected normalization");
        assert_eq!(normalized, json!({ "content": "hi", "title": "there" }));
    }

    #[tokio::test]
    async fn notification_request_produces_no_id() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let server = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: None,
            method: proto::METHOD_TOOLS_LIST.to_string(),
            params: Some(json!({})),
        };
        let resp = server.handle_request(req).await;
        assert!(
            resp.id.is_none(),
            "notifications should not produce an id in the response"
        );
    }

    #[tokio::test]
    async fn save_and_get_round_trip() {
        let storage = EphemeralStorage::new();
        struct NoopIndex;
        impl Index for NoopIndex {
            type Error = std::io::Error;
            fn update(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _m: &Memory,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn delete(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &str,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn search(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &mcp_gitmem_core::traits::SearchParams,
            ) -> Result<mcp_gitmem_core::traits::SearchResults, Self::Error> {
                Ok(mcp_gitmem_core::traits::SearchResults {
                    items: vec![],
                    total: 0,
                })
            }
        }
        let srv = Server::new(storage, NoopIndex);

        // save
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({"content":"hello","title":"t","type":"note"})),
        };
        let resp = srv.handle_save(req).await;
        assert!(resp.error.is_none());
        let mem: Memory = serde_json::from_value(resp.result.unwrap()).unwrap();
        let id = mem.id.clone();

        // get
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(2)),
            method: proto::TOOL_MEMORY_GET.into(),
            params: Some(json!({"id": id})),
        };
        let resp = srv.handle_get(req).await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn save_with_invalid_type_returns_validation_error() {
        let storage = EphemeralStorage::new();
        struct NoopIndex;
        impl Index for NoopIndex {
            type Error = std::io::Error;
            fn update(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _m: &Memory,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn delete(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &str,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn search(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &mcp_gitmem_core::traits::SearchParams,
            ) -> Result<mcp_gitmem_core::traits::SearchResults, Self::Error> {
                Ok(mcp_gitmem_core::traits::SearchResults {
                    items: vec![],
                    total: 0,
                })
            }
        }
        let srv = Server::new(storage, NoopIndex);

        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({"content":"hello","title":"t","type":"unknown_kind"})),
        };
        let resp = srv.handle_save(req).await;
        assert!(resp.result.is_none());
        let err = resp.error.expect("expected error");
        assert_eq!(err.code, -32000);
        let data = err.data.unwrap();
        let code = data.get("code").unwrap().as_str().unwrap();
        assert_eq!(code, "E_VALIDATION");
    }

    #[tokio::test]
    async fn save_with_tags() {
        let storage = EphemeralStorage::new();
        struct NoopIndex;
        impl Index for NoopIndex {
            type Error = std::io::Error;
            fn update(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _m: &Memory,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn delete(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &str,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn search(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &mcp_gitmem_core::traits::SearchParams,
            ) -> Result<mcp_gitmem_core::traits::SearchResults, Self::Error> {
                Ok(mcp_gitmem_core::traits::SearchResults {
                    items: vec![],
                    total: 0,
                })
            }
        }
        let srv = Server::new(storage, NoopIndex);

        // save with explicit tags
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({
                "content": "test content",
                "title": "test title",
                "type": "note",
                "tags": ["tag1", "tag2", "custom-tag"]
            })),
        };
        let resp = srv.handle_save(req).await;
        assert!(resp.error.is_none(), "save should succeed");
        let mem: Memory = serde_json::from_value(resp.result.unwrap()).unwrap();
        
        // Verify tags were saved correctly
        // Should have the custom tags plus project:default
        assert!(mem.tags.contains(&"tag1".to_string()), "should have tag1");
        assert!(mem.tags.contains(&"tag2".to_string()), "should have tag2");
        assert!(mem.tags.contains(&"custom-tag".to_string()), "should have custom-tag");
        assert!(mem.tags.contains(&"project:default".to_string()), "should have project:default");
        assert_eq!(mem.tags.len(), 4, "should have exactly 4 tags");
    }

    #[tokio::test]
    async fn update_with_tags() {
        let storage = EphemeralStorage::new();
        struct NoopIndex;
        impl Index for NoopIndex {
            type Error = std::io::Error;
            fn update(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _m: &Memory,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn delete(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &str,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn search(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &mcp_gitmem_core::traits::SearchParams,
            ) -> Result<mcp_gitmem_core::traits::SearchResults, Self::Error> {
                Ok(mcp_gitmem_core::traits::SearchResults {
                    items: vec![],
                    total: 0,
                })
            }
        }
        let srv = Server::new(storage, NoopIndex);

        // Save initial memory
        let save_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({
                "content": "initial content",
                "title": "initial title",
                "type": "note",
                "tags": ["initial-tag"]
            })),
        };
        let save_resp = srv.handle_save(save_req).await;
        assert!(save_resp.error.is_none());
        let saved_mem: Memory = serde_json::from_value(save_resp.result.unwrap()).unwrap();
        let mem_id = saved_mem.id.clone();

        // Update with new tags
        let update_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(2)),
            method: proto::TOOL_MEMORY_UPDATE.into(),
            params: Some(json!({
                "id": mem_id,
                "patch": {
                    "tags": ["updated-tag1", "updated-tag2", "project:default"]
                }
            })),
        };
        let update_resp = srv.handle_update(update_req).await;
        assert!(update_resp.error.is_none(), "update should succeed");
        let updated_mem: Memory = serde_json::from_value(update_resp.result.unwrap()).unwrap();

        // Verify tags were updated correctly
        assert!(updated_mem.tags.contains(&"updated-tag1".to_string()), "should have updated-tag1");
        assert!(updated_mem.tags.contains(&"updated-tag2".to_string()), "should have updated-tag2");
        assert!(updated_mem.tags.contains(&"project:default".to_string()), "should have project:default");
        assert!(!updated_mem.tags.contains(&"initial-tag".to_string()), "should not have initial-tag");
        assert_eq!(updated_mem.tags.len(), 3, "should have exactly 3 tags");
    }

    #[tokio::test]
    async fn delete_then_get_returns_not_found() {
        let storage = EphemeralStorage::new();
        struct NoopIndex;
        impl Index for NoopIndex {
            type Error = std::io::Error;
            fn update(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _m: &Memory,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn delete(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &str,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn search(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &mcp_gitmem_core::traits::SearchParams,
            ) -> Result<mcp_gitmem_core::traits::SearchResults, Self::Error> {
                Ok(mcp_gitmem_core::traits::SearchResults {
                    items: vec![],
                    total: 0,
                })
            }
        }
        let srv = Server::new(storage, NoopIndex);

        // save first
        let save = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({"content":"bye","title":"t","type":"note"})),
        };
        let saved = srv.handle_save(save).await;
        let mem: Memory = serde_json::from_value(saved.result.unwrap()).unwrap();

        // delete
        let del = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(2)),
            method: proto::TOOL_MEMORY_DELETE.into(),
            params: Some(json!({"id": mem.id, "hard": true})),
        };
        let del_resp = srv.handle_delete(del).await;
        assert!(del_resp.error.is_none());
        assert!(del_resp
            .result
            .unwrap()
            .get("ok")
            .unwrap()
            .as_bool()
            .unwrap());
    }

    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn save_encrypts_when_configured() {
        let storage = EphemeralStorage::new();
        let index = CapturingIndex::default();
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let mut options = ServerOptions::default();
        options.encryption_recipients = vec![recipient.clone()];
        let srv = Server::new_with_options(storage, index.clone(), options);

        let save_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({
                "title": "secret",
                "content": "top secret body",
                "type": "note"
            })),
        };
        let resp = srv.handle_save(save_req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let stored: Memory = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert!(stored
            .encryption
            .as_ref()
            .map(|meta| meta.encrypted)
            .unwrap_or(false));
        assert_ne!(stored.content, "top secret body");

        let crypto = TestCryptoFacade::new(TestCryptoConfig {
            recipients: Vec::new(),
            enabled: true,
        });
        let secret_material = identity.to_string();
        let secret = SecretString::new(secret_material.expose_secret().to_owned());
        let decrypted = crypto.decrypt(&stored.content, &secret).unwrap();
        assert_eq!(decrypted, "top secret body");

        let index_doc = index.last().expect("captured index doc");
        assert_eq!(index_doc.0, DEFAULT_PROJECT_ID.to_string());
        assert!(index_doc.1.title.is_empty());
        assert!(index_doc.1.content.is_empty());

        let get_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(2)),
            method: proto::TOOL_MEMORY_GET.into(),
            params: Some(json!({"id": stored.id})),
        };
        let fetched = srv.handle_get(get_req).await;
        assert!(fetched.error.is_none(), "get failed: {:?}", fetched.error);
        let fetched_mem: Memory = serde_json::from_value(fetched.result.unwrap()).unwrap();
        assert_ne!(fetched_mem.content, "top secret body");
    }

    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn update_reencrypts_on_content_change() {
        let storage = EphemeralStorage::new();
        let index = CapturingIndex::default();
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let mut options = ServerOptions::default();
        options.encryption_recipients = vec![recipient.clone()];
        let srv = Server::new_with_options(storage, index.clone(), options);

        let save_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(10)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({
                "title": "draft",
                "content": "version one",
                "type": "note"
            })),
        };
        let saved = srv.handle_save(save_req).await;
        let mem: Memory = serde_json::from_value(saved.result.unwrap()).unwrap();
        let ciphertext_before = mem.content.clone();

        let update_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(11)),
            method: proto::TOOL_MEMORY_UPDATE.into(),
            params: Some(json!({
                "id": mem.id,
                "patch": {"content": "version two"}
            })),
        };
        let updated = srv.handle_update(update_req).await;
        assert!(
            updated.error.is_none(),
            "update failed: {:?}",
            updated.error
        );
        let updated_mem: Memory = serde_json::from_value(updated.result.unwrap()).unwrap();
        assert_ne!(updated_mem.content, ciphertext_before);
        let crypto = TestCryptoFacade::new(TestCryptoConfig {
            recipients: Vec::new(),
            enabled: true,
        });
        let secret_material = identity.to_string();
        let secret = SecretString::new(secret_material.expose_secret().to_owned());
        let decrypted = crypto.decrypt(&updated_mem.content, &secret).unwrap();
        assert_eq!(decrypted, "version two");

        let index_doc = index.last().expect("captured doc after update");
        assert!(index_doc.1.title.is_empty());
        assert!(index_doc.1.content.is_empty());
    }

    #[cfg(feature = "encryption")]
    #[tokio::test]
    async fn metadata_update_preserves_ciphertext() {
        let storage = EphemeralStorage::new();
        let index = CapturingIndex::default();
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let mut options = ServerOptions::default();
        options.encryption_recipients = vec![recipient.clone()];
        let srv = Server::new_with_options(storage, index.clone(), options);

        let save_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(20)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({
                "title": "prefs",
                "content": "likes cats",
                "type": "note",
                "tags": ["animals"]
            })),
        };
        let saved = srv.handle_save(save_req).await;
        let mem: Memory = serde_json::from_value(saved.result.unwrap()).unwrap();
        let ciphertext_before = mem.content.clone();

        let update_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(21)),
            method: proto::TOOL_MEMORY_UPDATE.into(),
            params: Some(json!({
                "id": mem.id,
                "patch": {"tags": ["animals", "pets"]}
            })),
        };
        let updated = srv.handle_update(update_req).await;
        assert!(
            updated.error.is_none(),
            "update failed: {:?}",
            updated.error
        );
        let updated_mem: Memory = serde_json::from_value(updated.result.unwrap()).unwrap();
        assert_eq!(ciphertext_before, updated_mem.content);
        assert!(updated_mem.tags.contains(&"pets".to_string()));

        let crypto = TestCryptoFacade::new(TestCryptoConfig {
            recipients: Vec::new(),
            enabled: true,
        });
        let secret_material = identity.to_string();
        let secret = SecretString::new(secret_material.expose_secret().to_owned());
        let decrypted = crypto.decrypt(&updated_mem.content, &secret).unwrap();
        assert_eq!(decrypted, "likes cats");

        let index_doc = index.last().expect("captured doc after metadata update");
        assert!(index_doc.1.title.is_empty());
        assert!(index_doc.1.content.is_empty());
    }

    #[tokio::test]
    async fn method_not_found() {
        let storage = EphemeralStorage::new();
        struct NoopIndex;
        impl Index for NoopIndex {
            type Error = std::io::Error;
            fn update(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _m: &Memory,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn delete(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &str,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
            fn search(
                &self,
                _: &mcp_gitmem_core::project::ProjectId,
                _: &mcp_gitmem_core::traits::SearchParams,
            ) -> Result<mcp_gitmem_core::traits::SearchResults, Self::Error> {
                Ok(mcp_gitmem_core::traits::SearchResults {
                    items: vec![],
                    total: 0,
                })
            }
        }
        let srv = Server::new(storage, NoopIndex);

        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(99)),
            method: "unknown.method".into(),
            params: None,
        };
        let resp = srv.handle_request(req).await;
        assert!(resp.result.is_none());
        let err = resp.error.expect("expected error");
        assert_eq!(err.code, -32601);
    }

    #[tokio::test]
    async fn update_changes_title_and_content() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        // save
        let save = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({"content":"hello","title":"old","type":"note"})),
        };
        let saved = srv.handle_save(save).await;
        let mem: Memory = serde_json::from_value(saved.result.unwrap()).unwrap();

        // update
        let upd = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(2)),
            method: proto::TOOL_MEMORY_UPDATE.into(),
            params: Some(json!({"id": mem.id, "patch": {"title":"new","content":"world"}})),
        };
        let resp = srv.handle_update(upd).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let updated: Memory = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(updated.title, "new");
        assert_eq!(updated.content, "world");
    }

    #[tokio::test]
    async fn search_returns_saved_items() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        // save
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(
                json!({"content":"hello world","title":"greet","type":"note","tags":["greet"]}),
            ),
        };
        let _resp = srv.handle_save(req).await;

        // search
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(2)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({"query":"hello"})),
        };
        let resp = srv.handle_search(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let v = resp.result.unwrap();
        let items = v.get("items").unwrap().as_array().unwrap();
        assert!(!items.is_empty());
    }

    #[tokio::test]
    async fn search_pagination_offset_and_limit() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let project = DEFAULT_PROJECT_ID.to_string();
        let mut ids = Vec::new();
        for i in 0..5 {
            let title = format!("doc{}", i);
            let m = Memory::new(&title, "alpha beta", "note");
            let id = m.id.clone();
            storage.save(&project, &m).unwrap();
            index.update(&project, &m).unwrap();
            ids.push(id);
        }
        let srv = Server::new(storage, index);
        // offset 1, limit 2
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(30)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({"query":"alpha","offset":1,"limit":2})),
        };
        let resp = srv.handle_search(req).await;
        assert!(resp.error.is_none());
        let v = resp.result.unwrap();
        let items = v.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn search_filters_by_type() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let m1 = Memory::new("t1", "alpha", "note");
        let m2 = Memory::new("t2", "beta", "fact");
        let project = DEFAULT_PROJECT_ID.to_string();
        storage.save(&project, &m1).unwrap();
        index.update(&project, &m1).unwrap();
        storage.save(&project, &m2).unwrap();
        index.update(&project, &m2).unwrap();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(20)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({"query":"","filters":{"type":["fact"]}})),
        };
        let resp = srv.handle_search(req).await;
        assert!(resp.error.is_none());
        let v = resp.result.unwrap();
        let items = v.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get("type").unwrap().as_str().unwrap(), "fact");
    }

    #[tokio::test]
    async fn search_filters_by_tags() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let mut m1 = Memory::new("t1", "alpha", "note");
        m1.tags = vec!["a".to_string()];
        let mut m2 = Memory::new("t2", "beta", "note");
        m2.tags = vec!["b".to_string()];
        let project = DEFAULT_PROJECT_ID.to_string();
        storage.save(&project, &m1).unwrap();
        index.update(&project, &m1).unwrap();
        storage.save(&project, &m2).unwrap();
        index.update(&project, &m2).unwrap();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(21)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({"query":"","filters":{"tags":["b"]}})),
        };
        let resp = srv.handle_search(req).await;
        assert!(resp.error.is_none());
        let v = resp.result.unwrap();
        let items = v.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 1);
        let tags = items[0].get("tags").unwrap().as_array().unwrap();
        assert!(tags.iter().any(|t| t.as_str().unwrap() == "b"));
    }

    #[tokio::test]
    async fn tools_call_handles_sanitized_input_text_arguments() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let memory = Memory::new("title", "hello world", "note");
        let expected_id = memory.id.clone();
        let project = DEFAULT_PROJECT_ID.to_string();
        storage.save(&project, &memory).unwrap();
        index.update(&project, &memory).unwrap();

        let server = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": "memory_search",
                "arguments": { "type": "input_text", "text": "hello" }
            })),
        };
        let resp = server.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        let items = structured
            .get("items")
            .and_then(|v| v.as_array())
            .expect("items array missing");
        assert!(
            items
                .iter()
                .any(|item| item.get("id").and_then(|v| v.as_str()) == Some(expected_id.as_str())),
            "expected memory id to be present in search results"
        );
    }

    #[tokio::test]
    async fn tools_call_handles_text_alias_arguments() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let memory = Memory::new("title", "hello world", "note");
        let expected_id = memory.id.clone();
        let project = DEFAULT_PROJECT_ID.to_string();
        storage.save(&project, &memory).unwrap();
        index.update(&project, &memory).unwrap();

        let server = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": "memory_search",
                "arguments": { "type": "text", "text": "hello" }
            })),
        };
        let resp = server.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        let items = structured
            .get("items")
            .and_then(|v| v.as_array())
            .expect("items array missing");
        assert!(
            items
                .iter()
                .any(|item| item.get("id").and_then(|v| v.as_str()) == Some(expected_id.as_str())),
            "expected memory id to be present in search results"
        );
    }

    #[tokio::test]
    async fn tools_call_handles_sanitized_input_json_arguments() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let server = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(42)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": "memory_save",
                "arguments": {
                    "type": "input_json",
                    "json": {
                        "title": "greeting",
                        "content": "world",
                        "type": "note"
                    }
                }
            })),
        };
        let resp = server.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        assert_eq!(structured.get("title").unwrap(), "greeting");
        assert_eq!(structured.get("content").unwrap(), "world");
        assert_eq!(structured.get("type").unwrap(), "note");
    }

    #[tokio::test]
    async fn tools_call_handles_json_alias_arguments() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let server = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(42)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": "memory_save",
                "arguments": {
                    "type": "json",
                    "json": {
                        "title": "greeting",
                        "content": "world",
                        "type": "note"
                    }
                }
            })),
        };
        let resp = server.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        assert_eq!(structured.get("title").unwrap(), "greeting");
        assert_eq!(structured.get("content").unwrap(), "world");
        assert_eq!(structured.get("type").unwrap(), "note");
    }

    #[tokio::test]
    async fn tools_call_search_returns_formatted_results() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        for title in ["alpha result", "beta entry"] {
            let req = JsonRpcRequest {
                jsonrpc: Some("2.0".into()),
                id: Some(json!(500)),
                method: proto::TOOL_WRITE_NOTE.into(),
                params: Some(json!({
                    "title": title,
                    "content": format!("{} note body with extra context", title),
                    "project": "alpha"
                })),
            };
            let _ = srv.handle_write_note(req).await;
        }

        let search_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(501)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::TOOL_SEARCH,
                "arguments": {
                    "query": "alpha",
                    "project": "alpha",
                    "limit": 3
                }
            })),
        };
        let resp = srv.handle_tools_call(search_req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        let results = structured
            .get("results")
            .and_then(|v| v.as_array())
            .expect("results array missing");
        assert!(!results.is_empty(), "expected at least one search result");
        let first = results.first().unwrap();
        assert!(
            first
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("alpha"),
            "expected search result title to mention query term"
        );
    }

    #[tokio::test]
    async fn tools_call_fetch_returns_full_note() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let write_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(510)),
            method: proto::TOOL_WRITE_NOTE.into(),
            params: Some(json!({
                "title": "fetch me",
                "content": "full note content",
                "project": "alpha"
            })),
        };
        let saved = srv.handle_write_note(write_req).await;
        let mem: Memory = serde_json::from_value(saved.result.unwrap()).unwrap();

        let fetch_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(511)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::TOOL_FETCH,
                "arguments": {
                    "id": mem.id,
                    "project": "alpha"
                }
            })),
        };
        let resp = srv.handle_tools_call(fetch_req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        assert_eq!(structured.get("title").unwrap(), "fetch me");
        assert_eq!(structured.get("content").unwrap(), "full note content");
        assert_eq!(structured.get("project").unwrap(), "alpha");
    }

    #[tokio::test]
    async fn tools_call_project_info_summarizes_recent_notes() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        for idx in 0..3 {
            let req = JsonRpcRequest {
                jsonrpc: Some("2.0".into()),
                id: Some(json!(520 + idx)),
                method: proto::TOOL_WRITE_NOTE.into(),
                params: Some(json!({
                    "title": format!("note-{idx}"),
                    "content": "body content",
                    "project": "alpha"
                })),
            };
            let _ = srv.handle_write_note(req).await;
        }

        let info_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(523)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::TOOL_PROJECT_INFO,
                "arguments": {
                    "project": "alpha",
                    "recent_limit": 2
                }
            })),
        };
        let resp = srv.handle_tools_call(info_req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        assert_eq!(structured.get("project").unwrap(), "alpha");
        let recent = structured
            .get("recentNotes")
            .and_then(|v| v.as_array())
            .expect("recentNotes missing");
        assert_eq!(recent.len(), 2);
    }

    #[tokio::test]
    async fn tools_call_ai_assistant_guide_returns_sections() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(530)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::TOOL_AI_ASSISTANT_GUIDE,
                "arguments": {}
            })),
        };
        let resp = srv.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        let sections = structured
            .get("sections")
            .and_then(|v| v.as_array())
            .expect("sections missing");
        assert!(
            !sections.is_empty(),
            "expected guide sections to be returned"
        );
    }

    #[tokio::test]
    async fn tools_call_continue_conversation_uses_context() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let write_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(540)),
            method: proto::TOOL_WRITE_NOTE.into(),
            params: Some(json!({
                "title": "contextual note",
                "content": "Discuss launch plans and next steps",
                "project": "alpha"
            })),
        };
        let _ = srv.handle_write_note(write_req).await;

        let prompt_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(541)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::TOOL_CONTINUE_CONVERSATION,
                "arguments": {
                    "topic": "launch",
                    "project": "alpha",
                    "limit": 3
                }
            })),
        };
        let resp = srv.handle_tools_call(prompt_req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        let suggestions = structured
            .get("suggestions")
            .and_then(|v| v.as_array())
            .expect("suggestions missing");
        assert!(!suggestions.is_empty(), "expected at least one suggestion");
        assert!(
            suggestions[0]
                .get("snippet")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("launch"),
            "the snippet should reference the topic"
        );
    }

    #[tokio::test]
    async fn tools_call_canvas_creates_canvas_note() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let canvas_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(550)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::TOOL_CANVAS,
                "arguments": {
                    "title": "Architecture Canvas",
                    "nodes": [
                        { "id": "n1", "type": "text", "text": "Component A" }
                    ],
                    "edges": [],
                    "project": "alpha"
                }
            })),
        };
        let resp = srv.handle_tools_call(canvas_req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let structured = call_result_json(&resp.result.unwrap());
        let canvas_id = structured
            .get("id")
            .and_then(|v| v.as_str())
            .expect("canvas id missing")
            .to_string();

        let read_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(551)),
            method: proto::TOOL_READ_NOTE.into(),
            params: Some(json!({
                "id": canvas_id,
                "project": "alpha"
            })),
        };
        let read_resp = srv.handle_read_note(read_req).await;
        assert!(
            read_resp.error.is_none(),
            "failed to read canvas note: {:?}",
            read_resp.error
        );
        let memory: Memory = serde_json::from_value(read_resp.result.unwrap()).unwrap();
        assert!(memory.tags.contains(&"canvas".to_string()));
        assert!(
            memory.content.contains("Component A"),
            "canvas content should include serialized node payload"
        );
    }

    #[tokio::test]
    async fn search_time_range_filters_updated_at() {
        use chrono::{Duration, Utc};
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        // older updated_at
        let mut m1 = Memory::new("old", "bar", "note");
        m1.updated_at = Utc::now() - Duration::minutes(10);
        let project = DEFAULT_PROJECT_ID.to_string();
        storage.save(&project, &m1).unwrap();
        index.update(&project, &m1).unwrap();
        // newer updated_at
        let mut m2 = Memory::new("new", "bar", "note");
        m2.updated_at = Utc::now();
        storage.save(&project, &m2).unwrap();
        index.update(&project, &m2).unwrap();
        let srv = Server::new(storage, index);
        let from = (Utc::now() - Duration::minutes(5)).to_rfc3339();
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(22)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({"query":"bar","time_range":{"from": from}})),
        };
        let resp = srv.handle_search(req).await;
        assert!(resp.error.is_none());
        let v = resp.result.unwrap();
        let items = v.get("items").unwrap().as_array().unwrap();
        assert!(items
            .iter()
            .all(|it| it.get("title").unwrap().as_str().unwrap() != "old"));
    }

    #[tokio::test]
    async fn resources_list_and_read() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let m = Memory::new("t", "c", "note");
        let id = m.id.clone();
        let project = DEFAULT_PROJECT_ID.to_string();
        storage.save(&project, &m).unwrap();
        index.update(&project, &m).unwrap();
        let srv = Server::new(storage, index);
        let uri = format!("mem://{}/{}", project, id);
        // list (canonical)
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(40)),
            method: proto::METHOD_RESOURCES_LIST.into(),
            params: Some(json!({"limit": 10})),
        };
        let resp = srv.handle_request(req).await;
        assert!(resp.error.is_none());
        let list_result = resp.result.expect("missing list result");
        let resources = list_result
            .get("resources")
            .and_then(|r| r.as_array())
            .expect("resources array missing");
        assert!(!resources.is_empty());
        let first = resources
            .iter()
            .find(|res| res.get("uri").and_then(|u| u.as_str()) == Some(uri.as_str()))
            .expect("expected uri not found in resources");
        assert_eq!(
            first
                .get("mimeType")
                .and_then(|m| m.as_str())
                .unwrap_or_default(),
            "application/json"
        );
        // list (legacy alias)
        let legacy_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(41)),
            method: proto::TOOL_RESOURCE_LIST.into(),
            params: Some(json!({})),
        };
        let legacy_resp = srv.handle_request(legacy_req).await;
        assert!(legacy_resp.error.is_none());
        // read
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(42)),
            method: proto::METHOD_RESOURCES_READ.into(),
            params: Some(json!({"uri": uri})),
        };
        let resp = srv.handle_request(req).await;
        assert!(resp.error.is_none());
        let read_result = resp.result.expect("missing read result");
        let contents = read_result
            .get("contents")
            .and_then(|c| c.as_array())
            .expect("contents array missing");
        assert_eq!(contents.len(), 1);
        let entry = contents.first().expect("expected resource entry");
        assert_eq!(
            entry.get("uri").and_then(|u| u.as_str()).unwrap(),
            uri.as_str()
        );
        assert_eq!(
            entry
                .get("mimeType")
                .and_then(|m| m.as_str())
                .unwrap_or_default(),
            "application/json"
        );
        let text = entry
            .get("text")
            .and_then(|t| t.as_str())
            .expect("missing text payload");
        let parsed: Memory = serde_json::from_str(text).expect("memory json failed to parse");
        assert_eq!(parsed.id, id);
        // read (legacy alias)
        let legacy_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(43)),
            method: proto::TOOL_RESOURCE_READ.into(),
            params: Some(json!({"uri": format!("mem://{}", id)})),
        };
        let legacy_resp = srv.handle_request(legacy_req).await;
        assert!(legacy_resp.error.is_none());
    }

    #[tokio::test]
    async fn project_scoping_is_respected() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let save_alpha = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({
                "content": "alpha note",
                "title": "alpha",
                "type": "note",
                "project": "alpha"
            })),
        };
        let saved = srv.handle_save(save_alpha).await;
        assert!(saved.error.is_none(), "unexpected error: {:?}", saved.error);

        let search_default = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(2)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({ "query": "alpha" })),
        };
        let resp_default = srv.handle_search(search_default).await;
        assert!(
            resp_default.error.is_none(),
            "search default failed: {:?}",
            resp_default.error
        );
        let payload_default = resp_default.result.unwrap();
        let items_default = payload_default
            .get("items")
            .and_then(|v| v.as_array())
            .expect("items missing");
        assert!(
            items_default.is_empty(),
            "default project should not see alpha items"
        );

        let search_alpha = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(3)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({ "query": "alpha", "project": "alpha" })),
        };
        let resp_alpha = srv.handle_search(search_alpha).await;
        assert!(
            resp_alpha.error.is_none(),
            "search alpha failed: {:?}",
            resp_alpha.error
        );
        let payload_alpha = resp_alpha.result.unwrap();
        let items_alpha = payload_alpha
            .get("items")
            .and_then(|v| v.as_array())
            .expect("items missing");
        assert_eq!(
            items_alpha.len(),
            1,
            "alpha project should return exactly one item"
        );
    }

    #[tokio::test]
    async fn list_memory_projects_returns_projects() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(500)),
            method: proto::TOOL_LIST_MEMORY_PROJECTS.into(),
            params: Some(json!({})),
        };
        let resp = srv.handle_list_memory_projects(req).await;
        assert!(
            resp.error.is_none(),
            "list projects failed: {:?}",
            resp.error
        );
        let result = resp.result.expect("missing list result");
        let projects = result
            .get("projects")
            .and_then(|v| v.as_array())
            .expect("projects missing");
        assert!(projects
            .iter()
            .any(|p| p.get("id").and_then(|v| v.as_str()) == Some(DEFAULT_PROJECT_ID)));

        let save_alpha = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(501)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({
                "content": "alpha note",
                "title": "alpha",
                "type": "note",
                "project": "alpha"
            })),
        };
        let saved = srv.handle_save(save_alpha).await;
        assert!(
            saved.error.is_none(),
            "save alpha failed: {:?}",
            saved.error
        );

        let req_alpha = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(502)),
            method: proto::TOOL_LIST_MEMORY_PROJECTS.into(),
            params: Some(json!({})),
        };
        let resp_alpha = srv.handle_list_memory_projects(req_alpha).await;
        assert!(
            resp_alpha.error.is_none(),
            "list projects failed: {:?}",
            resp_alpha.error
        );
        let result_alpha = resp_alpha.result.expect("missing list result");
        let projects_alpha = result_alpha
            .get("projects")
            .and_then(|v| v.as_array())
            .expect("projects missing");
        assert!(projects_alpha
            .iter()
            .any(|p| p.get("id").and_then(|v| v.as_str()) == Some("alpha")));
    }

    #[tokio::test]
    async fn initialize_returns_capabilities() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(50)),
            method: proto::TOOL_INITIALIZE.into(),
            params: None,
        };
        let resp = srv.handle_initialize(req).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(
            result
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap(),
            proto::MCP_PROTOCOL_VERSION
        );
        let caps = result.get("capabilities").cloned().unwrap();
        assert!(caps.get("resources").is_some());
        let server_info = result.get("serverInfo").cloned().unwrap();
        assert_eq!(
            server_info
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default(),
            "gitmem"
        );
        let metadata = caps
            .get("experimental")
            .and_then(|exp| exp.get("gitmem"))
            .and_then(|m| m.get("memory"));
        assert!(metadata.is_some());
    }

    #[tokio::test]
    async fn tools_list_contains_memory_save() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(60)),
            method: proto::METHOD_TOOLS_LIST.into(),
            params: None,
        };
        let resp = srv.handle_tools_list(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("missing result");
        let tools = result
            .get("tools")
            .and_then(|t| t.as_array())
            .expect("tools array missing");
        let exported_name = proto::exported_tool_name(proto::TOOL_MEMORY_SAVE);
        assert!(
            tools.iter().any(|tool| {
                tool.get("name").and_then(|n| n.as_str()) == Some(exported_name.as_str())
            }),
            "memory_save tool missing"
        );
    }

    #[tokio::test]
    async fn tools_call_invokes_memory_save() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(61)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::exported_tool_name(proto::TOOL_MEMORY_SAVE),
                "arguments": {
                    "title": "tool call",
                    "content": "created via tools.call",
                    "type": "note"
                }
            })),
        };
        let resp = srv.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("missing result");
        let payload_value = call_result_json(&result);
        let json_payload = payload_value.as_object().expect("json payload missing");
        let id_value = json_payload
            .get("id")
            .and_then(|v| v.as_str())
            .expect("id missing in payload");
        let get_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(62)),
            method: proto::TOOL_MEMORY_GET.into(),
            params: Some(json!({ "id": id_value })),
        };
        let get_resp = srv.handle_get(get_req).await;
        assert!(
            get_resp.error.is_none(),
            "memory.get failed: {:?}",
            get_resp.error
        );
    }

    #[tokio::test]
    async fn tools_call_accepts_name_alias() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(101)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "name": proto::TOOL_MEMORY_SAVE,
                "arguments": {
                    "title": "alias call",
                    "content": "created via name alias",
                    "type": "note"
                }
            })),
        };
        let resp = srv.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("missing result body");
        let payload_value = call_result_json(&result);
        let payload = payload_value.as_object().expect("json payload missing");
        assert_eq!(
            payload.get("title"),
            Some(&json!("alias call")),
            "unexpected title in payload"
        );
    }

    #[tokio::test]
    async fn tools_call_allows_null_arguments() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(99)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::TOOL_MEMORY_SEARCH,
                "arguments": null
            })),
        };
        let resp = srv.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("missing result body");
        let payload_value = call_result_json(&result);
        let payload = payload_value.as_object().expect("json payload missing");
        assert_eq!(payload.get("total"), Some(&json!(0)));
        assert_eq!(payload.get("items"), Some(&json!([])));
    }

    #[tokio::test]
    async fn tools_call_accepts_input_json_argument_array() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(100)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::exported_tool_name(proto::TOOL_MEMORY_SEARCH),
                "arguments": [
                    {
                        "type": "input_json",
                        "json": {
                            "query": "",
                            "sort": "recency"
                        }
                    }
                ]
            })),
        };
        let resp = srv.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("missing result body");
        let payload_value = call_result_json(&result);
        let payload = payload_value.as_object().expect("json payload missing");
        assert_eq!(payload.get("total"), Some(&json!(0)));
        assert_eq!(payload.get("items"), Some(&json!([])));
    }

    #[tokio::test]
    async fn tools_call_accepts_input_text_with_json_payload() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(101)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::exported_tool_name(proto::TOOL_MEMORY_SEARCH),
                "arguments": [
                    {
                        "type": "input_text",
                        "text": "{\"query\":\"\",\"limit\":1}"
                    }
                ]
            })),
        };
        let resp = srv.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("missing result body");
        let payload_value = call_result_json(&result);
        let payload = payload_value.as_object().expect("json payload missing");
        assert_eq!(payload.get("total"), Some(&json!(0)));
        assert_eq!(payload.get("items"), Some(&json!([])));
    }

    #[tokio::test]
    async fn tools_call_accepts_input_text_plain_query() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(102)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::exported_tool_name(proto::TOOL_MEMORY_SEARCH),
                "arguments": [
                    {
                        "type": "input_text",
                        "text": "show me recent memories about onboarding"
                    }
                ]
            })),
        };
        let resp = srv.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("missing result body");
        let payload_value = call_result_json(&result);
        let payload = payload_value.as_object().expect("json payload missing");
        assert_eq!(payload.get("total"), Some(&json!(0)));
    }

    #[tokio::test]
    async fn tools_call_accepts_input_structured_payload() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(103)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::exported_tool_name(proto::TOOL_MEMORY_SEARCH),
                "arguments": [
                    {
                        "type": "input_structured",
                        "structured": {
                            "query": "search term",
                            "limit": 5
                        }
                    }
                ]
            })),
        };
        let resp = srv.handle_tools_call(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("missing result body");
        let payload_value = call_result_json(&result);
        let payload = payload_value.as_object().expect("json payload missing");
        assert_eq!(payload.get("total"), Some(&json!(0)));
    }

    #[tokio::test]
    async fn ttl_expired_is_filtered_out() {
        // Prepare storage and index with two docs: one expired, one valid
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let project = DEFAULT_PROJECT_ID.to_string();
        // Create expired
        let mut expired = Memory::new("t1", "foo content", "note");
        expired.created_at = Utc::now() - Duration::seconds(30);
        expired.updated_at = expired.created_at;
        expired.ttl = Some("PT1S".to_string()); // 1 second
        let id_exp = expired.id.clone();
        storage.save(&project, &expired).unwrap();
        index.update(&project, &expired).unwrap();

        // Create valid
        let mut valid = Memory::new("t2", "foo content", "note");
        valid.created_at = Utc::now() - Duration::seconds(30);
        valid.updated_at = valid.created_at;
        valid.ttl = Some("PT1M".to_string()); // 1 minute
        let id_valid = valid.id.clone();
        storage.save(&project, &valid).unwrap();
        index.update(&project, &valid).unwrap();

        let srv = Server::new(storage, index);

        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(10)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({"query":"foo"})),
        };
        let resp = srv.handle_search(req).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let v = resp.result.unwrap();
        let items = v.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 1);
        let got_id = items[0].get("id").unwrap().as_str().unwrap();
        assert_eq!(got_id, id_valid);
        assert_ne!(got_id, id_exp);
    }

    #[tokio::test]
    async fn sort_by_recency_orders_newest_first() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let project = DEFAULT_PROJECT_ID.to_string();
        // older
        let mut m1 = Memory::new("old", "bar", "note");
        m1.updated_at = Utc::now() - Duration::minutes(5);
        let _id1 = m1.id.clone();
        storage.save(&project, &m1).unwrap();
        index.update(&project, &m1).unwrap();
        // newer
        let mut m2 = Memory::new("new", "bar", "note");
        m2.updated_at = Utc::now();
        let id2 = m2.id.clone();
        storage.save(&project, &m2).unwrap();
        index.update(&project, &m2).unwrap();

        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(11)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({"query":"bar","sort":"recency"})),
        };
        let resp = srv.handle_search(req).await;
        assert!(resp.error.is_none());
        let v = resp.result.unwrap();
        let items = v.get("items").unwrap().as_array().unwrap();
        assert!(items.len() >= 2);
        let first_id = items[0].get("id").unwrap().as_str().unwrap();
        assert_eq!(first_id, id2);
    }

    #[tokio::test]
    async fn sort_by_score_uses_memory_score_when_present() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let project = DEFAULT_PROJECT_ID.to_string();
        // lower memory score
        let mut m1 = Memory::new("t1", "query term", "note");
        m1.score = Some(0.1);
        let id1 = m1.id.clone();
        storage.save(&project, &m1).unwrap();
        index.update(&project, &m1).unwrap();
        // higher memory score
        let mut m2 = Memory::new("t2", "query term", "note");
        m2.score = Some(0.9);
        let id2 = m2.id.clone();
        storage.save(&project, &m2).unwrap();
        index.update(&project, &m2).unwrap();

        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(12)),
            method: proto::TOOL_MEMORY_SEARCH.into(),
            params: Some(json!({"query":"query","sort":"score"})),
        };
        let resp = srv.handle_search(req).await;
        assert!(resp.error.is_none());
        let v = resp.result.unwrap();
        let items = v.get("items").unwrap().as_array().unwrap();
        assert!(items.len() >= 2);
        let first_id = items[0].get("id").unwrap().as_str().unwrap();
        assert_eq!(first_id, id2);
        assert_ne!(first_id, id1);
    }

    #[tokio::test]
    async fn tools_call_missing_required_field_returns_invalid_params() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(305)),
            method: proto::METHOD_TOOLS_CALL.into(),
            params: Some(json!({
                "toolName": proto::exported_tool_name(proto::TOOL_MEMORY_SAVE),
                "arguments": {
                    "title": "missing content",
                    "type": "note"
                }
            })),
        };
        let resp = srv.handle_tools_call(req).await;
        assert!(
            resp.result.is_none(),
            "unexpected result payload: {:?}",
            resp.result
        );
        let err = resp.error.expect("expected error response");
        assert_eq!(err.code, -32602);
        let data = err.data.expect("missing error data");
        assert_eq!(
            data.get("code").and_then(|v| v.as_str()),
            Some("E_VALIDATION")
        );
    }

    #[tokio::test]
    async fn import_basic_dry_run_reports_counts() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("memories.json");
        let payload = r#"[
  {"id":"mem-1","title":"alpha","content":"one","type":"note"},
  {"id":"mem-1","title":"alpha","content":"one","type":"note"},
  {"id":"mem-2","title":"beta","content":"two","type":"note"}
]"#;
        fs::write(&path, payload).expect("write basic memory payload");

        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let server = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(401)),
            method: proto::TOOL_MEMORY_IMPORT_BASIC.into(),
            params: Some(json!({
                "path": path.to_string_lossy(),
                "dry_run": true
            })),
        };
        let resp = server.handle_import_basic(req).await;
        assert!(
            resp.error.is_none(),
            "import dry_run errored: {:?}",
            resp.error
        );
        let summary = resp.result.expect("missing import summary");
        assert_eq!(summary.get("total").and_then(|v| v.as_u64()), Some(3));
        assert_eq!(summary.get("deduped").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(summary.get("imported").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(
            summary.get("skipped_existing").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(summary.get("errors").and_then(|v| v.as_u64()), Some(0));
    }

    #[tokio::test]
    async fn import_basic_skips_existing_records() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("records.json");
        let payload = r#"[
  {"id":"mem-a","title":"A","content":"Alpha","type":"note"},
  {"id":"mem-b","title":"B","content":"Beta","type":"note"}
]"#;
        fs::write(&path, payload).expect("write basic memory payload");

        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let server = Server::new(storage, index);

        let first_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(410)),
            method: proto::TOOL_MEMORY_IMPORT_BASIC.into(),
            params: Some(json!({ "path": path.to_string_lossy() })),
        };
        let first = server.handle_import_basic(first_req).await;
        assert!(
            first.error.is_none(),
            "first import failed: {:?}",
            first.error
        );
        let first_summary = first.result.expect("missing first summary");
        assert_eq!(
            first_summary.get("imported").and_then(|v| v.as_u64()),
            Some(2)
        );

        let second_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(411)),
            method: proto::TOOL_MEMORY_IMPORT_BASIC.into(),
            params: Some(json!({ "path": path.to_string_lossy() })),
        };
        let second = server.handle_import_basic(second_req).await;
        assert!(
            second.error.is_none(),
            "second import failed: {:?}",
            second.error
        );
        let second_summary = second.result.expect("missing second summary");
        assert_eq!(
            second_summary.get("imported").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            second_summary
                .get("skipped_existing")
                .and_then(|v| v.as_u64()),
            Some(2)
        );
    }

    #[tokio::test]
    async fn create_and_delete_project_handlers() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let create_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(520)),
            method: proto::TOOL_CREATE_MEMORY_PROJECT.into(),
            params: Some(json!({"id":"alpha"})),
        };
        let create_resp = srv.handle_create_project(create_req).await;
        assert!(
            create_resp.error.is_none(),
            "create project failed: {:?}",
            create_resp.error
        );

        let list_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(521)),
            method: proto::TOOL_LIST_MEMORY_PROJECTS.into(),
            params: Some(json!({})),
        };
        let list_resp = srv.handle_list_memory_projects(list_req).await;
        let list_value = list_resp.result.unwrap();
        let projects = list_value
            .get("projects")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(projects
            .iter()
            .any(|p| p.get("id").and_then(|v| v.as_str()) == Some("alpha")));

        let delete_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(522)),
            method: proto::TOOL_DELETE_MEMORY_PROJECT.into(),
            params: Some(json!({"id":"alpha","force":true})),
        };
        let delete_resp = srv.handle_delete_project(delete_req).await;
        assert!(
            delete_resp.error.is_none(),
            "delete project failed: {:?}",
            delete_resp.error
        );
    }

    #[cfg(feature = "backend-github")]
    #[tokio::test]
    async fn github_project_handlers_touch_filesystem() {
        let repo = tempdir().expect("tempdir");
        let storage = GithubStorage::new(repo.path()).expect("github storage");
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let project_id = "alpha";

        let create_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(620)),
            method: proto::TOOL_CREATE_MEMORY_PROJECT.into(),
            params: Some(json!({"id":project_id,"name":"Alpha"})),
        };
        let create_resp = srv.handle_create_project(create_req).await;
        assert!(
            create_resp.error.is_none(),
            "github create project failed: {:?}",
            create_resp.error
        );
        assert!(repo.path().join("memories").join(project_id).is_dir());
        assert!(repo
            .path()
            .join("meta")
            .join(project_id)
            .join("MANIFEST.json")
            .exists());

        let delete_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(621)),
            method: proto::TOOL_DELETE_MEMORY_PROJECT.into(),
            params: Some(json!({"id":project_id,"force":true})),
        };
        let delete_resp = srv.handle_delete_project(delete_req).await;
        assert!(
            delete_resp.error.is_none(),
            "github delete project failed: {:?}",
            delete_resp.error
        );
        assert!(
            !repo.path().join("memories").join(project_id).exists(),
            "project directory should be removed"
        );
        assert!(
            !repo.path().join("meta").join(project_id).exists(),
            "project metadata directory should be removed"
        );
    }

    #[tokio::test]
    async fn list_directory_returns_entries() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let save = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(530)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({"content":"body","title":"note","type":"note","project":"alpha"})),
        };
        let saved = srv.handle_save(save).await;
        assert!(saved.error.is_none());

        let list_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(531)),
            method: proto::TOOL_LIST_DIRECTORY.into(),
            params: Some(json!({"project":"alpha"})),
        };
        let list_resp = srv.handle_list_directory(list_req).await;
        assert!(
            list_resp.error.is_none(),
            "list directory failed: {:?}",
            list_resp.error
        );
        let list_value = list_resp.result.unwrap();
        let entries = list_value
            .get("entries")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(!entries.is_empty());
    }

    #[tokio::test]
    async fn sync_status_returns_idle() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(540)),
            method: proto::TOOL_SYNC_STATUS.into(),
            params: Some(json!({"project":"alpha"})),
        };
        let resp = srv.handle_sync_status(req).await;
        assert!(resp.error.is_none(), "sync status failed: {:?}", resp.error);
        let status: proto::SyncStatusResult = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(status.project, "alpha");
        assert_eq!(status.state, "idle");
    }

    #[cfg(feature = "backend-github")]
    #[tokio::test]
    async fn github_sync_status_reports_pending_commit() {
        let repo = tempdir().expect("tempdir");
        let storage = GithubStorage::new(repo.path()).expect("github storage");
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);
        let project = "alpha";

        let first_save = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(630)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(json!({"content":"body","title":"first","type":"note","project":project})),
        };
        let first_resp = srv.handle_save(first_save).await;
        assert!(
            first_resp.error.is_none(),
            "first save failed: {:?}",
            first_resp.error
        );

        let second_save = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(631)),
            method: proto::TOOL_MEMORY_SAVE.into(),
            params: Some(
                json!({"content":"body2","title":"second","type":"note","project":project}),
            ),
        };
        let second_resp = srv.handle_save(second_save).await;
        assert!(
            second_resp.error.is_none(),
            "second save failed: {:?}",
            second_resp.error
        );

        let status_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(632)),
            method: proto::TOOL_SYNC_STATUS.into(),
            params: Some(json!({"project":project})),
        };
        let status_resp = srv.handle_sync_status(status_req).await;
        assert!(
            status_resp.error.is_none(),
            "github sync status failed: {:?}",
            status_resp.error
        );
        let status: proto::SyncStatusResult =
            serde_json::from_value(status_resp.result.unwrap()).unwrap();
        assert_eq!(status.project, project);
        assert_eq!(status.state, "pending_commit");
        let details = status.details.expect("missing details");
        assert_eq!(details.get("dirty").and_then(|v| v.as_bool()), Some(true));
        assert!(details
            .get("sinceLastCommitMs")
            .and_then(|v| v.as_u64())
            .is_some());
        assert_eq!(
            details
                .get("deviceBranch")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("devices/")),
            Some(true)
        );
    }

    #[cfg(feature = "backend-local")]
    #[tokio::test]
    async fn link_list_sync_and_unlink_external_folder() {
        let root_dir = tempdir().expect("tempdir");
        let external_dir = tempdir().expect("external");
        let external_path = external_dir.path().join("vault");
        fs::create_dir_all(&external_path).expect("external dir");
        let file_path = external_path.join("note.md");
        fs::write(&file_path, "---\ntitle: Linked\n---\nbody").expect("write file");

        let mut watch_config = LocalWatchConfig::default();
        watch_config.set_allow_outside_home(true);
        let storage = LocalStorage::with_config(root_dir.path(), watch_config);
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let link_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(9000)),
            method: proto::TOOL_PROJECT_LINK_FOLDER.into(),
            params: Some(json!({
                "project": DEFAULT_PROJECT_ID,
                "path": external_path.to_string_lossy()
            })),
        };
        let link_resp = srv.handle_link_folder(link_req).await;
        assert!(
            link_resp.error.is_none(),
            "link failed: {:?}",
            link_resp.error
        );
        let link_value = link_resp.result.clone().unwrap();
        let link_result: proto::LinkFolderResult = serde_json::from_value(link_value).unwrap();
        assert_eq!(link_result.project, DEFAULT_PROJECT_ID);
        assert_eq!(
            link_result.watch.as_ref().map(|w| w.mode.as_str()),
            Some("poll")
        );
        assert_eq!(link_result.status.as_deref(), Some("polling"));
        assert!(link_result.file_count.unwrap_or(0) >= 1);
        assert!(link_result.total_bytes.unwrap_or(0) > 0);
        assert!(link_result.last_runtime_ms.unwrap_or(0) > 0);
        assert!(link_result.last_scan.is_some());
        let link_id = link_result.link_id.clone();

        let list_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(9001)),
            method: proto::TOOL_PROJECT_LIST_LINKS.into(),
            params: Some(json!({"project": DEFAULT_PROJECT_ID})),
        };
        let list_resp = srv.handle_list_linked_folders(list_req).await;
        assert!(
            list_resp.error.is_none(),
            "list failed: {:?}",
            list_resp.error
        );
        let list_value = list_resp.result.unwrap();
        let links: proto::ListLinkedFoldersResult = serde_json::from_value(list_value).unwrap();
        assert_eq!(links.links.len(), 1);
        let listed = &links.links[0];
        assert_eq!(listed.link_id, link_id);
        assert_eq!(listed.status.as_deref(), Some("polling"));
        assert!(listed.file_count.unwrap_or(0) >= 1);
        assert!(listed.total_bytes.unwrap_or(0) > 0);
        assert!(listed.last_runtime_ms.unwrap_or(0) > 0);

        let sync_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(9002)),
            method: proto::TOOL_MEMORY_SYNC.into(),
            params: Some(json!({
                "project": DEFAULT_PROJECT_ID,
                "direction": "external",
                "paths": [external_path.to_string_lossy()]
            })),
        };
        let sync_resp = srv.handle_sync(sync_req).await;
        assert!(
            sync_resp.error.is_none(),
            "external sync failed: {:?}",
            sync_resp.error
        );
        let sync_value = sync_resp.result.unwrap();
        assert_eq!(
            sync_value.get("direction").and_then(|v| v.as_str()),
            Some("external")
        );
        let reports = sync_value
            .get("reports")
            .and_then(|v| v.as_array())
            .expect("reports array");
        assert!(!reports.is_empty(), "reports should not be empty");
        let report = &reports[0];
        assert_eq!(
            report.get("linkId").and_then(|v| v.as_str()),
            Some(link_id.as_str())
        );
        assert!(
            report
                .get("totalBytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 0
        );
        assert!(
            report
                .get("runtimeMs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 0
        );

        let unlink_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(9003)),
            method: proto::TOOL_PROJECT_UNLINK_FOLDER.into(),
            params: Some(json!({
                "project": DEFAULT_PROJECT_ID,
                "path": external_path.to_string_lossy()
            })),
        };
        let unlink_resp = srv.handle_unlink_folder(unlink_req).await;
        assert!(
            unlink_resp.error.is_none(),
            "unlink failed: {:?}",
            unlink_resp.error
        );
    }

    #[tokio::test]
    async fn write_and_read_note_via_compat() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let write = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(600)),
            method: proto::TOOL_WRITE_NOTE.into(),
            params: Some(json!({
                "title": "compat",
                "content": "note body",
                "project": "alpha"
            })),
        };
        let saved = srv.handle_write_note(write).await;
        assert!(
            saved.error.is_none(),
            "write note failed: {:?}",
            saved.error
        );
        let mem: Memory = serde_json::from_value(saved.result.unwrap()).unwrap();

        let read = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(601)),
            method: proto::TOOL_READ_NOTE.into(),
            params: Some(json!({"id": mem.id, "project": "alpha"})),
        };
        let fetched = srv.handle_read_note(read).await;
        assert!(
            fetched.error.is_none(),
            "read note failed: {:?}",
            fetched.error
        );
        let fetched_mem: Memory = serde_json::from_value(fetched.result.unwrap()).unwrap();
        assert_eq!(fetched_mem.title, "compat");
        assert_eq!(fetched_mem.content, "note body");
    }

    #[tokio::test]
    async fn edit_and_delete_note_via_compat() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let write = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(610)),
            method: proto::TOOL_WRITE_NOTE.into(),
            params: Some(json!({"content":"start","project":"alpha"})),
        };
        let saved = srv.handle_write_note(write).await;
        let mem: Memory = serde_json::from_value(saved.result.unwrap()).unwrap();

        let edit = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(611)),
            method: proto::TOOL_EDIT_NOTE.into(),
            params: Some(json!({
                "id": mem.id,
                "content": "updated",
                "project": "alpha"
            })),
        };
        let edited = srv.handle_edit_note(edit).await;
        assert!(edited.error.is_none());
        let edited_mem: Memory = serde_json::from_value(edited.result.unwrap()).unwrap();
        assert_eq!(edited_mem.content, "updated");

        let delete = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(612)),
            method: proto::TOOL_DELETE_NOTE.into(),
            params: Some(json!({"id": edited_mem.id, "project": "alpha", "hard": true})),
        };
        let deleted = srv.handle_delete_note(delete).await;
        assert!(deleted.error.is_none());
    }

    #[tokio::test]
    async fn search_notes_and_recent_activity_return_results() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        for title in ["alpha", "beta"] {
            let req = JsonRpcRequest {
                jsonrpc: Some("2.0".into()),
                id: Some(json!(620)),
                method: proto::TOOL_WRITE_NOTE.into(),
                params: Some(json!({"title": title, "content": title, "project":"alpha"})),
            };
            let _ = srv.handle_write_note(req).await;
        }

        let search_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(621)),
            method: proto::TOOL_SEARCH_NOTES.into(),
            params: Some(json!({"query": "alpha", "project": "alpha"})),
        };
        let search_resp = srv.handle_search_notes(search_req).await;
        assert!(search_resp.error.is_none());
        let search_result: proto::SearchNotesResult =
            serde_json::from_value(search_resp.result.unwrap()).unwrap();
        assert!(search_result.total >= 1);

        let recent_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(622)),
            method: proto::TOOL_RECENT_ACTIVITY.into(),
            params: Some(json!({"project":"alpha", "limit":2})),
        };
        let recent_resp = srv.handle_recent_activity(recent_req).await;
        assert!(recent_resp.error.is_none());
        let recent: proto::RecentActivityResult =
            serde_json::from_value(recent_resp.result.unwrap()).unwrap();
        assert_eq!(recent.notes.len(), 2);
    }

    #[tokio::test]
    async fn read_content_returns_note_body() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let write = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(630)),
            method: proto::TOOL_WRITE_NOTE.into(),
            params: Some(json!({"content":"body","project":"alpha"})),
        };
        let saved = srv.handle_write_note(write).await;
        let mem: Memory = serde_json::from_value(saved.result.unwrap()).unwrap();

        let read_content_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(631)),
            method: proto::TOOL_READ_CONTENT.into(),
            params: Some(json!({"id": mem.id, "project": "alpha"})),
        };
        let resp = srv.handle_read_content(read_content_req).await;
        assert!(resp.error.is_none());
        let result: proto::ReadContentResult =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(result.content, "body");
    }

    #[tokio::test]
    async fn move_note_between_projects() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let write = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(640)),
            method: proto::TOOL_WRITE_NOTE.into(),
            params: Some(json!({"content":"body","project":"alpha"})),
        };
        let saved = srv.handle_write_note(write).await;
        let mem: Memory = serde_json::from_value(saved.result.unwrap()).unwrap();

        let move_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(641)),
            method: proto::TOOL_MOVE_NOTE.into(),
            params: Some(json!({"id": mem.id, "project": "alpha", "target_project": "beta"})),
        };
        let move_resp = srv.handle_move_note(move_req).await;
        assert!(
            move_resp.error.is_none(),
            "move note failed: {:?}",
            move_resp.error
        );

        let read_alpha = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(642)),
            method: proto::TOOL_READ_NOTE.into(),
            params: Some(json!({"id": mem.id, "project": "alpha"})),
        };
        let resp_alpha = srv.handle_read_note(read_alpha).await;
        assert!(resp_alpha.result.is_none());

        let read_beta = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(643)),
            method: proto::TOOL_READ_NOTE.into(),
            params: Some(json!({"id": mem.id, "project": "beta"})),
        };
        let resp_beta = srv.handle_read_note(read_beta).await;
        assert!(resp_beta.error.is_none());
    }

    #[tokio::test]
    async fn move_note_returns_not_found_for_missing_id() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let move_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(644)),
            method: proto::TOOL_MOVE_NOTE.into(),
            params: Some(json!({
                "id": "does-not-exist",
                "project": "alpha",
                "target_project": "beta"
            })),
        };
        let resp = srv.handle_move_note(move_req).await;
        assert!(resp.result.is_none());
        let err = resp.error.expect("expected move error");
        assert_eq!(err.code, -32000);
        let data = err.data.expect("expected move error data");
        assert_eq!(data.get("code"), Some(&json!("E_NOT_FOUND")));
    }

    #[tokio::test]
    async fn build_context_without_query_uses_recent_activity_limit() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        for idx in 0..3 {
            let write = JsonRpcRequest {
                jsonrpc: Some("2.0".into()),
                id: Some(json!(650 + idx)),
                method: proto::TOOL_WRITE_NOTE.into(),
                params: Some(json!({
                    "title": format!("n{idx}"),
                    "content": format!("note-{idx}")
                })),
            };
            let _ = srv.handle_write_note(write).await;
        }

        let ctx_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(660)),
            method: proto::TOOL_BUILD_CONTEXT.into(),
            params: Some(json!({"limit": 2})),
        };
        let resp = srv.handle_build_context(ctx_req).await;
        assert!(
            resp.error.is_none(),
            "build_context failed: {:?}",
            resp.error
        );
        let ctx: proto::BuildContextResult =
            serde_json::from_value(resp.result.expect("missing context result")).unwrap();
        assert_eq!(ctx.notes.len(), 2);
    }

    #[tokio::test]
    async fn build_context_with_query_filters_results() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let alpha = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(670)),
            method: proto::TOOL_WRITE_NOTE.into(),
            params: Some(json!({"title":"alpha","content":"alpha body"})),
        };
        let beta = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(671)),
            method: proto::TOOL_WRITE_NOTE.into(),
            params: Some(json!({"title":"beta","content":"beta body"})),
        };
        let _ = srv.handle_write_note(alpha).await;
        let _ = srv.handle_write_note(beta).await;

        let ctx_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(672)),
            method: proto::TOOL_BUILD_CONTEXT.into(),
            params: Some(json!({"query": "beta"})),
        };
        let resp = srv.handle_build_context(ctx_req).await;
        assert!(
            resp.error.is_none(),
            "build_context failed: {:?}",
            resp.error
        );
        let ctx: proto::BuildContextResult =
            serde_json::from_value(resp.result.expect("missing context result")).unwrap();
        assert_eq!(ctx.notes.len(), 1);
        let note = ctx.notes.first().expect("expected single note");
        assert_eq!(note.get("title"), Some(&json!("beta")));
    }

    #[tokio::test]
    async fn read_content_missing_id_returns_error() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let srv = Server::new(storage, index);

        let read_content_req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(680)),
            method: proto::TOOL_READ_CONTENT.into(),
            params: Some(json!({"id": "unknown"})),
        };
        let resp = srv.handle_read_content(read_content_req).await;
        assert!(resp.result.is_none());
        let err = resp.error.expect("expected read_content error");
        assert_eq!(err.code, -32000);
        let data = err.data.expect("expected error data");
        assert_eq!(data.get("code"), Some(&json!("E_NOT_FOUND")));
    }

    #[tokio::test]
    async fn sync_without_github_backend_returns_storage_error() {
        let storage = EphemeralStorage::new();
        let index = TantivyIndex::new();
        let server = Server::new(storage, index);
        let req = JsonRpcRequest {
            jsonrpc: Some("2.0".into()),
            id: Some(json!(420)),
            method: proto::TOOL_MEMORY_SYNC.into(),
            params: Some(json!({ "direction": "push" })),
        };
        let resp = server.handle_sync(req).await;
        assert!(resp.result.is_none(), "sync unexpectedly succeeded");
        let err = resp.error.expect("expected sync error");
        assert_eq!(err.code, -32000);
        assert_eq!(err.message, "sync not supported for this backend");
        let data = err.data.expect("missing error data");
        assert_eq!(
            data.get("code").and_then(|v| v.as_str()),
            Some("E_STORAGE_IO")
        );
    }
}
