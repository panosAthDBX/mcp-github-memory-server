use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use color_eyre::eyre::{eyre, Result};
use mcp_gitmem_core::{
    project::{sanitize_project_id, DEFAULT_PROJECT_ID},
    traits::{Index, Storage},
};
use mcp_gitmem_storage_local::{LocalError as LocalStorageError, LocalStorage, LocalWatchConfig};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf};
use toml::Value as TomlValue;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize, PartialEq)]
enum Backend {
    Local,
    Github,
    Ephemeral,
}

#[derive(Parser, Debug)]
#[command(name = "gitmem", version, about = "MCP GitHub Memory Server CLI")]
struct Cli {
    #[arg(long, global = true, default_value = "info")]
    log_level: String,
    #[arg(long, global = true)]
    config: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Serve(ServeArgs),
    Import(ImportArgs),
    Sync(SyncArgs),
    LinkFolder(LinkFolderArgs),
    UnlinkFolder(UnlinkFolderArgs),
    ListLinks(ListLinksArgs),
    RescanLinks(RescanLinksArgs),
    Reindex,
    Reencrypt,
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[arg(long, value_enum, default_value_t = Backend::Ephemeral)]
    backend: Backend,
    #[arg(long, default_value = "./data")]
    root: String,
    #[arg(long)]
    project: Option<String>,
    #[arg(long, default_value_t = false)]
    http: bool,
    #[arg(long, default_value = "127.0.0.1:8080")]
    addr: String,
    #[cfg(feature = "encryption")]
    #[arg(
        long = "encryption-recipient",
        action = ArgAction::Append,
        value_name = "AGE_RECIPIENT",
        help = "Age recipient to encrypt new memories for (repeatable)"
    )]
    encryption_recipient: Vec<String>,
    #[cfg(feature = "encryption")]
    #[arg(
        long = "encryption-enabled",
        help = "Force encryption on new memories (true/false)",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    encryption_enabled: Option<bool>,
    #[arg(
        long = "auto-push",
        help = "Enable automatic push to remote after every write (GitHub backend only)"
    )]
    auto_push: bool,
    #[arg(
        long = "remote-url",
        value_name = "URL",
        help = "Remote URL for auto-push (e.g., https://github.com/user/repo.git or file:///path)"
    )]
    remote_url: Option<String>,
}

#[derive(Args, Debug)]
struct ImportArgs {
    #[arg(long)]
    from: String,
    #[arg(long, value_enum, default_value_t = Backend::Local)]
    backend: Backend,
    #[arg(long, default_value = "./data")]
    root: String,
    #[arg(long)]
    project: Option<String>,
    #[arg(long = "map-type", value_parser = parse_kv, num_args = 0.., value_delimiter = ' ')]
    map_types: Vec<(String, String)>,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(Args, Debug)]
struct SyncArgs {
    #[arg(long, default_value = "both")]
    direction: String,
    #[arg(long, value_enum, default_value_t = Backend::Github)]
    backend: Backend,
    #[arg(long, default_value = "./repo")]
    root: String,
    #[arg(long)]
    project: Option<String>,
    #[arg(long, default_value = "origin")]
    remote: String,
    #[arg(long)]
    branch: Option<String>,
    #[arg(long = "path", action = ArgAction::Append, value_name = "PATH")]
    paths: Vec<String>,
}

#[derive(Args, Debug)]
struct LinkFolderArgs {
    #[arg(long, value_enum, default_value_t = Backend::Local)]
    backend: Backend,
    #[arg(long, default_value = "./data")]
    root: String,
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    path: String,
    #[arg(long = "include", action = ArgAction::Append, value_name = "GLOB")]
    include: Vec<String>,
    #[arg(long = "exclude", action = ArgAction::Append, value_name = "GLOB")]
    exclude: Vec<String>,
    #[arg(long = "no-rescan")]
    no_rescan: bool,
    #[arg(long = "watch-mode", value_name = "MODE")]
    watch_mode: Option<String>,
    #[arg(long = "poll-interval", value_name = "MILLIS")]
    poll_interval: Option<u64>,
    #[arg(long = "jitter", value_name = "PERCENT")]
    jitter: Option<u32>,
}

#[derive(Args, Debug)]
struct UnlinkFolderArgs {
    #[arg(long, value_enum, default_value_t = Backend::Local)]
    backend: Backend,
    #[arg(long, default_value = "./data")]
    root: String,
    #[arg(long)]
    project: Option<String>,
    #[arg(long)]
    path: Option<String>,
}

#[derive(Args, Debug)]
struct ListLinksArgs {
    #[arg(long, value_enum, default_value_t = Backend::Local)]
    backend: Backend,
    #[arg(long, default_value = "./data")]
    root: String,
    #[arg(long)]
    project: Option<String>,
}

#[derive(Args, Debug)]
struct RescanLinksArgs {
    #[arg(long, value_enum, default_value_t = Backend::Local)]
    backend: Backend,
    #[arg(long, default_value = "./data")]
    root: String,
    #[arg(long)]
    project: Option<String>,
    #[arg(long = "path", action = ArgAction::Append, value_name = "PATH")]
    paths: Vec<String>,
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    init_tracing(&cli.log_level);
    let cfg = load_config(cli.config.as_deref())?;
    match cli.command {
        Commands::Serve(args) => serve(args, cfg.as_ref()).await?,
        Commands::Import(args) => import_cmd(args, cfg.as_ref()).await?,
        Commands::Sync(args) => sync_cmd(args, cfg.as_ref()).await?,
        Commands::LinkFolder(args) => link_folder_cmd(args, cfg.as_ref())?,
        Commands::UnlinkFolder(args) => unlink_folder_cmd(args, cfg.as_ref())?,
        Commands::ListLinks(args) => list_links_cmd(args, cfg.as_ref())?,
        Commands::RescanLinks(args) => rescan_links_cmd(args, cfg.as_ref())?,
        Commands::Reindex => info!("reindex requested (placeholder)"),
        Commands::Reencrypt => info!("reencrypt requested (placeholder)"),
    }
    Ok(())
}

async fn serve(mut args: ServeArgs, cfg: Option<&AppConfig>) -> Result<()> {
    use mcp_gitmem_index_tantivy::TantivyIndex;
    use mcp_gitmem_server::{Server, ServerOptions};
    // apply config defaults if present for serve
    if let Some(cfg) = cfg {
        if let Some(s) = &cfg.serve {
            if let Some(b) = s.backend.clone() {
                args.backend = b;
            }
            if let Some(r) = s.root.clone() {
                args.root = r;
            }
        }
        if let Some(d) = &cfg.default {
            args.backend = d.backend.clone().unwrap_or(args.backend);
            args.root = d.root.clone().unwrap_or(args.root);
        }
    }
    let project = sanitize_project_id(args.project.as_deref().unwrap_or(DEFAULT_PROJECT_ID));
    info!(backend = ?args.backend, project = %project, "starting server");
    #[cfg(feature = "encryption")]
    let mut encryption_recipients: Vec<String> = args
        .encryption_recipient
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    #[cfg(feature = "encryption")]
    let mut encryption_enabled = args.encryption_enabled.unwrap_or(true);
    #[cfg(feature = "encryption")]
    if let Some(cfg) = cfg {
        if let Some(enc_cfg) = &cfg.encryption {
            if let Some(enabled) = enc_cfg.enabled {
                encryption_enabled = enabled;
            }
            if encryption_recipients.is_empty() {
                if let Some(from_cfg) = enc_cfg.recipients.clone() {
                    encryption_recipients = from_cfg
                        .into_iter()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }
    }
    #[cfg(feature = "encryption")]
    if encryption_recipients.is_empty() {
        if let Ok(env_val) = std::env::var("GITMEM_ENCRYPT_RECIPIENTS") {
            encryption_recipients = env_val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    #[cfg(feature = "encryption")]
    if !encryption_enabled {
        encryption_recipients.clear();
    }
    match args.backend {
        Backend::Ephemeral => {
            let storage = mcp_gitmem_storage_ephemeral::EphemeralStorage::new();
            let index = TantivyIndex::new();
            let mut options = ServerOptions::default();
            options.default_project = project.clone();
            #[cfg(feature = "encryption")]
            {
                if !encryption_recipients.is_empty() {
                    options.encryption_recipients = encryption_recipients.clone();
                }
            }
            let server = Server::new_with_options(storage, index, options);
            if args.http {
                if let Err(e) = server.run_http(&args.addr).await {
                    tracing::error!(error=%e, "http server exited with error");
                }
            } else if let Err(e) = server.run_stdio().await {
                tracing::error!(error=%e, "stdio server exited with error");
            }
        }
        Backend::Local => {
            let storage = new_local_storage(&args.root, cfg)?;
            // Prefer on-disk index when real Tantivy engine is enabled
            #[cfg(feature = "real_tantivy")]
            let index = {
                let p = format!("{}/index", &args.root);
                std::fs::create_dir_all(&p).ok();
                TantivyIndex::with_path(&p).unwrap_or_else(|_| TantivyIndex::new())
            };
            #[cfg(not(feature = "real_tantivy"))]
            let index = TantivyIndex::new();
            let mut options = ServerOptions::default();
            options.default_project = project.clone();
            #[cfg(feature = "encryption")]
            {
                if !encryption_recipients.is_empty() {
                    options.encryption_recipients = encryption_recipients.clone();
                }
            }
            let server = Server::new_with_options(storage, index, options);
            if args.http {
                if let Err(e) = server.run_http(&args.addr).await {
                    tracing::error!(error=%e, "http server exited with error");
                }
            } else if let Err(e) = server.run_stdio().await {
                tracing::error!(error=%e, "stdio server exited with error");
            }
        }
        Backend::Github => {
            let mut storage = match mcp_gitmem_storage_github::GithubStorage::new(&args.root) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error=%e, "failed to init github storage");
                    return Err(eyre!("failed to init github storage: {}", e));
                }
            };
            if let Some(cfg) = cfg {
                if let Some(gh) = &cfg.github {
                    if let Some(ms) = gh.commit_batch_ms {
                        storage.set_commit_batch_ms(ms);
                    }
                    if let Some(name) = gh.remote_name.clone() {
                        storage.set_remote_name(name);
                    }
                    if let Some(branch) = gh.device_branch.clone() {
                        if !branch.trim().is_empty() {
                            if let Err(e) = storage.configure_device_branch(&branch) {
                                tracing::warn!(error = %e, branch = %branch, "failed to set device branch from config");
                            }
                        }
                    }
                    if let Some(creds) = &gh.credentials {
                        use mcp_gitmem_storage_github::CredentialMode;
                        let mode = match creds.mode.as_deref() {
                            Some("userpass") => CredentialMode::UserPass,
                            Some("token") => CredentialMode::Token,
                            Some("ssh-agent") => CredentialMode::SshAgent,
                            _ => CredentialMode::Helper,
                        };
                        storage.set_credentials(
                            mode,
                            creds.username.clone(),
                            creds.secret_env.clone(),
                        );
                    }
                    // Configure auto-push from config
                    if let Some(true) = gh.auto_push {
                        if let Some(url) = gh.remote_url.clone() {
                            storage.enable_auto_push(url);
                            tracing::info!("auto-push enabled from config");
                        } else {
                            tracing::warn!("auto-push enabled in config but no remote_url specified");
                        }
                    }
                }
            }
            // Configure auto-push from CLI args (overrides config)
            if args.auto_push {
                if let Some(url) = args.remote_url.clone() {
                    storage.enable_auto_push(url);
                    tracing::info!("auto-push enabled from CLI args");
                } else {
                    tracing::warn!("--auto-push specified but no --remote-url provided");
                }
            }
            if let Ok(env_remote) = std::env::var("GITMEM_REMOTE_NAME") {
                if !env_remote.trim().is_empty() {
                    storage.set_remote_name(env_remote);
                }
            }
            // Env variable overrides config file
            if let Ok(env_branch) = std::env::var("GITMEM_DEVICE_BRANCH") {
                if !env_branch.trim().is_empty() {
                    if let Err(e) = storage.configure_device_branch(&env_branch) {
                        tracing::warn!(error = %e, branch = %env_branch, "failed to set device branch from env");
                    }
                }
            }
            #[cfg(feature = "real_tantivy")]
            let index = {
                let p = format!("{}/index", &args.root);
                std::fs::create_dir_all(&p).ok();
                TantivyIndex::with_path(&p).unwrap_or_else(|_| TantivyIndex::new())
            };
            #[cfg(not(feature = "real_tantivy"))]
            let index = TantivyIndex::new();
            let mut options = ServerOptions::default();
            options.default_project = project.clone();
            #[cfg(feature = "encryption")]
            {
                if !encryption_recipients.is_empty() {
                    options.encryption_recipients = encryption_recipients.clone();
                }
            }
            let server = Server::new_with_options(storage, index, options);
            if args.http {
                if let Err(e) = server.run_http(&args.addr).await {
                    tracing::error!(error=%e, "http server exited with error");
                }
            } else if let Err(e) = server.run_stdio().await {
                tracing::error!(error=%e, "stdio server exited with error");
            }
        }
    }
    Ok(())
}

async fn import_cmd(mut args: ImportArgs, cfg: Option<&AppConfig>) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};
    use mcp_gitmem_index_tantivy::TantivyIndex;
    // apply config defaults if present for import
    if let Some(cfg) = cfg {
        if let Some(s) = &cfg.import {
            if args.backend == Backend::Local {
                // allow overriding default backend
                if let Some(b) = s.backend.clone() {
                    args.backend = b;
                }
            }
            if args.root == "./data" {
                if let Some(r) = s.root.clone() {
                    args.root = r;
                }
            }
        }
        if let Some(d) = &cfg.default {
            if args.backend == Backend::Local {
                if let Some(b) = d.backend.clone() {
                    args.backend = b;
                }
            }
            if args.root == "./data" {
                if let Some(r) = d.root.clone() {
                    args.root = r;
                }
            }
        }
    }

    // Load records
    let path = &args.from;
    let mut mems = mcp_gitmem_compat::import_basic_from_path(path)
        .map_err(|e| color_eyre::eyre::eyre!("{}", e))?;
    // Optional type remapping
    if !args.map_types.is_empty() {
        let mut map: HashMap<String, String> = HashMap::new();
        for (k, v) in &args.map_types {
            map.insert(k.clone(), v.clone());
        }
        mcp_gitmem_compat::remap_types(&mut mems, &map);
    }
    // dedupe by id within file set
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let before_len = mems.len();
    mems.retain(|m| seen.insert(m.id.clone()));
    let deduped = before_len.saturating_sub(mems.len());
    let total = mems.len() as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap(),
    );

    let mut imported: u64 = 0;
    let mut errors: u64 = 0;
    let mut skipped_existing: u64 = 0;
    let project = sanitize_project_id(args.project.as_deref().unwrap_or(DEFAULT_PROJECT_ID));
    match args.backend {
        Backend::Ephemeral => {
            let storage = mcp_gitmem_storage_ephemeral::EphemeralStorage::new();
            let index = TantivyIndex::new();
            for m in mems {
                if args.dry_run {
                    imported += 1;
                    pb.inc(1);
                    continue;
                }
                if storage.get(&project, &m.id).unwrap_or(None).is_some() {
                    skipped_existing += 1;
                    pb.inc(1);
                    continue;
                }
                match storage.save(&project, &m).and_then(|_| {
                    index.update(&project, &m).map_err(|e| {
                        mcp_gitmem_storage_ephemeral::EphemeralError::NotFound(e.to_string())
                    })
                }) {
                    Ok(_) => imported += 1,
                    Err(_) => errors += 1,
                }
                pb.inc(1);
            }
        }
        Backend::Local => {
            let storage = new_local_storage(&args.root, cfg)?;
            #[cfg(feature = "real_tantivy")]
            let index = {
                let p = format!("{}/index", &args.root);
                std::fs::create_dir_all(&p).ok();
                TantivyIndex::with_path(&p).unwrap_or_else(|_| TantivyIndex::new())
            };
            #[cfg(not(feature = "real_tantivy"))]
            let index = TantivyIndex::new();
            for m in mems {
                if args.dry_run {
                    imported += 1;
                    pb.inc(1);
                    continue;
                }
                if storage.get(&project, &m.id).unwrap_or(None).is_some() {
                    skipped_existing += 1;
                    pb.inc(1);
                    continue;
                }
                match storage.save(&project, &m).and_then(|_| {
                    index
                        .update(&project, &m)
                        .map_err(|e| mcp_gitmem_storage_local::LocalError::Io(e.to_string()))
                }) {
                    Ok(_) => imported += 1,
                    Err(_) => errors += 1,
                }
                pb.inc(1);
            }
        }
        Backend::Github => {
            info!(
                "github backend import not fully implemented; using local working tree semantics"
            );
            let mut storage = mcp_gitmem_storage_github::GithubStorage::new(&args.root)
                .map_err(|e| color_eyre::eyre::eyre!("{}", e))?;
            if let Some(cfg) = cfg {
                if let Some(gh) = &cfg.github {
                    if let Some(ms) = gh.commit_batch_ms {
                        storage.set_commit_batch_ms(ms);
                    }
                    if let Some(name) = gh.remote_name.clone() {
                        storage.set_remote_name(name);
                    }
                    if let Some(creds) = &gh.credentials {
                        use mcp_gitmem_storage_github::CredentialMode;
                        let mode = match creds.mode.as_deref() {
                            Some("userpass") => CredentialMode::UserPass,
                            Some("token") => CredentialMode::Token,
                            Some("ssh-agent") => CredentialMode::SshAgent,
                            _ => CredentialMode::Helper,
                        };
                        storage.set_credentials(
                            mode,
                            creds.username.clone(),
                            creds.secret_env.clone(),
                        );
                    }
                }
            }
            let index = TantivyIndex::new();
            for m in mems {
                if args.dry_run {
                    imported += 1;
                    pb.inc(1);
                    continue;
                }
                if storage.get(&project, &m.id).unwrap_or(None).is_some() {
                    skipped_existing += 1;
                    pb.inc(1);
                    continue;
                }
                match storage.save(&project, &m).and_then(|_| {
                    index
                        .update(&project, &m)
                        .map_err(|e| mcp_gitmem_storage_github::GithubError::Io(e.to_string()))
                }) {
                    Ok(_) => imported += 1,
                    Err(_) => errors += 1,
                }
                pb.inc(1);
            }
            // flush batched commit
            storage
                .flush()
                .map_err(|e| color_eyre::eyre::eyre!("{}", e))?;
        }
    }

    pb.finish_with_message("done");
    println!(
        "Total input: {}\nDeduped (within input): {}\nSkipped existing: {}\nImported: {}\nErrors: {}",
        total + deduped as u64,
        deduped,
        skipped_existing,
        imported,
        errors
    );
    Ok(())
}

fn parse_kv(s: &str) -> std::result::Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err("expected key=value".to_string());
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

async fn sync_cmd(mut args: SyncArgs, cfg: Option<&AppConfig>) -> Result<()> {
    // apply config defaults if present for sync
    if let Some(cfg) = cfg {
        if let Some(s) = &cfg.sync {
            if args.backend == Backend::Github {
                if let Some(b) = s.backend.clone() {
                    args.backend = b;
                }
            }
            if args.root == "./repo" {
                if let Some(r) = s.root.clone() {
                    args.root = r;
                }
            }
            if args.remote == "origin" {
                if let Some(r) = s.remote.clone() {
                    args.remote = r;
                }
            }
            if args.branch.is_none() {
                args.branch = s.branch.clone();
            }
            if args.direction == "both" {
                if let Some(d) = s.direction.clone() {
                    args.direction = d;
                }
            }
        }
        if let Some(d) = &cfg.default {
            if args.root == "./repo" {
                if let Some(r) = d.root.clone() {
                    args.root = r;
                }
            }
        }
    }
    let codex_env = load_codex_gitmem_env();
    if let Some(env_map) = codex_env.as_ref() {
        tracing::debug!(?env_map, "codex gitmem env detected");
    } else {
        tracing::debug!("no codex gitmem env detected");
    }
    if args.remote == "origin" {
        if let Some(env_map) = codex_env.as_ref() {
            if let Some(remote) = env_map.get("GITMEM_REMOTE_NAME") {
                args.remote = remote.clone();
            }
        }
        if args.remote == "origin" {
            if let Ok(remote_env) = std::env::var("GITMEM_REMOTE_NAME") {
                if !remote_env.trim().is_empty() {
                    args.remote = remote_env;
                }
            }
        }
    }
    if args.branch.is_none() {
        if let Some(env_map) = codex_env.as_ref() {
            if let Some(branch) = env_map.get("GITMEM_DEVICE_BRANCH") {
                if !branch.trim().is_empty() {
                    args.branch = Some(branch.clone());
                }
            }
        }
        if args.branch.is_none() {
            if let Ok(env_branch) = std::env::var("GITMEM_DEVICE_BRANCH") {
                if !env_branch.trim().is_empty() {
                    args.branch = Some(env_branch);
                }
            }
        }
    }
    let project = sanitize_project_id(args.project.as_deref().unwrap_or(DEFAULT_PROJECT_ID));
    let dir = args.direction.to_lowercase();
    match args.backend {
        Backend::Github => {
            let mut storage = mcp_gitmem_storage_github::GithubStorage::new(&args.root)
                .map_err(|e| color_eyre::eyre::eyre!("{}", e))?;
            if let Some(cfg) = cfg {
                if let Some(gh) = &cfg.github {
                    if let Some(ms) = gh.commit_batch_ms {
                        storage.set_commit_batch_ms(ms);
                    }
                }
            }
            if let Some(branch) = args.branch.clone() {
                storage
                    .configure_device_branch(&branch)
                    .map_err(|e| color_eyre::eyre::eyre!("{}", e))?;
            } else if let Ok(env_branch) = std::env::var("GITMEM_DEVICE_BRANCH") {
                if !env_branch.trim().is_empty() {
                    storage
                        .configure_device_branch(&env_branch)
                        .map_err(|e| color_eyre::eyre::eyre!("{}", e))?;
                    args.branch = Some(env_branch);
                }
            }
            if dir == "pull" || dir == "both" {
                storage
                    .pull(&args.remote, args.branch.as_deref())
                    .map_err(|e| color_eyre::eyre::eyre!("pull failed: {}", e))?;
                println!("Pulled from {}", args.remote);
            }
            if dir == "push" || dir == "both" {
                storage
                    .push(&args.remote, args.branch.as_deref())
                    .map_err(|e| color_eyre::eyre::eyre!("push failed: {}", e))?;
                println!("Pushed to {}", args.remote);
            }
        }
        Backend::Local => {
            if dir == "external" {
                let storage = new_local_storage(&args.root, cfg)?;
                let paths = if args.paths.is_empty() {
                    None
                } else {
                    Some(args.paths.clone())
                };
                let reports = storage
                    .rescan_external_folders(&project, paths.as_deref())
                    .map_err(|e| eyre!("external sync failed: {}", e))?;
                if reports.is_empty() {
                    println!("No linked folders registered for project {}", project);
                } else {
                    for report in reports {
                        let path = report.display_path.as_deref().unwrap_or(&report.path);
                        println!(
                            "{}: scanned={} created={} updated={} deleted={} bytes={} runtime_ms={}{}",
                            path,
                            report.scanned,
                            report.created,
                            report.updated,
                            report.deleted,
                            report.total_bytes,
                            report.runtime_ms,
                            report
                                .last_error
                                .as_ref()
                                .map(|err| format!(" last_error={}", err))
                                .unwrap_or_default()
                        );
                    }
                }
            } else {
                println!("Nothing to sync for {:?}", args.backend);
            }
        }
        Backend::Ephemeral => {
            println!("Nothing to sync for {:?}", args.backend);
        }
    }
    Ok(())
}

fn apply_default_root(root: &mut String, cfg: Option<&AppConfig>, fallback: &str) {
    if let Some(cfg) = cfg {
        if let Some(d) = &cfg.default {
            if root == fallback {
                if let Some(r) = d.root.clone() {
                    *root = r;
                }
            }
        }
    }
}

fn ensure_local_backend(op: &str, backend: Backend) -> Result<()> {
    if backend != Backend::Local {
        return Err(eyre!("{} is supported only for the local backend", op));
    }
    Ok(())
}

fn link_folder_cmd(mut args: LinkFolderArgs, cfg: Option<&AppConfig>) -> Result<()> {
    apply_default_root(&mut args.root, cfg, "./data");
    ensure_local_backend("link-folder", args.backend)?;
    let project = sanitize_project_id(args.project.as_deref().unwrap_or(DEFAULT_PROJECT_ID));
    let storage = new_local_storage(&args.root, cfg)?;
    let include = if args.include.is_empty() {
        None
    } else {
        Some(args.include.clone())
    };
    let exclude = if args.exclude.is_empty() {
        None
    } else {
        Some(args.exclude.clone())
    };
    let mut info = storage
        .link_external_folder(
            &project,
            &args.path,
            include,
            exclude,
            args.watch_mode.as_deref(),
            args.poll_interval,
            args.jitter,
        )
        .map_err(|e| eyre!("link failed: {}", e))?;

    println!(
        "Linked {} -> {} (project {}, linkId={})",
        info.path, info.resolved_path, info.project, info.link_id
    );
    let watch = &info.watch;
    let platform_note = watch
        .platform()
        .map(|p| format!(" platform={}", p))
        .unwrap_or_default();
    println!(
        "  watch: mode={} poll={}ms jitter={}{}",
        watch.mode_str(),
        watch.poll_interval_ms(),
        watch.jitter_pct(),
        platform_note
    );

    if !args.no_rescan {
        let filters = vec![info.resolved_path.clone()];
        let reports = storage
            .rescan_external_folders(&project, Some(&filters))
            .map_err(|e| eyre!("rescan failed: {}", e))?;
        for report in reports {
            let path = report.display_path.as_deref().unwrap_or(&report.path);
            println!(
                "{}: scanned={} created={} updated={} deleted={} bytes={} runtime_ms={}{}",
                path,
                report.scanned,
                report.created,
                report.updated,
                report.deleted,
                report.total_bytes,
                report.runtime_ms,
                report
                    .last_error
                    .as_ref()
                    .map(|err| format!(" last_error={}", err))
                    .unwrap_or_default()
            );
        }
        if let Some(updated) = storage
            .list_external_folders(Some(&project))
            .map_err(|e| eyre!("refresh failed: {}", e))?
            .into_iter()
            .find(|entry| entry.link_id == info.link_id)
        {
            info = updated;
        }
    }

    println!(
        "  status: {} | files: {} | bytes: {} | last_scan: {} | last_runtime_ms: {}{}",
        info.status,
        info.file_count,
        info.total_bytes,
        info.last_scan.as_deref().unwrap_or("<never>"),
        info.last_runtime_ms
            .map(|ms| ms.to_string())
            .unwrap_or_else(|| "-".into()),
        info.last_error
            .as_ref()
            .map(|err| format!(" | last_error: {}", err))
            .unwrap_or_default()
    );
    Ok(())
}

fn unlink_folder_cmd(mut args: UnlinkFolderArgs, cfg: Option<&AppConfig>) -> Result<()> {
    apply_default_root(&mut args.root, cfg, "./data");
    ensure_local_backend("unlink-folder", args.backend)?;
    let project = sanitize_project_id(args.project.as_deref().unwrap_or(DEFAULT_PROJECT_ID));
    let storage = new_local_storage(&args.root, cfg)?;
    let removed = storage
        .unlink_external_folder(&project, args.path.as_deref())
        .map_err(|e| eyre!("unlink failed: {}", e))?;
    if removed.is_empty() {
        println!("No linked folders removed");
    } else {
        for path in removed {
            println!("Removed link: {}", path);
        }
    }
    Ok(())
}

fn list_links_cmd(mut args: ListLinksArgs, cfg: Option<&AppConfig>) -> Result<()> {
    apply_default_root(&mut args.root, cfg, "./data");
    ensure_local_backend("list-links", args.backend)?;
    let storage = new_local_storage(&args.root, cfg)?;
    let project = args.project.as_deref().map(sanitize_project_id);
    let links = storage
        .list_external_folders(project.as_ref())
        .map_err(|e| eyre!("list failed: {}", e))?;
    if links.is_empty() {
        println!("No linked folders found");
    } else {
        for link in links {
            let display = link.display_path.as_deref().unwrap_or(&link.path);
            println!(
                "{} -> {} (project {}, linkId={})",
                display, link.resolved_path, link.project, link.link_id
            );
            let watch = &link.watch;
            let platform_note = watch
                .platform()
                .map(|p| format!(" platform={}", p))
                .unwrap_or_default();
            println!(
                "  watch: mode={} poll={}ms jitter={}{}",
                watch.mode_str(),
                watch.poll_interval_ms(),
                watch.jitter_pct(),
                platform_note
            );
            println!(
                "  status: {} | files: {} | bytes: {} | last_scan: {} | last_runtime_ms: {}{}",
                link.status,
                link.file_count,
                link.total_bytes,
                link.last_scan.as_deref().unwrap_or("<never>"),
                link.last_runtime_ms
                    .map(|ms| ms.to_string())
                    .unwrap_or_else(|| "-".into()),
                link.last_error
                    .as_ref()
                    .map(|err| format!(" | last_error: {}", err))
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn rescan_links_cmd(mut args: RescanLinksArgs, cfg: Option<&AppConfig>) -> Result<()> {
    apply_default_root(&mut args.root, cfg, "./data");
    ensure_local_backend("rescan-links", args.backend)?;
    let project = sanitize_project_id(args.project.as_deref().unwrap_or(DEFAULT_PROJECT_ID));
    let storage = new_local_storage(&args.root, cfg)?;
    let paths = if args.paths.is_empty() {
        None
    } else {
        Some(args.paths.clone())
    };
    let reports = storage
        .rescan_external_folders(&project, paths.as_deref())
        .map_err(|e| eyre!("rescan failed: {}", e))?;
    if reports.is_empty() {
        println!("No linked folders registered for project {}", project);
    } else {
        for report in reports {
            let path = report.display_path.as_deref().unwrap_or(&report.path);
            println!(
                "{}: scanned={} created={} updated={} deleted={} bytes={} runtime_ms={}{}",
                path,
                report.scanned,
                report.created,
                report.updated,
                report.deleted,
                report.total_bytes,
                report.runtime_ms,
                report
                    .last_error
                    .as_ref()
                    .map(|err| format!(" last_error={}", err))
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

// -----------------
// Config handling

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SectionDefaults {
    backend: Option<Backend>,
    root: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SyncSection {
    backend: Option<Backend>,
    root: Option<String>,
    remote: Option<String>,
    branch: Option<String>,
    direction: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GithubCredentials {
    mode: Option<String>,
    username: Option<String>,
    secret_env: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GithubSection {
    commit_batch_ms: Option<u64>,
    remote_name: Option<String>,
    device_branch: Option<String>,
    credentials: Option<GithubCredentials>,
    auto_push: Option<bool>,
    remote_url: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct LocalWatchSection {
    mode: Option<String>,
    poll_interval_ms: Option<u64>,
    jitter_pct: Option<u32>,
    max_concurrent: Option<usize>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct LocalStorageSection {
    allow_outside_home: Option<bool>,
    #[serde(default)]
    watch: Option<LocalWatchSection>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StorageSection {
    #[serde(default)]
    local: Option<LocalStorageSection>,
}

#[cfg(feature = "encryption")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct EncryptionSection {
    enabled: Option<bool>,
    recipients: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AppConfig {
    #[serde(default)]
    default: Option<SectionDefaults>,
    #[serde(default)]
    serve: Option<SectionDefaults>,
    #[serde(default)]
    import: Option<SectionDefaults>,
    #[serde(default)]
    sync: Option<SyncSection>,
    #[serde(default)]
    github: Option<GithubSection>,
    #[serde(default)]
    storage: Option<StorageSection>,
    #[cfg(feature = "encryption")]
    #[serde(default)]
    encryption: Option<EncryptionSection>,
}

fn load_config(path: Option<&str>) -> Result<Option<AppConfig>> {
    let mut builder = config::Config::builder()
        .add_source(config::Environment::with_prefix("GITMEM").separator("__"));

    let mut has_sources = false;
    if let Some(raw) = path {
        let expanded = expand_path(raw);
        has_sources = true;
        if !expanded.exists() {
            tracing::warn!(
                path = expanded.display().to_string(),
                "config file not found; continuing with defaults and env overrides"
            );
        }
        builder = builder.add_source(config::File::from(expanded).required(false));
    }

    let cfg = builder
        .build()
        .map_err(|e| color_eyre::eyre::eyre!("config load error: {}", e))?;
    let parsed: AppConfig = cfg
        .try_deserialize()
        .map_err(|e| color_eyre::eyre::eyre!("config parse error: {}", e))?;
    if has_sources || parsed_has_values(&parsed) {
        return Ok(Some(parsed));
    }
    Ok(None)
}

fn expand_path(input: &str) -> PathBuf {
    if input == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from(input));
    }
    if let Some(rest) = input.strip_prefix("~/") {
        return home_dir()
            .map(|mut base| {
                base.push(rest);
                base
            })
            .unwrap_or_else(|| PathBuf::from(rest));
    }
    PathBuf::from(input)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

fn parsed_has_values(cfg: &AppConfig) -> bool {
    cfg.default.is_some()
        || cfg.serve.is_some()
        || cfg.import.is_some()
        || cfg.sync.is_some()
        || cfg.github.is_some()
        || cfg.storage.is_some()
        || {
            #[cfg(feature = "encryption")]
            {
                cfg.encryption.is_some()
            }
            #[cfg(not(feature = "encryption"))]
            {
                false
            }
        }
}

fn build_local_watch_config(cfg: Option<&AppConfig>) -> Result<Option<LocalWatchConfig>> {
    let storage_cfg = cfg.and_then(|c| c.storage.as_ref());
    let local_cfg = storage_cfg.and_then(|s| s.local.as_ref());
    let Some(local) = local_cfg else {
        return Ok(None);
    };

    let mut config = LocalWatchConfig::default();
    if let Some(allow) = local.allow_outside_home {
        config.set_allow_outside_home(allow);
    }
    if let Some(watch) = &local.watch {
        config
            .apply_overrides(
                watch.mode.as_deref(),
                watch.poll_interval_ms,
                watch.jitter_pct,
                watch.max_concurrent,
            )
            .map_err(|e: LocalStorageError| eyre!("invalid local.watch config: {}", e))?;
    }
    Ok(Some(config))
}

fn new_local_storage(root: &str, cfg: Option<&AppConfig>) -> Result<LocalStorage> {
    if let Some(config) = build_local_watch_config(cfg)? {
        Ok(LocalStorage::with_config(root, config))
    } else {
        Ok(LocalStorage::new(root))
    }
}

fn load_codex_gitmem_env() -> Option<HashMap<String, String>> {
    let mut path = home_dir()?;
    path.push(".codex");
    path.push("config.toml");
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(err) => {
            tracing::debug!(error = %err, path = %path.display(), "failed to read codex config");
            return None;
        }
    };
    let root: TomlValue = match toml::from_str(&contents) {
        Ok(v) => v,
        Err(err) => {
            tracing::debug!(error = %err, "failed to parse codex config");
            return None;
        }
    };
    let servers = match root.get("mcp_servers").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => {
            tracing::debug!("no mcp_servers entry in codex config");
            return None;
        }
    };
    let gitmem = match servers.get("gitmem").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => {
            tracing::debug!("codex config does not contain gitmem entry");
            return None;
        }
    };
    let env = match gitmem.get("env").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => {
            tracing::debug!("codex config gitmem entry missing env table");
            return None;
        }
    };
    let mut map = HashMap::new();
    for (key, value) in env {
        if let Some(v) = value.as_str() {
            map.insert(key.clone(), v.to_string());
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}
