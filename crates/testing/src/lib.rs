#[cfg(test)]
mod tests {
    use mcp_gitmem_core::{model::Memory, project::DEFAULT_PROJECT_ID, traits::Storage};
    use mcp_gitmem_storage_ephemeral::EphemeralStorage;

    #[test]
    fn ephemeral_round_trip() {
        let storage = EphemeralStorage::new();
        let mem = Memory::new("t", "c", "note");
        let id = mem.id.clone();
        storage.save(&DEFAULT_PROJECT_ID.to_string(), &mem).unwrap();
        let got = storage
            .get(&DEFAULT_PROJECT_ID.to_string(), &id)
            .unwrap()
            .unwrap();
        assert_eq!(got.title, "t");
    }
}

#[cfg(test)]
mod cli_tests {
    use assert_cmd::prelude::*;
    use std::{fs, path::PathBuf, process::Command};
    use tempfile::tempdir;

    #[test]
    fn import_into_local_repo_creates_files() {
        // Prepare JSONL
        let tmp = tempdir().unwrap();
        let src = tmp.path().join("data.jsonl");
        fs::write(
            &src,
            "{\"title\":\"t\",\"content\":\"c\",\"type\":\"note\"}\n",
        )
        .unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();

        let mut cmd = Command::cargo_bin("gitmem").unwrap();
        let assert = cmd
            .args(["import", "--from"])
            .arg(&src)
            .args(["--backend", "local", "--root"])
            .arg(&repo)
            .assert();
        assert.success();

        // verify files under memories/
        let memories = repo.join("memories");
        assert!(memories.exists());
        // ensure at least one json file exists deep inside
        fn find_json(dir: &PathBuf) -> bool {
            for entry in fs::read_dir(dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    if find_json(&p) {
                        return true;
                    }
                } else if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    return true;
                }
            }
            false
        }
        assert!(find_json(&memories));
    }

    #[test]
    fn import_github_and_sync_file_remote_roundtrip() {
        let tmp = tempdir().unwrap();
        let src = tmp.path().join("data.jsonl");
        fs::write(
            &src,
            "{\"title\":\"t\",\"content\":\"c\",\"type\":\"note\"}\n",
        )
        .unwrap();

        // working repo A
        let repo_a = tmp.path().join("repoA");
        fs::create_dir_all(&repo_a).unwrap();
        // remote dir
        let remote = tmp.path().join("remote");
        fs::create_dir_all(&remote).unwrap();
        let remote_uri = format!("file://{}", remote.display());

        // import into github backend (working tree mode)
        Command::cargo_bin("gitmem")
            .unwrap()
            .args(["import", "--from"])
            .arg(&src)
            .args(["--backend", "github", "--root"])
            .arg(&repo_a)
            .assert()
            .success();

        // push to remote file:// path
        Command::cargo_bin("gitmem")
            .unwrap()
            .args(["sync", "--backend", "github", "--root"])
            .arg(&repo_a)
            .args(["--remote"])
            .arg(&remote_uri)
            .args(["--direction", "push"])
            .assert()
            .success();

        // working repo B, pull from remote
        let repo_b = tmp.path().join("repoB");
        fs::create_dir_all(&repo_b).unwrap();
        Command::cargo_bin("gitmem")
            .unwrap()
            .args(["sync", "--backend", "github", "--root"])
            .arg(&repo_b)
            .args(["--remote"])
            .arg(&remote_uri)
            .args(["--direction", "pull"])
            .assert()
            .success();

        // verify repo B has memories
        let memories = repo_b.join("memories");
        assert!(memories.exists());
        fn find_json(dir: &PathBuf) -> bool {
            for entry in fs::read_dir(dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    if find_json(&p) {
                        return true;
                    }
                } else if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    return true;
                }
            }
            false
        }
        assert!(find_json(&memories));
    }

    #[test]
    fn import_many_local_jsonl_succeeds() {
        let tmp = tempdir().unwrap();
        // prepare JSONL with 1000 records
        let src = tmp.path().join("many.jsonl");
        let mut buf = String::new();
        for i in 0..1000 {
            buf.push_str(&format!(
                "{{\"title\":\"t{}\",\"content\":\"c{}\",\"type\":\"note\"}}\n",
                i, i
            ));
        }
        fs::write(&src, buf).unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();

        let output = Command::cargo_bin("gitmem")
            .unwrap()
            .args(["import", "--from"])
            .arg(&src)
            .args(["--backend", "local", "--root"])
            .arg(&repo)
            .output()
            .unwrap();
        assert!(output.status.success());
        let s = String::from_utf8_lossy(&output.stdout);
        assert!(
            s.contains("Imported: 1000"),
            "summary missing or incorrect: {}",
            s
        );
    }
}

#[cfg(test)]
mod conformance {
    use assert_cmd::cargo::cargo_bin;
    use insta::assert_yaml_snapshot;
    use mcp_gitmem_proto as proto;
    use rmcp::{
        model::{CallToolRequestParam, CallToolResult, ClientInfo},
        service::{serve_client, Peer, QuitReason, RoleClient, RunningService},
        transport::TokioChildProcess,
    };
    use serde_json::{json, Value};
    use std::borrow::Cow;
    use tokio::{process::Command, runtime::Builder};

    #[cfg(feature = "remote-git")]
    use {
        std::{
            fs,
            path::Path,
            process::Command as StdCommand,
            sync::Once,
            time::{SystemTime, UNIX_EPOCH},
        },
        tempfile::tempdir,
    };

    fn runtime() -> tokio::runtime::Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime")
    }

    fn fixture_path(rel: &str) -> std::path::PathBuf {
        let base = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        std::path::Path::new(&base).join("fixtures").join(rel)
    }

    async fn spawn_ephemeral_service() -> RunningService<RoleClient, ClientInfo> {
        let mut cmd = Command::new(cargo_bin("gitmem"));
        cmd.args(["serve", "--backend", "ephemeral"]);
        let transport = TokioChildProcess::new(cmd).expect("spawn gitmem serve");
        let mut client_info = ClientInfo::default();
        client_info.client_info.name = "mcp-gitmem-testing".into();
        client_info.client_info.version = env!("CARGO_PKG_VERSION").into();
        serve_client(client_info, transport)
            .await
            .expect("rmcp initialize")
    }

    #[cfg(feature = "remote-git")]
    fn ensure_gitmem_remote_git_built() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let status = StdCommand::new("cargo")
                .args([
                    "build",
                    "-p",
                    "mcp-gitmem-cli",
                    "--bin",
                    "gitmem",
                    "--features",
                    "remote-git",
                ])
                .status()
                .expect("cargo build --features remote-git should run");
            assert!(status.success(), "gitmem build with remote-git failed");
        });
    }

    #[cfg(feature = "remote-git")]
    async fn spawn_github_service(
        root: &Path,
        extra_env: &[(&str, &str)],
    ) -> RunningService<RoleClient, ClientInfo> {
        let mut cmd = Command::new(cargo_bin("gitmem"));
        cmd.args(["serve", "--backend", "github", "--root"])
            .arg(root);
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        let transport = TokioChildProcess::new(cmd).expect("spawn gitmem github");
        let mut client_info = ClientInfo::default();
        client_info.client_info.name = "mcp-gitmem-testing".into();
        client_info.client_info.version = env!("CARGO_PKG_VERSION").into();
        serve_client(client_info, transport)
            .await
            .expect("rmcp initialize")
    }

    #[cfg(feature = "remote-git")]
    fn unique_branch_name() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("devices/test-sync-{nanos}")
    }

    fn extract_payload(result: &CallToolResult) -> Value {
        if let Some(structured) = result.structured_content.clone() {
            return structured;
        }
        if let Some(entry) = result.content.first() {
            if let Some(text) = entry.as_text() {
                if let Ok(value) = serde_json::from_str::<Value>(&text.text) {
                    return value;
                }
            }
        }
        Value::Null
    }

    async fn call_tool_json(peer: &Peer<RoleClient>, name: &str, arguments: Value) -> Value {
        let arguments_map = arguments
            .as_object()
            .cloned()
            .unwrap_or_else(serde_json::Map::new);
        let result = peer
            .call_tool(CallToolRequestParam {
                name: Cow::Owned(name.to_string()),
                arguments: Some(arguments_map),
            })
            .await
            .expect("tools.call request should succeed");
        extract_payload(&result)
    }

    #[test]
    fn mcp_conformance_basic_import_and_search_shapes() {
        runtime().block_on(async {
            let service = spawn_ephemeral_service().await;
            let peer = service.peer().clone();

            let tools = peer
                .list_tools(None)
                .await
                .expect("list tools should succeed");
            let save_name = proto::exported_tool_name(proto::TOOL_MEMORY_SAVE);
            assert!(
                tools
                    .tools
                    .iter()
                    .any(|tool| tool.name.as_ref() == save_name),
                "memory.save tool missing"
            );

            let saves = [
                ("alpha", "first note", "note", &["a", "x"][..]),
                ("beta", "second fact", "fact", &["b"][..]),
                ("gamma", "another note", "note", &["a", "c"][..]),
            ];
            for (title, content, typ, tags) in saves {
                let payload = call_tool_json(
                    &peer,
                    &save_name,
                    json!({
                        "title": title,
                        "content": content,
                        "type": typ,
                        "tags": tags,
                    }),
                )
                .await;
                assert_eq!(payload.get("title").and_then(Value::as_str), Some(title));
            }

            let search_name = proto::exported_tool_name(proto::TOOL_MEMORY_SEARCH);
            let search_payload = call_tool_json(
                &peer,
                &search_name,
                json!({
                    "query": "",
                    "sort": "recency"
                }),
            )
            .await;
            let items = search_payload
                .get("items")
                .and_then(Value::as_array)
                .expect("items array");
            let slim: Vec<Value> = items
                .iter()
                .map(|item| {
                    json!({
                        "title": item.get("title").unwrap(),
                        "type": item.get("type").unwrap(),
                        "tags": item.get("tags").unwrap(),
                    })
                })
                .collect();
            assert_yaml_snapshot!("search_slim_items", slim);

            match service.cancel().await {
                Ok(QuitReason::Cancelled | QuitReason::Closed) => {}
                other => panic!("unexpected cancel result: {other:?}"),
            }
        });
    }

    #[test]
    fn mcp_conformance_import_basic_summary() {
        runtime().block_on(async {
            let service = spawn_ephemeral_service().await;
            let peer = service.peer().clone();

            let tools = peer
                .list_tools(None)
                .await
                .expect("list tools should succeed");
            let import_name = proto::exported_tool_name(proto::TOOL_MEMORY_IMPORT_BASIC);
            assert!(
                tools
                    .tools
                    .iter()
                    .any(|tool| tool.name.as_ref() == import_name),
                "memory.import.basic tool missing"
            );

            let path = fixture_path("compat_basic/records.jsonl");
            let payload = call_tool_json(
                &peer,
                &import_name,
                json!({
                    "path": path,
                    "dry_run": false
                }),
            )
            .await;
            assert_eq!(payload.get("imported").and_then(Value::as_u64), Some(3));
            assert_eq!(payload.get("errors").and_then(Value::as_u64), Some(0));

            let tools = peer
                .list_tools(None)
                .await
                .expect("list tools should succeed");
            let search_exported = proto::exported_tool_name(proto::TOOL_SEARCH_NOTES);
            let tool_names: Vec<_> = tools
                .tools
                .iter()
                .map(|tool| tool.name.as_ref().to_string())
                .collect();
            assert!(
                tool_names.iter().any(|name| name == &search_exported),
                "search_notes tool missing from list; available: {tool_names:?}"
            );

            let search_payload = call_tool_json(
                &peer,
                &search_exported,
                json!({
                    "query": "",
                    "limit": 10
                }),
            )
            .await;
            let notes = search_payload
                .get("notes")
                .and_then(Value::as_array)
                .expect("notes array missing");
            let mut canonical: Vec<Value> = notes
                .iter()
                .map(|note| {
                    json!({
                        "id": note.get("id").unwrap(),
                        "title": note.get("title").unwrap(),
                        "type": note.get("type").unwrap(),
                        "tags": note.get("tags").unwrap(),
                    })
                })
                .collect();
            canonical.sort_by(|a, b| {
                a.get("id")
                    .and_then(Value::as_str)
                    .cmp(&b.get("id").and_then(Value::as_str))
            });
            assert_yaml_snapshot!("import_fixture_notes", canonical);

            match service.cancel().await {
                Ok(QuitReason::Cancelled | QuitReason::Closed) => {}
                other => panic!("unexpected cancel result: {other:?}"),
            }
        });
    }

    #[test]
    fn mcp_conformance_multi_project_listing_and_fetch() {
        runtime().block_on(async {
            let service = spawn_ephemeral_service().await;
            let peer = service.peer().clone();

            let alpha = call_tool_json(
                &peer,
                &proto::exported_tool_name(proto::TOOL_MEMORY_SAVE),
                json!({
                    "title": "alpha note",
                    "content": "content for alpha note",
                    "type": "note",
                    "project": "alpha"
                }),
            )
            .await;
            let beta = call_tool_json(
                &peer,
                &proto::exported_tool_name(proto::TOOL_MEMORY_SAVE),
                json!({
                    "title": "beta note",
                    "content": "content for beta note",
                    "type": "note",
                    "project": "beta"
                }),
            )
            .await;

            let projects = call_tool_json(
                &peer,
                &proto::exported_tool_name(proto::TOOL_LIST_MEMORY_PROJECTS),
                json!({}),
            )
            .await;
            let ids: Vec<_> = projects
                .get("projects")
                .and_then(Value::as_array)
                .expect("projects array")
                .iter()
                .map(|p| p.get("id").and_then(Value::as_str).unwrap().to_string())
                .collect();
            let mut sorted_ids = ids.clone();
            sorted_ids.sort();
            assert_eq!(sorted_ids, vec!["alpha".to_string(), "beta".to_string()]);

            let list_alpha = call_tool_json(
                &peer,
                &proto::exported_tool_name(proto::TOOL_LIST_DIRECTORY),
                json!({"project": "alpha"}),
            )
            .await;
            let entries_alpha = list_alpha
                .get("entries")
                .and_then(Value::as_array)
                .expect("entries array (alpha)");
            assert_eq!(entries_alpha.len(), 1);
            let alpha_entry = &entries_alpha[0];
            assert_eq!(alpha_entry.get("kind"), Some(&Value::String("file".into())));
            assert_eq!(
                alpha_entry.get("name").and_then(Value::as_str),
                alpha.get("id").and_then(Value::as_str)
            );

            let list_beta = call_tool_json(
                &peer,
                &proto::exported_tool_name(proto::TOOL_LIST_DIRECTORY),
                json!({"project": "beta"}),
            )
            .await;
            let entries_beta = list_beta
                .get("entries")
                .and_then(Value::as_array)
                .expect("entries array (beta)");
            assert_eq!(entries_beta.len(), 1);
            let beta_entry = &entries_beta[0];
            assert_eq!(beta_entry.get("kind"), Some(&Value::String("file".into())));
            assert_eq!(
                beta_entry.get("name").and_then(Value::as_str),
                beta.get("id").and_then(Value::as_str)
            );

            let alpha_id = alpha.get("id").and_then(Value::as_str).unwrap();
            let fetched_alpha = call_tool_json(
                &peer,
                &proto::exported_tool_name(proto::TOOL_FETCH),
                json!({"id": alpha_id, "project": "alpha"}),
            )
            .await;
            assert_eq!(
                fetched_alpha.get("project"),
                Some(&Value::String("alpha".into()))
            );
            assert_eq!(
                fetched_alpha.get("title"),
                Some(&Value::String("alpha note".into()))
            );
            assert_eq!(
                fetched_alpha.get("id"),
                Some(&Value::String(alpha_id.into()))
            );

            let beta_id = beta.get("id").and_then(Value::as_str).unwrap();
            let fetched_beta = call_tool_json(
                &peer,
                &proto::exported_tool_name(proto::TOOL_FETCH),
                json!({"id": beta_id, "project": "beta"}),
            )
            .await;
            assert_eq!(
                fetched_beta.get("project"),
                Some(&Value::String("beta".into()))
            );
            assert_eq!(
                fetched_beta.get("title"),
                Some(&Value::String("beta note".into()))
            );
            assert_eq!(fetched_beta.get("id"), Some(&Value::String(beta_id.into())));

            match service.cancel().await {
                Ok(QuitReason::Cancelled | QuitReason::Closed) => {}
                other => panic!("unexpected cancel result: {other:?}"),
            }
        });
    }

    #[cfg(feature = "remote-git")]
    #[test]
    fn mcp_conformance_memory_sync_bootstraps_remote_branch() {
        runtime().block_on(async {
            ensure_gitmem_remote_git_built();

            let tmp = tempdir().unwrap();
            let repo_root = tmp.path().join("repo");
            fs::create_dir_all(&repo_root).unwrap();
            let remote_path = tmp.path().join("remote.git");

            let status = StdCommand::new("git")
                .args(["init", "--bare"])
                .arg(&remote_path)
                .status()
                .expect("git init --bare should succeed");
            assert!(status.success(), "failed to initialise bare remote repo");

            let remote_uri = remote_path.to_string_lossy().to_string();
            let branch = unique_branch_name();
            let service = spawn_github_service(
                &repo_root,
                [("GITMEM_DEVICE_BRANCH", branch.as_str())].as_ref(),
            )
            .await;
            let peer = service.peer().clone();

            let save_tool = proto::exported_tool_name(proto::TOOL_MEMORY_SAVE);
            call_tool_json(
                &peer,
                &save_tool,
                json!({
                    "title": "remote sync note",
                    "content": "body",
                    "type": "note"
                }),
            )
            .await;

            let sync_tool = proto::exported_tool_name(proto::TOOL_MEMORY_SYNC);
            let payload = call_tool_json(
                &peer,
                &sync_tool,
                json!({
                    "direction": "both",
                    "remote": remote_uri,
                    "branch": branch.clone()
                }),
            )
            .await;
            assert_eq!(payload.get("ok"), Some(&Value::Bool(true)));

            match service.cancel().await {
                Ok(QuitReason::Cancelled | QuitReason::Closed) => {}
                other => panic!("unexpected cancel result: {other:?}"),
            }

            let branch_ref = format!("refs/heads/{}", branch);
            let status = StdCommand::new("git")
                .arg("--git-dir")
                .arg(&remote_path)
                .arg("show-ref")
                .arg(&branch_ref)
                .status()
                .expect("git show-ref should run");
            assert!(status.success(), "remote branch not created");
        });
    }
}
