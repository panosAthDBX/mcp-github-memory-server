use mcp_gitmem_core::{
    model::Memory,
    project::ProjectId,
    traits::{Index, SearchParams, SearchResult, SearchResults},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TantivyIndexError {
    #[error("internal: {0}")]
    Internal(String),
}

// Default: milli-core-backed index for portability and Apple Silicon compatibility
#[cfg(not(feature = "real_tantivy"))]
mod engine {
    use super::*;
    use bumpalo::Bump;
    use milli_core::documents::documents_batch_reader_from_objects;
    use milli_core::heed::{EnvOpenOptions, RwTxn};
    use milli_core::progress::Progress;
    use milli_core::score_details::ScoreDetails;
    use milli_core::update::{
        self, IndexDocuments, IndexDocumentsConfig, IndexDocumentsMethod, IndexerConfig, Settings,
    };
    use milli_core::vector::EmbeddingConfigs;
    use milli_core::{
        AscDesc, Filter as MilliFilter, FilterableAttributesRule, Index as MilliIndex, Search,
        ThreadPoolNoAbortBuilder,
    };
    use parking_lot::RwLock;
    use serde_json::{Map as JsonMap, Number, Value};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::sync::Arc;
    use tempfile::TempDir;

    const LMDB_MAX_DBS: u32 = 25;
    const DEFAULT_MAP_SIZE_BYTES: usize = 512 * 1024 * 1024; // 512 MiB per project

    #[derive(Clone)]
    struct Doc {
        id: String,
        title: String,
        content: String,
        tags: Vec<String>,
        r#type: String,
        score: Option<f32>,
    }

    struct MemoryProject {
        docs: RwLock<HashMap<String, Doc>>,
    }

    impl MemoryProject {
        fn new() -> Self {
            Self {
                docs: RwLock::new(HashMap::new()),
            }
        }

        fn update(&self, memory: &Memory) -> Result<(), TantivyIndexError> {
            let doc = Doc {
                id: memory.id.clone(),
                title: memory.title.clone(),
                content: memory.content.clone(),
                tags: memory.tags.clone(),
                r#type: memory.r#type.clone(),
                score: memory.score,
            };
            self.docs.write().insert(doc.id.clone(), doc);
            Ok(())
        }

        fn delete(&self, id: &str) -> Result<(), TantivyIndexError> {
            self.docs.write().remove(id);
            Ok(())
        }

        fn search(&self, params: &SearchParams) -> Result<SearchResults, TantivyIndexError> {
            let q = params.query.to_lowercase();
            let types = params.types.as_ref();
            let tags_filter = params.tags.as_ref();
            let limit = params.limit.unwrap_or(50) as usize;
            let offset = params.offset.unwrap_or(0) as usize;

            let docs = self.docs.read();
            let mut scored: Vec<(f32, &Doc)> = Vec::new();
            for doc in docs.values() {
                if let Some(tl) = types {
                    if !tl.is_empty() && !tl.iter().any(|t| t == &doc.r#type) {
                        continue;
                    }
                }
                if let Some(tf) = tags_filter {
                    if !tf.is_empty() && !tf.iter().any(|t| doc.tags.iter().any(|dt| dt == t)) {
                        continue;
                    }
                }
                let title_hit = if q.is_empty() {
                    0.0
                } else {
                    (doc.title.to_lowercase().contains(&q)) as i32 as f32
                };
                let content_hit = if q.is_empty() {
                    0.0
                } else {
                    (doc.content.to_lowercase().contains(&q)) as i32 as f32
                };
                let tag_hit = if q.is_empty() {
                    0.0
                } else {
                    (doc.tags.iter().any(|t| t.to_lowercase().contains(&q))) as i32 as f32
                };
                let base = doc.score.unwrap_or(0.0);
                let score = base + title_hit * 2.0 + content_hit + tag_hit * 0.5;
                if q.is_empty() || score > 0.0 {
                    scored.push((score, doc));
                }
            }
            scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            let total = scored.len() as u64;
            let items = scored
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|(score, doc)| SearchResult {
                    id: doc.id.clone(),
                    score: Some(score),
                })
                .collect();
            Ok(SearchResults { items, total })
        }
    }

    enum ProjectBackend {
        Milli(Arc<ProjectHandle>),
        Memory(Arc<MemoryProject>),
    }

    impl Clone for ProjectBackend {
        fn clone(&self) -> Self {
            match self {
                Self::Milli(handle) => Self::Milli(Arc::clone(handle)),
                Self::Memory(mem) => Self::Memory(Arc::clone(mem)),
            }
        }
    }

    fn is_permission_error(err: &TantivyIndexError) -> bool {
        matches!(
            err,
            TantivyIndexError::Internal(msg)
                if msg.contains("Operation not permitted") || msg.contains("Permission denied")
        )
    }

    pub struct TantivyIndex {
        root: PathBuf,
        _temp_dir: Option<TempDir>,
        projects: RwLock<HashMap<ProjectId, ProjectBackend>>,
    }

    struct ProjectHandle {
        project: ProjectId,
        index: MilliIndex,
        indexer_config: IndexerConfig,
        index_documents_config: IndexDocumentsConfig,
    }

    impl TantivyIndex {
        #[must_use]
        pub fn new() -> Self {
            let temp_dir = TempDir::new().expect("tempdir");
            Self {
                root: temp_dir.path().to_path_buf(),
                _temp_dir: Some(temp_dir),
                projects: RwLock::new(HashMap::new()),
            }
        }

        pub fn with_path<P: AsRef<Path>>(path: P) -> Result<Self, TantivyIndexError> {
            let path = path.as_ref();
            std::fs::create_dir_all(path)
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            Ok(Self {
                root: path.to_path_buf(),
                _temp_dir: None,
                projects: RwLock::new(HashMap::new()),
            })
        }

        fn backend(&self, project: &ProjectId) -> Result<ProjectBackend, TantivyIndexError> {
            if let Some(existing) = self.projects.read().get(project) {
                return Ok(existing.clone());
            }
            let mut write_guard = self.projects.write();
            if let Some(existing) = write_guard.get(project) {
                return Ok(existing.clone());
            }
            let path = self.root.join(project);
            match ProjectHandle::create(project.clone(), path) {
                Ok(handle) => {
                    let backend = ProjectBackend::Milli(Arc::new(handle));
                    write_guard.insert(project.clone(), backend.clone());
                    Ok(backend)
                }
                Err(err) => {
                    if is_permission_error(&err) {
                        let backend = ProjectBackend::Memory(Arc::new(MemoryProject::new()));
                        write_guard.insert(project.clone(), backend.clone());
                        Ok(backend)
                    } else {
                        Err(err)
                    }
                }
            }
        }
    }

    impl Default for TantivyIndex {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ProjectHandle {
        fn create(project: ProjectId, path: PathBuf) -> Result<Self, TantivyIndexError> {
            std::fs::create_dir_all(&path)
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;

            let options = EnvOpenOptions::new();
            let mut options = options.read_txn_without_tls();
            options.map_size(DEFAULT_MAP_SIZE_BYTES);
            options.max_dbs(LMDB_MAX_DBS);

            let index = MilliIndex::new(options, &path, true)
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            let indexer_config = IndexerConfig::default();
            let index_documents_config = IndexDocumentsConfig {
                update_method: IndexDocumentsMethod::UpdateDocuments,
                autogenerate_docids: false,
                ..IndexDocumentsConfig::default()
            };

            let mut wtxn = index
                .write_txn()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            {
                let mut settings = Settings::new(&mut wtxn, &index, &indexer_config);
                settings.set_primary_key("id".to_string());
                settings.set_searchable_fields(vec![
                    "title".to_string(),
                    "content".to_string(),
                    "tags".to_string(),
                    "type".to_string(),
                ]);
                settings.set_displayed_fields(vec![
                    "id".to_string(),
                    "title".to_string(),
                    "content".to_string(),
                    "tags".to_string(),
                    "type".to_string(),
                    "project".to_string(),
                    "score".to_string(),
                    "created_at".to_string(),
                    "updated_at".to_string(),
                ]);
                settings.set_filterable_fields(vec![
                    FilterableAttributesRule::Field("type".to_string()),
                    FilterableAttributesRule::Field("tags".to_string()),
                    FilterableAttributesRule::Field("project".to_string()),
                    FilterableAttributesRule::Field("created_at".to_string()),
                    FilterableAttributesRule::Field("updated_at".to_string()),
                ]);
                settings.set_sortable_fields(
                    ["updated_at".to_string(), "created_at".to_string()]
                        .into_iter()
                        .collect(),
                );
                settings
                    .execute(|_| {}, || false)
                    .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            }
            wtxn.commit()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;

            Ok(Self {
                project,
                index,
                indexer_config,
                index_documents_config,
            })
        }

        fn upsert(&self, memory: &Memory) -> Result<(), TantivyIndexError> {
            let mut object = JsonMap::new();
            object.insert("id".into(), Value::String(memory.id.clone()));
            object.insert("title".into(), Value::String(memory.title.clone()));
            object.insert("content".into(), Value::String(memory.content.clone()));
            object.insert("type".into(), Value::String(memory.r#type.clone()));
            object.insert(
                "tags".into(),
                Value::Array(
                    memory
                        .tags
                        .iter()
                        .map(|t| Value::String(t.clone()))
                        .collect(),
                ),
            );
            if let Some(score) = memory.score {
                if let Some(number) = Number::from_f64(score as f64) {
                    object.insert("score".into(), Value::Number(number));
                }
            }
            object.insert("project".into(), Value::String(self.project.clone()));
            object.insert(
                "created_at".into(),
                Value::Number(Number::from(memory.created_at.timestamp())),
            );
            object.insert(
                "updated_at".into(),
                Value::Number(Number::from(memory.updated_at.timestamp())),
            );

            let reader = documents_batch_reader_from_objects([object]);

            let mut wtxn = self
                .index
                .write_txn()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            let builder = IndexDocuments::new(
                &mut wtxn,
                &self.index,
                &self.indexer_config,
                self.index_documents_config.clone(),
                |_| {},
                || false,
            )
            .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            let (builder, addition_result) = builder
                .add_documents(reader)
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            if let Err(user_error) = addition_result {
                return Err(TantivyIndexError::Internal(user_error.to_string()));
            }
            builder
                .execute()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            wtxn.commit()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            Ok(())
        }

        fn delete(&self, external_id: &str) -> Result<(), TantivyIndexError> {
            let mut wtxn = self
                .index
                .write_txn()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            self.delete_batch(&mut wtxn, &[external_id.to_string()])?;
            wtxn.commit()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            Ok(())
        }

        fn delete_batch(
            &self,
            wtxn: &mut RwTxn<'_>,
            external_document_ids: &[String],
        ) -> Result<(), TantivyIndexError> {
            if external_document_ids.is_empty() {
                return Ok(());
            }

            let rtxn = self
                .index
                .read_txn()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            let db_fields_ids_map = self
                .index
                .fields_ids_map(&rtxn)
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            let mut new_fields_ids_map = db_fields_ids_map.clone();

            let embedders = EmbeddingConfigs::default();

            let mut operation = update::new::indexer::DocumentOperation::new();
            let borrowed: Vec<_> = external_document_ids.iter().map(|s| s.as_str()).collect();
            operation.delete_documents(borrowed.as_slice());

            let alloc = Bump::new();
            let (document_changes, stats, primary_key) = operation
                .into_changes(
                    &alloc,
                    &self.index,
                    &rtxn,
                    None,
                    &mut new_fields_ids_map,
                    &|| false,
                    Progress::default(),
                )
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;

            if let Some(err) = stats.into_iter().find_map(|stat| stat.error) {
                return Err(TantivyIndexError::Internal(err.to_string()));
            }

            let pool = ThreadPoolNoAbortBuilder::new()
                .build()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            update::new::indexer::index(
                wtxn,
                &self.index,
                &pool,
                self.indexer_config.grenad_parameters(),
                &db_fields_ids_map,
                new_fields_ids_map,
                primary_key,
                &document_changes,
                embedders,
                &|| false,
                &Progress::default(),
            )
            .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            Ok(())
        }

        fn search(&self, params: &SearchParams) -> Result<SearchResults, TantivyIndexError> {
            let rtxn = self
                .index
                .read_txn()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            let mut search = Search::new(&rtxn, &self.index);
            let mut filter_backing: Vec<*mut str> = Vec::new();

            if !params.query.trim().is_empty() {
                search.query(params.query.trim());
            }
            if let Some(offset) = params.offset {
                search.offset(offset as usize);
            }
            if let Some(limit) = params.limit {
                search.limit(limit as usize);
            } else {
                search.limit(50);
            }

            if let Some(sort_expr) = params.sort.as_ref() {
                let mut crit = Vec::new();
                for part in sort_expr
                    .split(',')
                    .map(|p| p.trim())
                    .filter(|p| !p.is_empty())
                {
                    match AscDesc::from_str(part) {
                        Ok(value) => crit.push(value),
                        Err(err) => return Err(TantivyIndexError::Internal(err.to_string())),
                    }
                }
                if !crit.is_empty() {
                    search.sort_criteria(crit);
                }
            }

            if let Some(filter_expr) = build_filter(params)? {
                let boxed = filter_expr.into_boxed_str();
                let raw = Box::into_raw(boxed);
                let filter_candidate = MilliFilter::from_str(unsafe { &*raw })
                    .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
                if let Some(filter) = filter_candidate {
                    search.filter(filter);
                    filter_backing.push(raw);
                } else {
                    unsafe {
                        drop(Box::from_raw(raw));
                    }
                }
            }

            let result = search
                .execute()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;

            let external_ids = self
                .index
                .external_id_of(&rtxn, result.documents_ids.clone())
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;

            let mut items = Vec::with_capacity(result.documents_ids.len());
            for (external_id_res, score_details) in
                external_ids.into_iter().zip(result.document_scores)
            {
                let id = external_id_res.map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
                let score = score_from_details(&score_details);
                items.push(SearchResult { id, score });
            }

            let total = result.candidates.len();
            for ptr in filter_backing {
                unsafe {
                    drop(Box::from_raw(ptr));
                }
            }
            Ok(SearchResults { items, total })
        }
    }

    fn build_filter(params: &SearchParams) -> Result<Option<String>, TantivyIndexError> {
        let mut expressions = Vec::new();

        if let Some(types) = params.types.as_ref() {
            if !types.is_empty() {
                let or_clause: Vec<String> = types
                    .iter()
                    .map(|ty| format!("type = {}", quote_value(ty)))
                    .collect();
                expressions.push(format!("({})", or_clause.join(" OR ")));
            }
        }

        if let Some(tags) = params.tags.as_ref() {
            for tag in tags {
                expressions.push(format!("tags = {}", quote_value(tag)));
            }
        }

        if let Some(from) = params.from_time {
            expressions.push(format!("updated_at >= {}", from.timestamp()));
        }

        if let Some(to) = params.to_time {
            expressions.push(format!("updated_at <= {}", to.timestamp()));
        }

        if expressions.is_empty() {
            return Ok(None);
        }

        Ok(Some(expressions.join(" AND ")))
    }

    fn score_from_details(details: &[ScoreDetails]) -> Option<f32> {
        use milli_core::score_details::Rank;

        let ranks: Vec<Rank> = details.iter().filter_map(|d| d.rank()).collect();
        if ranks.is_empty() {
            None
        } else {
            Some(Rank::global_score(ranks.into_iter()) as f32)
        }
    }

    fn quote_value(value: &str) -> String {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{}\"", escaped)
    }

    impl Index for TantivyIndex {
        type Error = TantivyIndexError;

        fn update(&self, project: &ProjectId, memory: &Memory) -> Result<(), Self::Error> {
            match self.backend(project)? {
                ProjectBackend::Milli(handle) => handle.upsert(memory),
                ProjectBackend::Memory(mem) => mem.update(memory),
            }
        }

        fn delete(&self, project: &ProjectId, id: &str) -> Result<(), Self::Error> {
            match self.backend(project)? {
                ProjectBackend::Milli(handle) => handle.delete(id),
                ProjectBackend::Memory(mem) => mem.delete(id),
            }
        }

        fn search(
            &self,
            project: &ProjectId,
            params: &SearchParams,
        ) -> Result<SearchResults, Self::Error> {
            match self.backend(project)? {
                ProjectBackend::Milli(handle) => handle.search(params),
                ProjectBackend::Memory(mem) => mem.search(params),
            }
        }
    }
}

// Real Tantivy-backed engine (behind feature flag)
#[cfg(feature = "real_tantivy")]
mod engine {
    use super::*;
    use std::path::Path;
    use tantivy::query::{AllQuery, BooleanQuery, Occur, Query, RangeQuery, TermQuery};
    use tantivy::{
        doc,
        schema::{IndexRecordOption, Schema, INDEXED, STORED, TEXT},
        Index, IndexReader, IndexWriter, ReloadPolicy, Term,
    };

    pub struct TantivyIndex {
        index: Index,
        writer: RwLock<IndexWriter>,
        reader: RwLock<IndexReader>,
        id_f: tantivy::schema::Field,
        title_f: tantivy::schema::Field,
        content_f: tantivy::schema::Field,
        tags_f: tantivy::schema::Field,
        type_f: tantivy::schema::Field,
        score_f: tantivy::schema::Field,
        created_ts_f: tantivy::schema::Field,
        updated_ts_f: tantivy::schema::Field,
    }

    impl TantivyIndex {
        pub fn with_path<P: AsRef<Path>>(path: P) -> Result<Self, TantivyIndexError> {
            let mut schema_builder = Schema::builder();
            let id_f = schema_builder.add_text_field("id", TEXT | STORED);
            let title_f = schema_builder.add_text_field("title", TEXT);
            let content_f = schema_builder.add_text_field("content", TEXT);
            let tags_f = schema_builder.add_text_field("tags", TEXT);
            let type_f = schema_builder.add_text_field("type", TEXT | STORED | INDEXED);
            let score_f = schema_builder.add_f64_field("score", STORED | INDEXED);
            let created_ts_f = schema_builder.add_i64_field("created_ts");
            let updated_ts_f = schema_builder.add_i64_field("updated_ts");
            let schema = schema_builder.build();
            let index = Index::create_in_dir(path, schema.clone())
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            let writer = index
                .writer(50_000_000)
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            let reader = index
                .reader_builder()
                .reload_policy(ReloadPolicy::OnCommit)
                .try_into()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            Ok(Self {
                index,
                writer: RwLock::new(writer),
                reader: RwLock::new(reader),
                id_f,
                title_f,
                content_f,
                tags_f,
                type_f,
                score_f,
                created_ts_f,
                updated_ts_f,
            })
        }

        pub fn new() -> Self {
            let tmp = tempfile::tempdir().expect("tempdir");
            Self::with_path(tmp.path()).expect("tantivy index init")
        }
    }

    impl Index for TantivyIndex {
        type Error = TantivyIndexError;

        fn update(&self, _project: &ProjectId, memory: &Memory) -> Result<(), Self::Error> {
            let mut writer = self.writer.write();
            // delete existing
            writer.delete_term(Term::from_field_text(self.id_f, &memory.id));
            // add new doc
            let mut tags_joined = String::new();
            if !memory.tags.is_empty() {
                tags_joined = memory.tags.join(" ");
            }
            let score = memory.score.unwrap_or(0.0) as f64;
            let created_ts = memory.created_at.timestamp();
            let updated_ts = memory.updated_at.timestamp();
            writer
                .add_document(doc!(
                    self.id_f => memory.id.clone(),
                    self.title_f => memory.title.clone(),
                    self.content_f => memory.content.clone(),
                    self.tags_f => tags_joined,
                    self.type_f => memory.r#type.clone(),
                    self.score_f => score,
                    self.created_ts_f => created_ts,
                    self.updated_ts_f => updated_ts
                ))
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            writer
                .commit()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            Ok(())
        }

        fn delete(&self, _project: &ProjectId, id: &str) -> Result<(), Self::Error> {
            let mut writer = self.writer.write();
            writer.delete_term(Term::from_field_text(self.id_f, id));
            writer
                .commit()
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            Ok(())
        }

        fn search(
            &self,
            _project: &ProjectId,
            params: &SearchParams,
        ) -> Result<SearchResults, Self::Error> {
            let reader = self.reader.read();
            let searcher = reader.searcher();
            let mut musts: Vec<(Occur, Box<dyn Query>)> = Vec::new();
            if params.query.trim().is_empty() {
                musts.push((Occur::Must, Box::new(AllQuery)));
            } else {
                let qp_title =
                    tantivy::query::QueryParser::for_index(&self.index, vec![self.title_f]);
                let qp_ct = tantivy::query::QueryParser::for_index(
                    &self.index,
                    vec![self.content_f, self.tags_f],
                );
                let q_title = qp_title
                    .parse_query(&params.query)
                    .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
                let q_ct = qp_ct
                    .parse_query(&params.query)
                    .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
                // Boost title by adding it twice as SHOULD
                let boosted = BooleanQuery::from(vec![
                    (Occur::Should, q_title.box_clone()),
                    (Occur::Should, q_title),
                    (Occur::Should, q_ct),
                ]);
                musts.push((Occur::Must, Box::new(boosted)));
            }

            if let Some(types) = params.types.as_ref() {
                if !types.is_empty() {
                    let mut shoulds: Vec<(Occur, Box<dyn Query>)> = Vec::new();
                    for t in types {
                        let term = Term::from_field_text(self.type_f, t);
                        let tq: Box<dyn Query> =
                            Box::new(TermQuery::new(term, IndexRecordOption::Basic));
                        shoulds.push((Occur::Should, tq));
                    }
                    let type_q: Box<dyn Query> = Box::new(BooleanQuery::from(shoulds));
                    musts.push((Occur::Must, type_q));
                }
            }
            if let Some(tags) = params.tags.as_ref() {
                if !tags.is_empty() {
                    let mut shoulds: Vec<(Occur, Box<dyn Query>)> = Vec::new();
                    for tg in tags {
                        let term = Term::from_field_text(self.tags_f, tg);
                        let tq: Box<dyn Query> =
                            Box::new(TermQuery::new(term, IndexRecordOption::Basic));
                        shoulds.push((Occur::Should, tq));
                    }
                    let tags_q: Box<dyn Query> = Box::new(BooleanQuery::from(shoulds));
                    musts.push((Occur::Must, tags_q));
                }
            }

            // Time range on updated_ts
            if let Some(from) = params.from_time {
                let from_ts = from.timestamp();
                let rq: Box<dyn Query> = Box::new(RangeQuery::new_i64_bounds(
                    self.updated_ts_f,
                    tantivy::Bound::Included(from_ts),
                    tantivy::Bound::Unbounded,
                ));
                musts.push((Occur::Must, rq));
            }
            if let Some(to) = params.to_time {
                let to_ts = to.timestamp();
                let rq: Box<dyn Query> = Box::new(RangeQuery::new_i64_bounds(
                    self.updated_ts_f,
                    tantivy::Bound::Unbounded,
                    tantivy::Bound::Included(to_ts),
                ));
                musts.push((Occur::Must, rq));
            }

            let final_q = BooleanQuery::from(musts);
            let limit = params.limit.unwrap_or(50) as usize;
            let offset = params.offset.unwrap_or(0) as usize;
            let top = tantivy::collector::TopDocs::with_limit(limit + offset);
            let top_docs = searcher
                .search(&final_q, &top)
                .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
            let mut items = Vec::new();
            for (i, (score, addr)) in top_docs.into_iter().enumerate() {
                if i < offset {
                    continue;
                }
                let retrieved = searcher
                    .doc(addr)
                    .map_err(|e| TantivyIndexError::Internal(e.to_string()))?;
                let id_val = retrieved
                    .get_first(self.id_f)
                    .ok_or_else(|| TantivyIndexError::Internal("missing id".into()))?;
                let id_str = id_val
                    .text()
                    .ok_or_else(|| TantivyIndexError::Internal("id not text".into()))?
                    .to_string();
                items.push(SearchResult {
                    id: id_str,
                    score: Some(score as f32),
                });
            }
            Ok(SearchResults {
                total: items.len() as u64,
                items,
            })
        }
    }
}

pub use engine::TantivyIndex;

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gitmem_core::{
        model::Memory,
        traits::{Index, SearchParams},
    };
    use tempfile::TempDir;

    fn params(query: &str) -> SearchParams {
        SearchParams {
            query: query.to_string(),
            types: None,
            tags: None,
            limit: None,
            offset: None,
            sort: None,
            from_time: None,
            to_time: None,
        }
    }

    #[test]
    fn milli_core_with_path_round_trips() {
        let temp = TempDir::new().expect("tempdir");
        let index = TantivyIndex::with_path(temp.path()).expect("index init");
        let project = "alpha".to_string();

        let memory = Memory::new("alpha title", "alpha body", "note");
        index.update(&project, &memory).expect("index update");

        let results = index.search(&project, &params("alpha")).expect("search");
        assert_eq!(results.total, 1);
        assert_eq!(results.items.len(), 1);
        assert_eq!(results.items[0].id, memory.id);
    }

    #[cfg(unix)]
    #[test]
    fn milli_core_permission_denied_falls_back_to_memory() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        let read_only = fs::Permissions::from_mode(0o555);
        fs::set_permissions(root, read_only).expect("set read-only perms");

        let index = TantivyIndex::with_path(root).expect("index init");
        let project = "beta".to_string();
        let memory = Memory::new("beta title", "beta body", "note");
        index.update(&project, &memory).expect("index update");

        let results = index.search(&project, &params("beta")).expect("search");
        assert_eq!(results.total, 1);
        assert_eq!(results.items.len(), 1);
        assert_eq!(results.items[0].id, memory.id);

        // Restore permissions so TempDir cleanup succeeds.
        let writable = fs::Permissions::from_mode(0o755);
        fs::set_permissions(root, writable).expect("restore perms");
        assert!(
            !root.join(&project).exists(),
            "project directory should not exist when falling back to memory backend"
        );
    }
}
