//! Compatibility helpers for basic-memory format and importers

use mcp_gitmem_core::model::Memory;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicMemoryRecord {
    pub id: Option<String>,
    pub title: Option<String>,
    pub content: String,
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

pub fn from_basic(rec: BasicMemoryRecord) -> Memory {
    let mut m = Memory::new(
        rec.title.as_deref().unwrap_or(""),
        &rec.content,
        rec.r#type.as_deref().unwrap_or("note"),
    );
    m.tags = rec.tags;
    if let Some(id) = rec.id {
        m.id = id;
    }
    m
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicFormat {
    JsonArray,
    Jsonl,
}

pub fn detect_format<P: AsRef<Path>>(path: P) -> std::io::Result<BasicFormat> {
    let mut f = File::open(path)?;
    let mut buf = [0u8; 1];
    let n = f.read(&mut buf)?;
    if n > 0 && (buf[0] as char) == '[' {
        Ok(BasicFormat::JsonArray)
    } else {
        Ok(BasicFormat::Jsonl)
    }
}

pub fn import_basic_from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<Memory>> {
    match detect_format(&path)? {
        BasicFormat::JsonArray => import_json_array(path),
        BasicFormat::Jsonl => import_jsonl(path),
    }
}

fn stable_id_for(m: &Memory) -> String {
    let mut h = Sha256::new();
    h.update(m.title.as_bytes());
    h.update(m.content.as_bytes());
    h.update(m.created_at.to_rfc3339().as_bytes());
    format!("mem_{}", hex::encode(h.finalize()))
}

fn import_json_array<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<Memory>> {
    let mut s = String::new();
    File::open(path)?.read_to_string(&mut s)?;
    let recs: Vec<BasicMemoryRecord> = serde_json::from_str(&s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut mems: Vec<Memory> = recs.into_iter().map(from_basic).collect();
    for m in &mut mems {
        if m.id.is_empty() {
            m.id = stable_id_for(m);
        }
    }
    Ok(mems)
}

fn import_jsonl<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<Memory>> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut out = Vec::new();
    for line in reader.lines() {
        let l = line?;
        if l.trim().is_empty() {
            continue;
        }
        let rec: BasicMemoryRecord = serde_json::from_str(&l)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut m = from_basic(rec);
        if m.id.is_empty() {
            m.id = stable_id_for(&m);
        }
        out.push(m);
    }
    Ok(out)
}

pub fn remap_types(mems: &mut [Memory], mapping: &std::collections::HashMap<String, String>) {
    for m in mems.iter_mut() {
        if let Some(new) = mapping.get(&m.r#type) {
            m.r#type = new.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn detect_and_import_jsonl() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("data.jsonl");
        let content = r#"{"title":"a","content":"x","type":"note"}
{"title":"b","content":"y","type":"fact"}
"#;
        fs::write(&p, content).unwrap();
        assert!(matches!(detect_format(&p).unwrap(), BasicFormat::Jsonl));
        let mems = import_basic_from_path(&p).unwrap();
        assert_eq!(mems.len(), 2);
        assert!(!mems[0].id.is_empty());
    }

    #[test]
    fn detect_and_import_json_array() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("data.json");
        let content = r#"[
  {"title":"a","content":"x","type":"note"},
  {"title":"b","content":"y","type":"fact"}
]"#;
        fs::write(&p, content).unwrap();
        assert!(matches!(detect_format(&p).unwrap(), BasicFormat::JsonArray));
        let mems = import_basic_from_path(&p).unwrap();
        assert_eq!(mems.len(), 2);
        assert!(!mems[1].id.is_empty());
    }
}
