use mcp_gitmem_core::model::Memory;
use rand::{distributions::Alphanumeric, rngs::StdRng, Rng, SeedableRng};
use std::fs::File;
use std::io::{BufWriter, Write};
use tempfile::NamedTempFile;

const TITLE_PREFIX: &str = "Synthetic Note ";
const CONTENT_SENTENCE: &str =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum facilisis.";

pub fn generate_memories(count: usize, project: &str, seed: u64) -> Vec<Memory> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..count)
        .map(|idx| {
            let title = format!("{TITLE_PREFIX}{idx:05}");
            let mut memory = Memory::new(&title, CONTENT_SENTENCE, "note");
            memory.tags.push(format!("project:{project}"));
            memory.tags.push(format!("tag{}", idx % 5));
            memory.score = Some((rng.gen::<f32>() * 10.0).round() / 10.0);
            memory.content = format!(
                "{}\n{}\n{}",
                CONTENT_SENTENCE,
                random_suffix(&mut rng),
                random_suffix(&mut rng)
            );
            memory
        })
        .collect()
}

fn random_suffix(rng: &mut StdRng) -> String {
    let suffix: String = (0..32).map(|_| rng.sample(Alphanumeric) as char).collect();
    suffix
}

pub fn write_jsonl_dataset(memories: &[Memory]) -> NamedTempFile {
    let file = NamedTempFile::new().expect("create temp dataset file");
    let mut writer = BufWriter::new(File::create(file.path()).expect("open dataset file"));
    for mem in memories {
        let value = serde_json::json!({
            "id": mem.id,
            "title": mem.title,
            "content": mem.content,
            "type": mem.r#type,
            "tags": mem.tags,
        });
        let line = serde_json::to_string(&value).expect("serialize jsonl record");
        writeln!(writer, "{line}").expect("write dataset row");
    }
    writer.flush().expect("flush dataset writer");
    file
}
