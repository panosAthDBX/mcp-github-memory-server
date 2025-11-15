use std::sync::Arc;

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use mcp_gitmem_compat::import_basic_from_path;
use tempfile::NamedTempFile;

use mcp_gitmem_benchmarks::{
    datasets::{generate_memories, write_jsonl_dataset},
    harness::{default_project, measure_save, measure_search, EphemeralStack, LocalStack},
};

const DATASET_SIZES: [usize; 3] = [1_000, 10_000, 50_000];

fn bench_save(c: &mut Criterion) {
    let project = default_project();
    let mut group = c.benchmark_group("save_ephemeral");
    for &size in &DATASET_SIZES {
        let dataset = Arc::new(generate_memories(size, &project, size as u64));
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("ephemeral", size),
            &dataset,
            |b, memories| {
                b.iter_batched(
                    || (EphemeralStack::new(&project), Arc::clone(memories)),
                    |(stack, dataset)| {
                        measure_save(&stack.storage, &stack.index, &stack.project, &dataset);
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();

    let mut local_group = c.benchmark_group("save_local");
    for &size in &DATASET_SIZES {
        let dataset = Arc::new(generate_memories(size, &project, (size as u64) + 1));
        local_group.throughput(Throughput::Elements(size as u64));
        local_group.bench_with_input(BenchmarkId::new("local", size), &dataset, |b, memories| {
            b.iter_batched(
                || (LocalStack::new(&project), Arc::clone(memories)),
                |(stack, dataset)| {
                    measure_save(&stack.storage, &stack.index, &stack.project, &dataset);
                },
                BatchSize::LargeInput,
            );
        });
    }
    local_group.finish();
}

fn bench_search(c: &mut Criterion) {
    let project = default_project();
    let mut group = c.benchmark_group("search");
    for &size in &DATASET_SIZES {
        group.bench_with_input(
            BenchmarkId::new("ephemeral", size),
            &size,
            |b, &input_size| {
                b.iter_batched(
                    || {
                        let dataset =
                            generate_memories(input_size, &project, (input_size as u64) + 11);
                        let stack = EphemeralStack::new(&project);
                        stack.save_all(&dataset);
                        (stack, dataset)
                    },
                    |(stack, _dataset)| {
                        let hits = measure_search(&stack.index, &stack.project, "Synthetic");
                        black_box(hits);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_import(c: &mut Criterion) {
    let project = default_project();
    let mut group = c.benchmark_group("import_local");
    for &size in &DATASET_SIZES {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, &input_size| {
                b.iter_batched(
                    || setup_import_case(input_size, &project),
                    |(stack, dataset_file)| {
                        let imported = import_basic_from_path(
                            dataset_file.path().to_str().expect("utf8 path"),
                        )
                        .expect("import dataset");
                        measure_save(&stack.storage, &stack.index, &stack.project, &imported);
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn setup_import_case(size: usize, project: &str) -> (LocalStack, NamedTempFile) {
    let dataset = generate_memories(size, project, (size as u64) + 29);
    let stack = LocalStack::new(project);
    let file = write_jsonl_dataset(&dataset);
    (stack, file)
}

fn benches(c: &mut Criterion) {
    bench_save(c);
    bench_search(c);
    bench_import(c);
}

criterion_group!(gitmem_benches, benches);
criterion_main!(gitmem_benches);
