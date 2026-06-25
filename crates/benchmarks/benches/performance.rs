use std::sync::Arc;

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use mcp_gitmem_compat::import_basic_from_path;
use mcp_gitmem_core::traits::Index;
use tempfile::NamedTempFile;

use mcp_gitmem_benchmarks::{
    datasets::{generate_memories, write_jsonl_dataset},
    harness::{
        default_project, measure_save, measure_save_batch, measure_search, EphemeralStack,
        LocalStack,
    },
};

const DATASET_SIZES: [usize; 3] = [10, 100, 500];

fn bench_save(c: &mut Criterion) {
    let project = default_project();
    let mut group = c.benchmark_group("save_ephemeral");
    group.sample_size(10);
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
    local_group.sample_size(10);
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

fn bench_save_batch(c: &mut Criterion) {
    let project = default_project();
    let mut group = c.benchmark_group("save_ephemeral_batch");
    group.sample_size(10);
    for &size in &DATASET_SIZES {
        let dataset = Arc::new(generate_memories(size, &project, (size as u64) + 2));
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("ephemeral_batch", size),
            &dataset,
            |b, memories| {
                b.iter_batched(
                    || (EphemeralStack::new(&project), Arc::clone(memories)),
                    |(stack, dataset)| {
                        measure_save_batch(&stack.storage, &stack.index, &stack.project, &dataset);
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_search(c: &mut Criterion) {
    let project = default_project();
    let mut group = c.benchmark_group("search");
    group.sample_size(10);
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

fn bench_batch_sizes(c: &mut Criterion) {
    let project = default_project();
    let mut group = c.benchmark_group("batch_sizes");
    group.sample_size(10);

    let total_items = 1000;
    let dataset = Arc::new(generate_memories(total_items, &project, 12345));

    for &batch_size in &[50, 500] {
        group.throughput(Throughput::Elements(total_items as u64));
        group.bench_with_input(
            BenchmarkId::new("chunk_size", batch_size),
            &batch_size,
            |b, &chunk_size| {
                b.iter_batched(
                    || (EphemeralStack::new(&project), Arc::clone(&dataset)),
                    |(stack, dataset)| {
                        for chunk in dataset.chunks(chunk_size) {
                            stack
                                .index
                                .update_batch(&stack.project, chunk)
                                .expect("update batch");
                        }
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_import(c: &mut Criterion) {
    let project = default_project();
    let mut group = c.benchmark_group("import_local");
    group.sample_size(10);
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
    // Set sample size on the global configuration for this run
    let mut c = c;
    // Note: Criterion doesn't let us easily clone the whole config to pass to sub-functions if they take &mut Criterion.
    // However, the sub-functions take &mut Criterion.
    // We can just set the sample size on `c` and pass it along.
    // But wait, `c` is already &mut.

    // Actually, let's just create a new configuration with the desired sample size if possible,
    // or just modify the existing one if the API allows.
    // Criterion::default().sample_size(10).configure_from_args();

    // The simplest way is to just use the benchmark groups inside the functions to set sample size,
    // but we want to do it globally.
    // Let's try just passing `c` and modifying the sub-functions to set sample size on their groups?
    // Or just set it here? `c.sample_size(10)` is not a method on Criterion, it's on BenchmarkGroup.

    // Ah, we can't set default sample size on Criterion struct directly after it's created easily?
    // Let's revert to the previous pattern but set sample size inside the individual bench functions.
    // It's cleaner and avoids this fighting with the API.

    bench_save(c);
    bench_save_batch(c);
    bench_batch_sizes(c);
    bench_search(c);
    bench_import(c);
}

criterion_group!(gitmem_benches, benches);
criterion_main!(gitmem_benches);
