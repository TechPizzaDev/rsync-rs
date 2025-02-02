use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fast_rsync::crc::Crc;
use fast_rsync::rabinkarp::RabinKarpHash;
use fast_rsync::sum_hash::SumHash;
use fast_rsync::{
    apply_limited, diff, CryptoHashType, RollingHashType, Signature, SignatureOptions,
};
use std::io;
use tokio::runtime::Builder;

fn random_block(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut v = vec![0; len];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

fn crc_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("Crc");
    for &len in &[128, 4096] {
        let data = random_block(len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("Crc::sum_of", len), &data, |b, data| {
            b.iter(|| Crc::default().update(black_box(data)).finish())
        });
        // TODO:
        //group.bench_with_input(
        //    BenchmarkId::new("Crc::basic_update", len),
        //    &data,
        //    |b, data| b.iter(|| basic_update(Crc::default(), black_box(data))),
        //);
    }
    group.finish();
}

fn rabinkarp_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("RabinKarp");
    for &len in &[128, 4096] {
        let data = random_block(len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(
            BenchmarkId::new("RabinKarpHash::sum_of", len),
            &data,
            |b, data| b.iter(|| RabinKarpHash::default().update(black_box(data)).finish()),
        );
    }
    group.finish();
}

criterion_group!(hash, crc_update, rabinkarp_update);

fn calculate_signature(c: &mut Criterion) {
    let rt = Builder::new_current_thread().build().unwrap();
    let data = random_block(1 << 22);
    let mut group = c.benchmark_group("calculate_signature");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.sample_size(20);
    group.bench_with_input(
        BenchmarkId::new("fast_rsync::Signature::calculate", data.len()),
        &data,
        |b, data| {
            b.to_async(&rt).iter(|| async {
                let mut sig_output = Vec::new();
                Signature::calculate(
                    black_box(&mut &data[..]),
                    &mut sig_output,
                    &SignatureOptions {
                        block_size: 4096,
                        crypto_hash_size: 8,
                        crypto_hash: CryptoHashType::Md4,
                        rolling_hash: RollingHashType::Rollsum,
                    },
                )
                .await
                .unwrap();
            })
        },
    );
    group.bench_with_input(
        BenchmarkId::new("librsync::whole::signature", data.len()),
        &data,
        |b, data| {
            b.iter(|| {
                let mut out = Vec::new();
                librsync::whole::signature_with_options(
                    &mut &data[..],
                    &mut out,
                    4096,
                    8,
                    librsync::SignatureType::MD4,
                )
                .unwrap();
                out
            })
        },
    );
    group.finish();
}

fn bench_diff(
    c: &mut Criterion,
    name: &str,
    data: &[u8],
    new_data: &Vec<u8>,
    allow_librsync: bool,
) {
    let rt = Builder::new_current_thread().build().unwrap();
    let mut sig_output = Vec::new();
    rt.block_on(async {
        Signature::calculate(
            &mut &data[..],
            &mut sig_output,
            &SignatureOptions {
                block_size: 4096,
                crypto_hash_size: 8,
                crypto_hash: CryptoHashType::Md4,
                rolling_hash: RollingHashType::Rollsum,
            },
        )
        .await
        .unwrap()
    });

    let mut group = c.benchmark_group(name);
    group.sample_size(15);
    group.bench_with_input(
        BenchmarkId::new("fast_rsync::diff", new_data.len()),
        new_data,
        |b, new_data| {
            b.to_async(&rt).iter(|| async {
                let sig = Signature::deserialize(&mut &sig_output[..]).await.unwrap();
                let sig = sig.index(&sig_output);
                let mut out = Vec::new();
                diff(&sig, black_box(new_data), &mut out).unwrap();
                out
            })
        },
    );
    if allow_librsync {
        group.bench_with_input(
            BenchmarkId::new("librsync::whole::delta", new_data.len()),
            new_data,
            |b, new_data| {
                b.iter(|| {
                    let mut out = Vec::new();
                    librsync::whole::delta(
                        &mut black_box(&new_data[..]),
                        &mut &sig_output[..],
                        &mut out,
                    )
                    .unwrap();
                    out
                })
            },
        );
    }
    group.finish();
}

fn calculate_diff(c: &mut Criterion) {
    let data = random_block(1 << 22);
    let mut new_data = data.clone();
    new_data[1000000..1065536].copy_from_slice(&random_block(65536));
    bench_diff(c, "diff (64KB edit)", &data, &new_data, true);
    bench_diff(c, "diff (random)", &data, &random_block(1 << 22), true);
    bench_diff(
        c,
        "diff (pathological)",
        &vec![0; 1 << 14],
        &vec![128; 1 << 14],
        true,
    );
    bench_diff(
        c,
        "diff (pathological)",
        &vec![0; 1 << 22],
        &vec![128; 1 << 22],
        false,
    );
}

fn apply_delta(c: &mut Criterion) {
    let rt = Builder::new_current_thread().build().unwrap();
    let data = random_block(1 << 22);
    let mut new_data = data.clone();
    new_data[1000000..1065536].copy_from_slice(&random_block(65536));
    let mut delta = Vec::new();
    let mut sig_output = Vec::new();
    let signature = rt.block_on(async {
        Signature::calculate(
            &mut &data[..],
            &mut sig_output,
            &SignatureOptions {
                block_size: 4096,
                crypto_hash_size: 8,
                crypto_hash: CryptoHashType::Md4,
                rolling_hash: RollingHashType::Rollsum,
            },
        )
        .await
        .unwrap()
    });
    diff(&signature.index(&sig_output), &new_data, &mut delta).unwrap();

    let mut group = c.benchmark_group("apply");
    group.bench_with_input(
        BenchmarkId::new("fast_rsync::apply", new_data.len()),
        &delta,
        |b, delta| {
            b.iter(|| {
                let mut out = Vec::new();
                apply_limited(&data, delta, &mut out, 1 << 22).unwrap();
                out
            })
        },
    );
    group.bench_with_input(
        BenchmarkId::new("librsync::whole::patch", new_data.len()),
        &delta,
        |b, delta| {
            b.iter(|| {
                let mut out = Vec::new();
                librsync::whole::patch(&mut io::Cursor::new(&data[..]), &mut &delta[..], &mut out)
                    .unwrap();
                out
            })
        },
    );
    group.finish();
}

criterion_group!(rsync, calculate_signature, calculate_diff, apply_delta);

criterion_main!(hash, rsync);
