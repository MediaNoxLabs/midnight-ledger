//! contract-benchmark — a parameterised "dummy contract" exposed as 20
//! circuits indexed by `k`, where `k` controls the circuit constraint
//! size. Each `circuit_k(k)` produces a zkir IR whose minimum required
//! halo2 `k` (the `2^k` rows the prover needs to lay it out) matches the
//! requested `k`.
//!
//! ## Why not compactc?
//!
//! Spec for this crate (see `mobile-bench/contract-benchmark/README.md`)
//! originally called for a `did.compact`-style Compact-DSL source compiled
//! into 20 circuits via `compactc`. `compactc` is not available locally —
//! the user agreed up-front: "try compactc; fall back to padding". We
//! ship the padding fallback: handwritten zkir IR programs that grow a
//! chain of `transient_hash` ops until `IrSource::model().k()` hits the
//! requested target. This exercises the same halo2-kzg prove/verify
//! pipeline `prover-core` exercises for the embedded examples (see
//! `mobile-bench/prover-core/src/zkir_example.rs`,
//! `htc_example.rs`, `ec_example.rs`), so the wall-clock numbers are
//! directly comparable.
//!
//! ## Locally-runnable subset of `k`
//!
//! `run_proof(k)` exposes `k` = 1..=20 unconditionally. Whether it
//! actually finishes proving depends on the BLS-12-381 KZG SRS files
//! available on disk:
//!
//! - Desktop: `~/.cache/midnight/zk-params/bls_midnight_2pN` files are
//!   fetched on demand from `srs.midnight.network` the first time a
//!   given `k` is requested.
//! - Android (emulator + S24 Ultra): the deploy guide pushes only
//!   `bls_midnight_2p4..2p11` to `/data/local/tmp/midnight-pp/` (see
//!   `mobile-bench/DEPLOY_TO_DEVICE.md`). Higher `k` will fail at
//!   `ParamsProverProvider::get_params` unless pushed manually.
//! - Verification with the embedded `PARAMS_VERIFIER` works for `k ≤
//!   14` only. For `k > 14`, `run_proof` skips verification but still
//!   reports the prove time.

#![deny(unreachable_pub)]
#![deny(warnings)]

use std::path::PathBuf;
// `Arc<ZswapResolver>` is only constructed by the native
// `make_zswap_resolver` helper. Gate the unused-on-wasm imports.
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
use std::time::Duration;
// `std::time::Instant` panics on `wasm32-unknown-unknown` (no
// JS hook in the std backend). `web_time::Instant` is an
// API-compatible drop-in that uses `std::time::Instant` on
// native and `js_sys::Date.now()` on wasm.
use web_time::Instant;

#[cfg(not(target_arch = "wasm32"))]
use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::tagged_serialize;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{
    KeyLocation, PARAMS_VERIFIER, ParamsProverProvider, ProofPreimage, ProverKey,
    ProvingKeyMaterial, Resolver as ResolverT, VerifierKey, Zkir,
};
use zkir::IrSource;
#[cfg(not(target_arch = "wasm32"))]
use zswap::{ZSWAP_EXPECTED_FILES, prove::ZswapResolver};

/// Inclusive upper bound on `k`. Originally 20; raised to 21 to
/// characterise the failure mode beyond the disk-spill unlock
/// (advice_cosets remain heap-resident — see §10.8 / §11 in the
/// architecture doc). Bumped to 22 in iteration 3 of the k21-plan
/// so the S3 chunked-Pippenger fallback in midnight-zk:msm.rs can
/// actually be exercised — at k=22 (n=2^22) the MSM falls off the
/// blstrs fast path (gated at n ≤ 2^21 in patch 0005) and the
/// chunked Pippenger keeps per-call peak heap bounded.
pub const MAX_K: u32 = 22;
/// Inclusive lower bound on `k`. `k = 1` corresponds to the minimal
/// "assert(input == 1)" circuit — the smallest possible zkir program.
pub const MIN_K: u32 = 1;
/// Highest `k` for which the embedded verifier can check a proof. For
/// `k > 14` the prove path still works but we can't verify in-process
/// without the matching verifying SRS.
pub const MAX_VERIFIABLE_K: u32 = 14;

/// Highest `k` at which we still call `ir.model()` to verify the
/// realised row count matches the target.
///
/// `ir.model()` invokes halo2's `cost_model_options`, which
/// synthesises the circuit into a `DevAssembly` whose `assign_fixed`
/// path stores every fixed-cell write in a `hashbrown::HashMap`.
/// At k≥19 the rehash needs multi-GiB transient allocation and
/// triggers `handle_alloc_error → SIGABRT` on a 12 GB S24 Ultra
/// (tombstone evidence: `cost_model_options` → `DevAssembly::assign_fixed`
/// → `hashbrown::Fallibility::alloc_err`).
///
/// The cost-model path is a *measurement* aid — the real prover
/// (`ir.keygen` + `prove`) takes a different synthesis route that
/// doesn't allocate this HashMap. So at `target_k > COST_MODEL_SAFE_K`
/// we trust the precomputed `HASHES_FOR_K[k]` and skip the call.
///
/// Set to 17: empirically k=18 still completes the cost-model
/// (~22 s on S24); k=19 dies. Conservative — bump if a future halo2
/// release makes the cost-model cheaper.
pub const COST_MODEL_SAFE_K: u32 = 17;

/// Precomputed transient-hash chain length that realises each target
/// `k` exactly. Lets `build_ir_for_k` skip the probe-and-double loop
/// + binary shrink (typically 5–17 IR parses) and just build the
/// circuit once with a known-good `n`.
///
/// Index by `k` directly (slot `[0]` unused). Values were observed
/// empirically by running the convergence loop on a desktop M-class
/// host; `build_ir_for_k` re-verifies `model().k() == target_k` and
/// falls back to the slow probing path on any mismatch (so a future
/// halo2 row-count change degrades gracefully instead of silently
/// running off-target).
///
/// `k = 1` is the special-case minimal-assert circuit and carries
/// no hash chain; the slot is `0` and ignored by the fast path.
pub const HASHES_FOR_K: [u32; (MAX_K + 1) as usize] = [
    0,      // k=0 — unused
    0,      // k=1 — minimal assert, no hash chain
    1,      // k=2..5 — hash count floors at 1 (k_realised clamps up)
    1,      // k=3
    1,      // k=4
    1,      // k=5
    2,      // k=6
    3,      // k=7
    6,      // k=8
    12,     // k=9
    24,     // k=10
    49,     // k=11
    98,     // k=12
    195,    // k=13
    390,    // k=14
    780,    // k=15
    1_560,  // k=16
    3_121,  // k=17
    6_242,  // k=18
    12_484, // k=19 (extrapolated by doubling; verified at runtime)
    24_967, // k=20 (extrapolated; verified at runtime)
    49_935, // k=21 (extrapolated by doubling; verified at runtime)
    99_871, // k=22 (extrapolated by doubling; verified at runtime)
];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("k out of range: requested {requested}, supported {MIN_K}..={MAX_K}")]
    KOutOfRange { requested: u32 },
    #[error("could not build a circuit needing k = {target}: \
            grew chain to {ops} transient_hash ops and only reached k = {reached}")]
    CircuitGrowFailed {
        target: u32,
        reached: u32,
        ops: u32,
    },
    #[error("anyhow: {0}")]
    Anyhow(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Timings for a single `run_proof(k)` invocation. All durations are
/// wall-clock measured at the boundaries of the corresponding
/// async / sync calls.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunStats {
    /// The requested `k`.
    pub k: u32,
    /// The actual minimum-`k` halo2 reported for the generated circuit
    /// (always equals `k` when `Ok`).
    pub realized_k: u32,
    /// The number of `transient_hash` ops in the generated chain.
    pub hash_chain_len: u32,
    /// halo2-cost-model row count (not counting lookups / custom gates).
    pub rows: u64,
    /// Time spent in `IrSource::keygen` — proving + verifying key
    /// generation. Amortised across calls if the caller caches keys
    /// (this crate does *not* cache; each `run_proof` regenerates so
    /// timings are reproducible for a clean run).
    pub keygen: Duration,
    /// Time spent in `ProofPreimage::prove`. The headline number — the
    /// thing the Benchmark tab plots per row.
    pub prove: Duration,
    /// Time spent in `VerifierKey::verify`. `None` when `k > MAX_VERIFIABLE_K`
    /// (no embedded verifier) or when verification was skipped.
    pub verify: Option<Duration>,
    /// Whether the verification succeeded. `None` if not attempted.
    pub verified: Option<bool>,
    /// Serialised proof size in bytes — small enough to log per-row.
    pub proof_bytes: usize,
    /// SHA-256 of the tagged-serialised proof bytes (hex-encoded,
    /// lowercase, no `0x`). Deterministic given `(k, seed, IR, PK,
    /// SRS)`. The smoke-test pipeline uses this as the golden
    /// test-vector identity to prove that prover optimisations
    /// (zk patches, S1/S3/S5, par-iter, …) do not change the proof
    /// bytes — see `docs/test-vectors/proof-vectors.json` and the
    /// smoke-test `--check-vectors` mode.
    pub proof_sha256_hex: String,
}

/// Optional knobs for `run_proof`.
#[derive(Debug, Clone)]
pub struct RunOpts {
    /// RNG seed for proving. Defaults to a fixed value so reruns are
    /// reproducible across the same circuit shape.
    pub seed: u64,
    /// If `false`, skip the verify step even if `k ≤ MAX_VERIFIABLE_K`.
    /// Lets the Benchmark tab isolate prove-only wall-clock.
    pub verify_after: bool,
    /// Where to cache the BLS SRS files. Defaults to the standard
    /// `MIDNIGHT_PP` resolution (env, $XDG_CACHE_HOME, $HOME/.cache).
    pub cache_dir: Option<PathBuf>,
    /// If `true`, reuse the `(ProverKey, VerifierKey)` pair from the
    /// process-wide `KEY_CACHE` keyed by `k`. Misses run keygen and
    /// then populate the cache. Cuts the keygen cost on every prove
    /// after the first at a given `k` to zero — for the dioxus-wallet
    /// "Benchmark" sweep that re-runs a row this halves wall-clock at
    /// high `k` where keygen ≈ prove.
    ///
    /// Default `true` because both the wallet's repeat-prove path and
    /// the bench_cli `--repeat=N` flag benefit. Disable to time a
    /// cold keygen explicitly.
    pub cache_keys: bool,
}

impl Default for RunOpts {
    fn default() -> Self {
        Self {
            seed: 0x42,
            verify_after: true,
            cache_dir: None,
            cache_keys: true,
        }
    }
}

/// Build a zkir IR that needs at least the requested `k`. Returns the
/// IR JSON and the number of `transient_hash` ops in the chain.
///
/// Strategy: start with `n` hashes (per a rough `2^(k-1)` schedule),
/// load via `IrSource::load`, query `model().k()`, and double `n`
/// until we hit or exceed the target `k`. This matches the spec's
/// "design each circuit to do `2^(k-1)` repetitions of a unit of
/// work" hint without hard-coding a magic constant per `k`.
///
/// For `k = 1` we emit the smallest legal IR: one input + one assert.
/// Process-wide cache of `(IrSource, hash_chain_len)` per target
/// `k`. First call for a given `k` does the JSON build + halo2
/// load + probe; subsequent calls return a clone (cheap — the
/// inner `instructions` is `Arc<Vec<…>>`). Worth it for any
/// caller that runs more than one prove at the same `k` (e.g.
/// the Benchmark sweep re-run, the wallet's repeated DID writes).
///
/// On wasm32 the `Mutex` is just a single-threaded spin, since
/// `wasm32-unknown-unknown` has no preemption — there's no
/// contention to mediate. On native arm64 / x86_64 the lock is
/// only held during the lookup, never across the IR construction.
static IR_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<u32, (IrSource, u32)>>,
> = std::sync::OnceLock::new();

fn ir_cache_lookup(target_k: u32) -> Option<(IrSource, u32)> {
    IR_CACHE
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .ok()
        .and_then(|m| m.get(&target_k).cloned())
}

fn ir_cache_store(target_k: u32, value: (IrSource, u32)) {
    if let Ok(mut m) = IR_CACHE
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
    {
        m.insert(target_k, value);
    }
}

/// Process-wide cache of `(ProverKey, VerifierKey)` per `k`.
///
/// Keygen is deterministic in `(SRS, IR)`: same `k` → same circuit
/// shape (because `build_ir_for_k` is itself memoised) → same key
/// pair. Once we've paid for it once at a given `k`, every later
/// prove at the same `k` can skip straight to `prove()`.
///
/// Empirically on M2 desktop:
///   k=12: keygen 216ms / prove 823ms  (cold prove ~1.04s)
///   k=14: keygen 947ms / prove 3647ms (cold prove ~4.6s — warm prove only ~3.6s after cache hit)
///   k=16: keygen 2258ms / prove 10565ms (warm cuts ~18% wall)
///
/// On mobile (slower keygen-to-prove ratio) the win is larger.
/// On the dioxus wallet's "Benchmark tab re-run" path this is the
/// difference between "almost instant" and "do it all again".
///
/// The values are `Arc`-shaped internally (`ProverKey<T> =
/// Arc<Mutex<…>>`, `VerifierKey = Arc<Mutex<…>>`), so insert + clone
/// are pointer copies — no per-prove allocation cost.
static KEY_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<u32, (ProverKey<IrSource>, VerifierKey)>>,
> = std::sync::OnceLock::new();

fn key_cache_lookup(target_k: u32) -> Option<(ProverKey<IrSource>, VerifierKey)> {
    KEY_CACHE
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .ok()
        .and_then(|m| m.get(&target_k).cloned())
}

fn key_cache_store(target_k: u32, value: (ProverKey<IrSource>, VerifierKey)) {
    if let Ok(mut m) = KEY_CACHE
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
    {
        m.insert(target_k, value);
    }
}

/// Drop every cached `(pk, vk)` pair — useful in tests / between
/// repeat sweeps where you want to time a true cold run.
pub fn clear_key_cache() {
    if let Some(m) = KEY_CACHE.get() {
        if let Ok(mut g) = m.lock() {
            g.clear();
        }
    }
}

fn build_ir_for_k(target_k: u32) -> Result<(IrSource, u32)> {
    if !(MIN_K..=MAX_K).contains(&target_k) {
        return Err(Error::KOutOfRange { requested: target_k });
    }

    // Cache hit: skip JSON build + IR parse + (potential) probing
    // entirely. Saves multi-second cold construction at high `k`.
    if let Some(cached) = ir_cache_lookup(target_k) {
        return Ok(cached);
    }

    let result = build_ir_for_k_uncached(target_k)?;
    ir_cache_store(target_k, result.clone());
    Ok(result)
}

fn build_ir_for_k_uncached(target_k: u32) -> Result<(IrSource, u32)> {
    if target_k == 1 {
        // Minimal circuit, identical shape to prover-core's `zkir-minimal-assert`.
        let json = r#"{
            "version": { "major": 2, "minor": 0 },
            "num_inputs": 1,
            "do_communications_commitment": false,
            "instructions": [
                { "op": "assert", "cond": 0 }
            ]
        }"#;
        let ir = IrSource::load(json.as_bytes())?;
        return Ok((ir, 0));
    }

    // Fast path: try the precomputed convergent `n` from
    // `HASHES_FOR_K`. Skips 5–17 redundant IR-build + halo2-load
    // probes that the original convergence loop did.
    //
    // For `target_k <= COST_MODEL_SAFE_K` we re-verify via
    // `ir.model().k() == target_k` so a future halo2 row-count
    // change can't silently mis-target; on mismatch we fall through
    // to the slow probing path below.
    //
    // For `target_k > COST_MODEL_SAFE_K` we *skip* the verification.
    // `ir.model()` calls `cost_model_options` which synthesises the
    // circuit into a `DevAssembly` whose internal HashMap stores
    // every fixed-cell assignment. At k=19+ that HashMap rehashes
    // itself into a `handle_alloc_error` -> SIGABRT on mobile
    // (~6+ GiB transient allocation observed in S24 Ultra tombstone,
    // backtrace shows `hashbrown::rustc_entry` -> `assign_fixed` ->
    // `poseidon_chip::partial_round` blowing up at k=19).
    //
    // The cost-model OOM is an artefact of the *measurement* path —
    // the real prover uses `keygen` + `prove` which take a different
    // synthesis route that doesn't materialise the row-count HashMap.
    // We trust `HASHES_FOR_K` at high k (the desktop
    // `every_k_builds` test validates the table up to MAX_K).
    let expected_n = HASHES_FOR_K[target_k as usize];
    if expected_n > 0 {
        if let Ok(ir) = build_hash_chain_ir(expected_n) {
            if target_k > COST_MODEL_SAFE_K || ir.model().k() as u32 == target_k {
                return Ok((ir, expected_n));
            }
        }
    }

    // Heuristic seed: TransientHash adds on the order of ~17 halo2 rows
    // per op (Poseidon round count). So 2^(k-1) hashes is a sensible
    // initial guess. We then probe + double until we hit `target_k`.
    let mut n: u32 = (1u32 << (target_k.saturating_sub(1).min(19))).max(1);

    // Cap iterations defensively — we should converge in ~log2(MAX_K)
    // doublings.
    for _attempt in 0..32 {
        let ir = build_hash_chain_ir(n)?;
        let model = ir.model();
        let got_k = model.k() as u32;
        if got_k >= target_k {
            // Step back down if we vastly overshot — keeps proving cost
            // close to the requested k. We accept the first n where the
            // realised k equals the target.
            return shrink_to_target(n, target_k).or_else(|_| Ok((ir, n)));
        }
        // Double and try again. Capped at u32 to avoid pathological
        // builders if the cost model changes.
        n = n.checked_mul(2).ok_or(Error::CircuitGrowFailed {
            target: target_k,
            reached: got_k,
            ops: n,
        })?;
    }

    Err(Error::CircuitGrowFailed {
        target: target_k,
        reached: 0,
        ops: n,
    })
}

/// Binary search downwards from the known-good `n_high` to find the
/// smallest `n` whose IR still realises `target_k`. Keeps each row's
/// proving cost as close to the bin as possible.
fn shrink_to_target(n_high: u32, target_k: u32) -> Result<(IrSource, u32)> {
    let mut lo: u32 = 1;
    let mut hi: u32 = n_high;
    let mut best: Option<(IrSource, u32)> = None;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let ir = build_hash_chain_ir(mid)?;
        let got = ir.model().k() as u32;
        if got >= target_k {
            best = Some((ir, mid));
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    best.ok_or(Error::CircuitGrowFailed {
        target: target_k,
        reached: 0,
        ops: n_high,
    })
}

/// Emits IR JSON for a chain of `n` `transient_hash` ops, each
/// consuming the previous hash output. The first hash consumes the
/// single input slot; subsequent hashes consume the previous output.
/// Ends with an `assert(input_0 == input_0)`-style sentinel so the
/// circuit still has a binding public input regardless of `n`.
fn build_hash_chain_ir(n: u32) -> Result<IrSource> {
    // Memory layout:
    //   index 0      → public input (Fr::from(1))
    //   index 1      → output of hash #1: H(0)
    //   index 2      → output of hash #2: H(1)
    //   ...
    //   index n      → output of hash #n: H(n-1)
    //   (no further instructions; the chain's tail isn't asserted to a
    //    constant so the circuit can stay small — the chain itself is
    //    the work, not the assertion.)
    //
    // We still need at least one `assert` so the IR has a non-trivial
    // boolean check; otherwise the cost model treats a "1-input,
    // no-asserts" program as degenerate. Use the input slot itself as
    // the asserted bit (the caller passes `1`).
    let mut instructions = String::with_capacity(64 * (n as usize + 1));
    instructions.push_str(r#"{ "op": "assert", "cond": 0 }"#);
    let mut prev: u32 = 0;
    for i in 0..n {
        instructions.push(',');
        instructions.push_str(&format!(
            r#"{{ "op": "transient_hash", "inputs": [{prev}] }}"#
        ));
        prev = i + 1;
    }

    let json = format!(
        r#"{{
            "version": {{ "major": 2, "minor": 0 }},
            "num_inputs": 1,
            "do_communications_commitment": false,
            "instructions": [{instructions}]
        }}"#
    );
    Ok(IrSource::load(json.as_bytes())?)
}

/// Internal resolver: keygen output + ir source, identical shape to
/// `prover-core`'s `ExampleResolver`. Lives here so we don't depend on
/// `prover-core` (avoiding a cyclic graph during refactors).
struct ChainResolver {
    pk: ProverKey<IrSource>,
    vk: VerifierKey,
    ir: IrSource,
    /// `k` parameter the PK was generated for. Used to derive a
    /// schema-versioned filename for the on-disk gzipped-PK cache.
    k: u32,
    /// Directory in which to persist the gzipped PK blob (typically
    /// the same `MIDNIGHT_PP` cache dir holding the SRS files). When
    /// `None`, `warm_pk_cache` recomputes the gzip every prove —
    /// matches the pre-Proposal-3 behaviour.
    pk_gz_cache_dir: Option<PathBuf>,
}

impl ResolverT for ChainResolver {
    async fn resolve_key(
        &self,
        _key: KeyLocation,
    ) -> std::io::Result<Option<ProvingKeyMaterial>> {
        bench_phase("resolver.resolve_key.start", 0);
        // Pre-warm the process-wide PK_CACHE *before* serialising.
        // The prover's `tagged_deserialize::<ProverKey<T>>` calls
        // `try_cache` which hashes the inner gzip bytes. By inserting
        // (hash, our Arc<MidnightPK>) into the cache now, the
        // consumer-side deserialise + initialise step turns into a
        // pointer copy — skipping ~1.3 GiB of `MidnightPK::read`
        // reconstruction at k=18 (and the ~5 GiB equivalent at k=20
        // that previously killed the wallet).
        //
        // Cost: one extra gzip compress of the same bytes we're about
        // to serialise anyway. CPU-bounded (~hundreds of ms at k=18),
        // does not push peak RSS. Honest trade per the user's brief:
        // "we trade RAM for CPU".
        // Proposal 3 (k21-plan): when a persistent cache dir is
        // available, route through `warm_pk_cache_with_disk` so the
        // deterministic gzip of `MidnightPK::write` is computed once
        // per `(k, IR, SRS)` and reused from disk on every subsequent
        // prove — saving ~hundreds of ms at k=18, multi-seconds at
        // k=21. Filename embeds `PK_GZ_CACHE_SCHEMA_VERSION` so a
        // future PK-layout change invalidates stale blobs cleanly.
        let warmed = if let Some(dir) = &self.pk_gz_cache_dir {
            let path = dir.join(format!(
                "pk-gz-v{}-k{}.bin",
                transient_crypto::proofs::PK_GZ_CACHE_SCHEMA_VERSION,
                self.k,
            ));
            self.pk.warm_pk_cache_with_disk(&path)?
        } else {
            self.pk.warm_pk_cache()?
        };
        tracing::info!(
            target: "midnight_bench",
            stage = "resolver.pk_cache_warmed",
            warmed = warmed,
        );
        let mut prover_key = Vec::new();
        tagged_serialize(&self.pk, &mut prover_key)?;
        let prover_len = prover_key.len();
        bench_phase("resolver.pk_serialised", 0);
        tracing::info!(
            target: "midnight_bench",
            stage = "resolver.pk_bytes",
            bytes = prover_len as u64,
        );
        let mut verifier_key = Vec::new();
        tagged_serialize(&self.vk, &mut verifier_key)?;
        bench_phase("resolver.vk_serialised", 0);
        let mut ir_source = Vec::new();
        tagged_serialize(&self.ir, &mut ir_source)?;
        bench_phase("resolver.resolve_key.end", 0);
        Ok(Some(ProvingKeyMaterial {
            prover_key,
            verifier_key,
            ir_source,
        }))
    }
}

/// Reads `/proc/self/status::{VmRSS,VmHWM}` and emits a stage event.
/// Same pattern as midnight-proofs's `log_phase` — kept duplicated
/// here so this crate doesn't need a back-channel into the proofs
/// crate's private helpers. On macOS/iOS (`/proc` absent) the event
/// fires without memory fields.
fn bench_phase(name: &'static str, k: u32) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            let mut rss: Option<u64> = None;
            let mut hwm: Option<u64> = None;
            for line in s.lines() {
                if let Some(v) = line.strip_prefix("VmRSS:") {
                    rss = v.split_whitespace().next().and_then(|n| n.parse().ok());
                } else if let Some(v) = line.strip_prefix("VmHWM:") {
                    hwm = v.split_whitespace().next().and_then(|n| n.parse().ok());
                }
            }
            if let (Some(rss_kb), Some(hwm_kb)) = (rss, hwm) {
                tracing::info!(
                    target: "midnight_bench",
                    stage = name,
                    k = k as u64,
                    rss_mb = rss_kb / 1024,
                    hwm_mb = hwm_kb / 1024,
                );
                return;
            }
        }
    }
    tracing::info!(target: "midnight_bench", stage = name, k = k as u64);
}

/// Builds, keygens, proves, and (optionally) verifies a circuit needing
/// the requested `k`, taking any `ParamsProverProvider` for the BLS
/// SRS. Returns a struct of wall-clock timings.
///
/// This is the wasm-friendly core: it has no opinion on where params
/// come from (filesystem cache, JS callback, embedded blob, …) — the
/// caller hands in a provider. Native callers wrap this via
/// [`run_proof_with_opts`] which constructs a `MidnightDataProvider`
/// using the standard `$MIDNIGHT_PP` / `$XDG_CACHE_HOME` resolution.
/// The browser-facing wrapper (`contract-benchmark-wasm`) passes a
/// `JsKeyProvider` that fetches via the JS `getParams(k)` callback.
pub async fn run_proof_with_params<P>(
    k: u32,
    opts: &RunOpts,
    params: &P,
) -> Result<RunStats>
where
    P: ParamsProverProvider,
{
    if !(MIN_K..=MAX_K).contains(&k) {
        return Err(Error::KOutOfRange { requested: k });
    }

    // Stage events flow into the dioxus-wallet's `BenchStageLayer`
    // (target prefix `midnight_` → captured) so the UI can pin the
    // current phase to a pill on the Benchmark tab. Cheap when no
    // subscriber is attached — `tracing::info!` is a noop without
    // a layer.
    tracing::info!(target: "midnight_bench", stage = "build_ir", k = k as u64);
    // 1) Build IR matched to target k.
    let (ir, chain_len) = build_ir_for_k(k)?;
    // `ir.model()` triggers `cost_model_options` which OOMs at
    // k≥19 on mobile (see `COST_MODEL_SAFE_K` docs). Skip the
    // measurement and report `realized_k = k` (we trust the IR
    // built from `HASHES_FOR_K`) and a row-count approximation
    // based on the chain length.
    let (realized_k, rows) = if k > COST_MODEL_SAFE_K {
        // Per the `every_k_builds` test, `HASHES_FOR_K` builds an
        // IR whose realised k equals the target k for k in 1..=MAX_K.
        // Approximate row count from the hash chain length —
        // empirically ~5 halo2 rows per transient_hash op plus
        // sub-2× overhead from the assertion / public-input cells.
        (k, (chain_len as u64).saturating_mul(5).saturating_add(64))
    } else {
        let model = ir.model();
        (model.k() as u32, model.rows() as u64)
    };

    // 2) Keygen — cache by `k` so repeat proves at the same `k`
    //    skip the (deterministic in IR + SRS) keygen entirely.
    //    `Duration::ZERO` on a cache hit means "didn't run", not
    //    "ran in 0ns"; the caller distinguishes via `RunStats.keygen`.
    tracing::info!(target: "midnight_bench", stage = "keygen", k = k as u64);
    let kg_start = Instant::now();
    let (pk, vk) = if opts.cache_keys {
        if let Some(cached) = key_cache_lookup(k) {
            cached
        } else {
            let pair = ir
                .keygen(params)
                .await
                .map_err(|e| Error::Anyhow(anyhow::anyhow!("keygen: {e}")))?;
            key_cache_store(k, pair.clone());
            pair
        }
    } else {
        ir.keygen(params)
            .await
            .map_err(|e| Error::Anyhow(anyhow::anyhow!("keygen: {e}")))?
    };
    let keygen = kg_start.elapsed();

    bench_phase("bench.keygen.end", k);
    // Resolve the gzipped-PK cache dir. Prefer the explicit
    // `opts.cache_dir`; fall back to the same `$MIDNIGHT_PP` /
    // `$XDG_CACHE_HOME/midnight/zk-params` / `$HOME/.cache/midnight/zk-params`
    // chain `MidnightDataProvider::new` uses, so the warm path lights
    // up without callers having to forward `--cache-dir` everywhere.
    #[cfg(not(target_arch = "wasm32"))]
    let pk_gz_cache_dir = opts.cache_dir.clone().or_else(default_pk_gz_cache_dir);
    #[cfg(target_arch = "wasm32")]
    let pk_gz_cache_dir = opts.cache_dir.clone();
    let resolver = ChainResolver {
        pk,
        vk: vk.clone(),
        ir,
        k,
        pk_gz_cache_dir,
    };
    bench_phase("bench.resolver_built", k);

    // 3) Prove.
    tracing::info!(target: "midnight_bench", stage = "prove", k = k as u64);
    let mut rng = ChaCha20Rng::seed_from_u64(opts.seed);
    let preimage = make_preimage();
    let binding_input = preimage.binding_input;
    bench_phase("bench.prove.start", k);

    let prove_start = Instant::now();
    let (proof, _pi_skips) = preimage
        .prove::<IrSource>(&mut rng, params, &resolver)
        .await
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("prove: {e}")))?;
    let prove = prove_start.elapsed();
    bench_phase("bench.prove.end", k);

    let (proof_bytes, proof_sha256_hex) = {
        use sha2::{Digest, Sha256};
        let mut buf = Vec::new();
        tagged_serialize(&proof, &mut buf)
            .map_err(|e| Error::Anyhow(anyhow::anyhow!("serialize proof: {e}")))?;
        let digest = Sha256::digest(&buf);
        // Lowercase hex, no `0x` prefix — easy to grep + diff against
        // `docs/test-vectors/proof-vectors.json`.
        let hex = digest.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        (buf.len(), hex)
    };

    // 4) Verify (if eligible).
    if opts.verify_after && realized_k <= MAX_VERIFIABLE_K {
        tracing::info!(target: "midnight_bench", stage = "verify", k = k as u64);
    }
    let (verified, verify_dur) = if opts.verify_after && realized_k <= MAX_VERIFIABLE_K {
        let v_start = Instant::now();
        let ok = vk
            .verify(&PARAMS_VERIFIER, &proof, std::iter::once(binding_input))
            .is_ok();
        (Some(ok), Some(v_start.elapsed()))
    } else {
        (None, None)
    };

    Ok(RunStats {
        k,
        realized_k,
        hash_chain_len: chain_len,
        rows,
        keygen,
        prove,
        verify: verify_dur,
        verified,
        proof_bytes,
        proof_sha256_hex,
    })
}

/// Native entry point: constructs the default
/// `MidnightDataProvider` (filesystem-backed SRS cache, on-demand
/// download from `srs.midnight.network`) and delegates to
/// [`run_proof_with_params`]. Compiled out on wasm targets where
/// there's no filesystem; the wasm wrapper crate calls
/// `run_proof_with_params` directly.
#[cfg(not(target_arch = "wasm32"))]
pub async fn run_proof_with_opts(k: u32, opts: RunOpts) -> Result<RunStats> {
    let params = make_zswap_resolver(opts.cache_dir.as_deref())?;
    run_proof_with_params(k, &opts, &params.0).await
}

/// Convenience wrapper: `run_proof_with_opts(k, RunOpts::default())`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn run_proof(k: u32) -> Result<RunStats> {
    run_proof_with_opts(k, RunOpts::default()).await
}

/// Run only the IR-build + `IrSource::keygen` step for `k` and store
/// the resulting `(pk, vk)` pair in the process-wide `KEY_CACHE`.
/// A subsequent `run_proof_with_opts(k, …)` with `opts.cache_keys =
/// true` then hits the cache and skips keygen entirely.
///
/// This is the back-end for the FFI-side `warm_keygen` prefetch:
/// the FFI fires this on a background worker thread immediately
/// after a `prove(k)` call so the next iteration's keygen overlaps
/// with the current iteration's prove. Honours `opts.cache_dir`
/// for the SRS lookup just like `run_proof_with_opts`.
///
/// Returns `Ok(())` on success — discards timing information; the
/// caller is expected to be fire-and-forget.
#[cfg(not(target_arch = "wasm32"))]
pub async fn keygen_for_k(k: u32, opts: &RunOpts) -> Result<()> {
    if !(MIN_K..=MAX_K).contains(&k) {
        return Err(Error::KOutOfRange { requested: k });
    }
    // Skip work if the key cache already has this k. Saves the IR
    // build for the common "already warmed by a prior prove" case.
    if opts.cache_keys && key_cache_lookup(k).is_some() {
        return Ok(());
    }
    let params = make_zswap_resolver(opts.cache_dir.as_deref())?;
    let (ir, _chain_len) = build_ir_for_k(k)?;
    let pair = ir
        .keygen(&params.0)
        .await
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("keygen: {e}")))?;
    if opts.cache_keys {
        key_cache_store(k, pair);
    }
    Ok(())
}

/// R6 — embedded `ProvingProvider.prove` equivalent.
///
/// Takes the same bytes the upstream `midnight-proof-server` /prove
/// HTTP endpoint accepts (minus the versioned envelope — the TS
/// adapter does the un-wrapping), runs the proof in-process, and
/// returns the serialised proof bytes. This is the byte-for-byte
/// drop-in replacement for the HTTP `proof-provider.prove` call
/// from the Midnight TS SDK.
///
/// Wiring:
///   - The TS host (`packages/react-native-prover/src/
///     nativeProvingProvider.ts`) marshals the four byte-blobs from
///     `ZKConfigProvider.{getZKIR, getProverKey, getVerifierKey}`
///     plus the witness `ProofPreimage` from the upstream
///     `createProvingPayload`.
///   - This function deserialises them into typed Rust objects,
///     reuses the existing `ChainResolver` machinery, and calls
///     `preimage.prove::<IrSource>(...)`.
///
/// Inputs:
///   `preimage_bytes`    — tagged-serialised `ProofPreimage`.
///   `prover_key_bytes`  — tagged-serialised `ProverKey<IrSource>`.
///   `verifier_key_bytes` — tagged-serialised `VerifierKey`.
///   `zkir_bytes`        — tagged-serialised `IrSource`.
///   `seed`              — RNG seed for prove. 0 = library default.
///   `cache_dir`         — SRS cache dir (same MIDNIGHT_PP semantics
///                          as the bench path). `None` = use the
///                          resolver chain's default.
///
/// Output: serialised proof bytes (tagged_serialize of `Proof`).
#[cfg(not(target_arch = "wasm32"))]
/// R9 — Circuit-check entry point for embedded provers.
///
/// Mirrors what the HTTP proof-server's `POST /check` endpoint does:
/// deserialise the preimage + zkir, run the witness-generation
/// validation step, and return the `pi_skips` vector (which slots
/// of the public-inputs vector are derived vs unset).
///
/// The Midnight TS SDK's `createProofProvider` calls `.check` before
/// `.prove` for every transaction. Without this entry the embedded
/// (in-process) prover path can't claim full ProvingProvider
/// compatibility — callers would have to bypass the SDK's standard
/// flow. With it, swapping `httpClientProofProvider` for
/// `nativeProvingProvider(zkConfigProvider)` is a single-line drop-in.
///
/// Returns one entry per public-input slot. `Some(i)` means the slot
/// is bound to witness index `i`; `None` means the slot is skipped
/// (no witness binding, value comes from the public transcript).
pub fn circuit_check_bytes(
    preimage_bytes: &[u8],
    zkir_bytes: &[u8],
) -> Result<Vec<Option<usize>>> {
    use serialize::tagged_deserialize;
    use transient_crypto::proofs::ProofPreimage;
    use zkir::IrSource;

    let preimage: ProofPreimage = tagged_deserialize(&mut &preimage_bytes[..])
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("deserialize preimage: {e}")))?;
    let ir: IrSource = tagged_deserialize(&mut &zkir_bytes[..])
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("deserialize zkir: {e}")))?;

    // ProofPreimage::check is sync — no params/resolver needed, just
    // the witness-generation check that runs locally. Same code path
    // as the upstream HTTP /check.
    preimage
        .check(&ir)
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("circuit_check: {e}")))
}

pub async fn circuit_prove_bytes(
    preimage_bytes: &[u8],
    prover_key_bytes: &[u8],
    verifier_key_bytes: &[u8],
    zkir_bytes: &[u8],
    seed: u64,
    cache_dir: Option<PathBuf>,
    binding_input_override: Option<&[u8]>,
) -> Result<Vec<u8>> {
    use serialize::tagged_deserialize;

    bench_phase("circuit_prove.start", 0);

    let mut preimage: ProofPreimage = tagged_deserialize(&mut &preimage_bytes[..])
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("deserialize preimage: {e}")))?;
    // R10 — apply the fee-binding override, matching the upstream
    // ProvingProvider::prove(preimage, Some(Fr)) semantics. The
    // Midnight TS SDK passes this for every callTx so the wallet
    // can bind transaction fees into the proof.
    //
    // Wire format: little-endian Fr bytes. We use Fr::from_le_bytes
    // here (NOT Fr::deserialize via Serializable) because Fr's
    // Serializable impl is SCALE-codec variable-length, not raw
    // 32-byte LE. Matches the wallet-sdk-prover-client → zkir-wasm
    // path which also uses Fr::from_le_bytes.
    if let Some(bi_bytes) = binding_input_override {
        let bi = Fr::from_le_bytes(bi_bytes).ok_or_else(|| {
            Error::Anyhow(anyhow::anyhow!(
                "binding_input_override out of range for the BLS scalar field"
            ))
        })?;
        preimage.binding_input = bi;
    }
    let pk: ProverKey<IrSource> = tagged_deserialize(&mut &prover_key_bytes[..])
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("deserialize prover_key: {e}")))?;
    let vk: VerifierKey = tagged_deserialize(&mut &verifier_key_bytes[..])
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("deserialize verifier_key: {e}")))?;
    let ir: IrSource = tagged_deserialize(&mut &zkir_bytes[..])
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("deserialize zkir: {e}")))?;

    bench_phase("circuit_prove.deserialised", 0);

    let params = make_zswap_resolver(cache_dir.as_deref())?;
    let resolver = ChainResolver {
        pk,
        vk,
        ir,
        k: 0, // not used on the prove-only path (no gz-cache filename derivation)
        pk_gz_cache_dir: cache_dir.clone(),
    };

    bench_phase("circuit_prove.prove.start", 0);

    let seed = if seed == 0 { 0x42 } else { seed };
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (proof, _pi_skips) = preimage
        .prove::<IrSource>(&mut rng, &params.0, &resolver)
        .await
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("circuit_prove: {e}")))?;

    bench_phase("circuit_prove.prove.end", 0);

    let mut out = Vec::new();
    tagged_serialize(&proof, &mut out)
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("serialize proof: {e}")))?;

    bench_phase("circuit_prove.end", 0);
    Ok(out)
}

fn make_preimage() -> ProofPreimage {
    ProofPreimage {
        inputs: vec![Fr::from(1u64)],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        binding_input: Fr::from(42u64),
        communications_commitment: None,
        key_location: KeyLocation(std::borrow::Cow::Borrowed("contract-benchmark")),
    }
}

/// Mirror of `MidnightDataProvider::new`'s cache-dir resolution chain
/// (`$MIDNIGHT_PP` → `$XDG_CACHE_HOME/midnight/zk-params` →
/// `$HOME/.cache/midnight/zk-params`), so the on-disk gzipped-PK cache
/// can light up even when the caller doesn't pass `--cache-dir`.
/// Returns `None` only when none of those env vars are set.
#[cfg(not(target_arch = "wasm32"))]
fn default_pk_gz_cache_dir() -> Option<PathBuf> {
    std::env::var_os("MIDNIGHT_PP")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_CACHE_HOME")
                .map(|p| PathBuf::from(p).join("midnight").join("zk-params"))
        })
        .or_else(|| {
            std::env::var_os("HOME").map(|p| {
                PathBuf::from(p)
                    .join(".cache")
                    .join("midnight")
                    .join("zk-params")
            })
        })
}

/// Filesystem-backed params resolver — uses the standard
/// `MidnightDataProvider` on-demand fetch path. Native-only; the
/// wasm crate constructs its own JS-backed provider.
#[cfg(not(target_arch = "wasm32"))]
fn make_zswap_resolver(cache_dir: Option<&std::path::Path>) -> Result<Arc<ZswapResolver>> {
    if let Some(dir) = cache_dir {
        std::fs::create_dir_all(dir)?;
        if std::env::var_os("MIDNIGHT_PP").is_none() {
            // SAFETY: same rationale as prover-core's params.rs — set
            // once at construction, value supplied by the caller.
            unsafe {
                std::env::set_var("MIDNIGHT_PP", dir);
            }
        }
    }
    // `MIDNIGHT_NO_FETCH=1` switches the provider to `Synchronous`
    // mode: `get_file` reads from the local SRS cache only and never
    // builds a reqwest client. We use this on Android, where the
    // transitive `rustls-platform-verifier` dep panics on first
    // construction without a JVM/JNI context. The smoke-test binary
    // sets this env var when running under `adb shell` (no JNI host
    // around), and the operator pre-pushes the required SRS files
    // with `adb push` before kicking off the run. Production
    // RN/iOS prove paths leave the env var unset and keep the
    // existing `OnDemand` behaviour.
    let no_fetch = matches!(
        std::env::var("MIDNIGHT_NO_FETCH").as_deref(),
        Ok("1") | Ok("true"),
    );
    let fetch_mode = if no_fetch {
        FetchMode::Synchronous
    } else {
        FetchMode::OnDemand
    };
    let provider = MidnightDataProvider::new(
        fetch_mode,
        OutputMode::Log,
        ZSWAP_EXPECTED_FILES.to_vec(),
    )?;
    Ok(Arc::new(ZswapResolver(provider)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity-check: every `k` in 1..=MAX_K builds a valid IR. Prints
    /// the realised k / row count / chain length so we can document
    /// the realised distribution in the README. Some low-k targets are
    /// naturally floored by halo2 baseline overhead (min realised k is
    /// observed empirically and recorded in `EFFECTIVE_FLOOR_K`).
    #[test]
    fn every_k_builds() {
        let mut last_realised: u32 = 0;
        for k in MIN_K..=MAX_K {
            let (ir, chain) = build_ir_for_k(k).unwrap_or_else(|e| {
                panic!("k={k} failed to build: {e:?}");
            });
            let got = ir.model().k() as u32;
            let rows = ir.model().rows();
            eprintln!(
                "k={k:>2}: realised={got:>2} chain={chain:>8} rows={rows}"
            );
            // Realised k must be monotonically non-decreasing in k —
            // requesting a bigger circuit never produces a smaller one.
            assert!(
                got >= last_realised,
                "k={k}: realised k={got} regressed from prior {last_realised}"
            );
            last_realised = got;
        }
    }

    /// Runs prove+verify for the smallest configured k. Requires
    /// `bls_midnight_2p4`-or-smaller params on disk (or network access
    /// to download them on first call). Slow: marked `ignore` by default.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "slow; pulls SRS from disk or network"]
    async fn smoke_k4() {
        let stats = run_proof(4).await.unwrap();
        assert_eq!(stats.k, 4);
        assert_eq!(stats.realized_k, 4);
        assert_eq!(stats.verified, Some(true));
    }
}
