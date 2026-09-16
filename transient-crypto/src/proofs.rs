// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module provides access to creating, and verifying zero-knowledge
//! proofs. It assumes that keys and IR are generated externally, which is the
//! focus of [Compact](https://github.com/input-output-hk/compactc).

use crate::curve::{Fr, outer};
use base_crypto::hash::{HashOutput, persistent_hash};
use derive_where::derive_where;
use lazy_static::lazy_static;
use lru::LruCache;
use midnight_curves::Bls12;
use midnight_proofs::{
    poly::kzg::params::{ParamsKZG, ParamsVerifierKZG},
    utils::SerdeFormat,
};
use midnight_zk_stdlib::{MidnightVK, Relation};
#[cfg(feature = "proptest")]
use proptest::arbitrary::Arbitrary;
#[cfg(feature = "proptest")]
use proptest_derive::Arbitrary;
use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::Error as SerError};
use serialize::{
    Deserializable, Serializable, Tagged, VecExt, tag_enforcement_test, tagged_deserialize,
};
#[cfg(feature = "proptest")]
use serialize::{NoStrategy, simple_arbitrary};
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::io::{self, Read, Seek};
#[cfg(feature = "proptest")]
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use std::{any::Any, cmp::Ordering};
use std::{borrow::Cow, num::NonZeroUsize};
use storage_core::Storable;
use storage_core::arena::ArenaKey;
use storage_core::db::DB;
use storage_core::storable::Loader;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// How `ParamsProverProvider::get_params` loads the SRS.
///
/// The same argument as `midnight_proofs::config::ProverConfig`, one crate up:
/// two variables read inline are invisible in every signature, cannot differ
/// between two providers in one process, and cannot be exercised by a test
/// without mutating process environment — which is `unsafe` under Rust 2024
/// and races every other test in the binary.
///
/// The variables still work and mean what they meant; they are parsed in one
/// place instead of at their use sites.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParamsLoadPolicy {
    /// Build the mmap companion file on first miss, paying a transient 2×
    /// peak to write it out. A one-shot desktop precompute — a device should
    /// ship the resulting file rather than build it.
    pub build_mmap_companion: bool,

    /// Skip parsing `g_lagrange` and recompute it on first use. Trades one
    /// inverse NTT for peak RAM during the parse; worth it only where the
    /// recompute amortises over a long idle period, and a clear loss in a
    /// tight prove loop.
    pub lazy_params: bool,
}

impl ParamsLoadPolicy {
    /// Read the policy from the environment. The only place this crate does so.
    ///
    /// | variable | field |
    /// |---|---|
    /// | `MIDNIGHT_MMAP_BUILD` | [`build_mmap_companion`](Self::build_mmap_companion) |
    /// | `MIDNIGHT_LAZY_PARAMS` | [`lazy_params`](Self::lazy_params) |
    pub fn from_env() -> Self {
        let flag = |name: &str| matches!(std::env::var(name).as_deref(), Ok("1") | Ok("true"));
        Self {
            build_mmap_companion: flag("MIDNIGHT_MMAP_BUILD"),
            lazy_params: flag("MIDNIGHT_LAZY_PARAMS"),
        }
    }

    /// The process-wide policy, read once.
    pub fn process() -> Self {
        static POLICY: std::sync::OnceLock<ParamsLoadPolicy> = std::sync::OnceLock::new();
        *POLICY.get_or_init(ParamsLoadPolicy::from_env)
    }
}

/// A provider of prover parameters.
pub trait ParamsProverProvider {
    // Allowed because we don't care about auto traits here.
    #[allow(async_fn_in_trait)]
    /// Retrieve the parameters for a given `k` value
    async fn get_params(&self, k: u8) -> io::Result<ParamsProver>;
}

/// The hash used during proof transcript processing
pub type TranscriptHash = blake2b_simd::State;

impl ParamsProverProvider for base_crypto::data_provider::MidnightDataProvider {
    async fn get_params(&self, k: u8) -> io::Result<ParamsProver> {
        let name = Self::name_k(k);

        // Paths A and A' are the mmap companion fast paths, and they
        // exist only where `mmap(2)` does. Both are `return`s, so a
        // target without them simply falls through to Path B below —
        // which is a real path producing identical parameters, not a
        // stub. Slower, and that is the correct trade for a target
        // that cannot map a file at all.
        //
        // Gated as one block rather than per-statement: this is the
        // whole host-only region, and splitting it would scatter `cfg`
        // through a function whose shape is otherwise portable.
        #[cfg(not(target_family = "wasm"))]
        {
            // Path A — a published mmap companion. The companion is a
            // `bls_midnight_2pN.mmap` file the cache published earlier
            // (typically built once on a roomy desktop and pushed to the
            // device). When found we go zero-copy: `ParamsKZG.g`/
            // `g_lagrange` become slice views into the file mapping and
            // the OS pages handle eviction under memory pressure. Trigger
            // is file presence, not an env var, so the optimisation lights
            // up automatically wherever the companion is shipped.
            //
            // Everything companion-shaped goes through `CompanionCache`:
            // it is the one place that may create a companion, and it never
            // rewrites a published inode, which is what keeps every live
            // mapping sound.
            let cache = CompanionCache::new(self.dir.clone());
            if let Some(mapped) = cache.open(&name)? {
                tracing::info!(
                    target: "midnight_bench",
                    stage = "load_mmap",
                    k = k as u64,
                );
                return Ok(mapped);
            }

            // Path A' — build the companion on first miss. Opt-in via
            // `MIDNIGHT_MMAP_BUILD=1` because the build step briefly
            // pays the 2× eager-load peak (we hold the just-parsed
            // `ParamsProver` AND write its bytes out). Useful as a
            // one-shot precompute on a desktop; the device should just
            // ship the resulting `.mmap` files. Concurrent first builders
            // are fine: the cache publishes by atomic rename with one
            // winner, and a loser opens the winner's complete file.
            if ParamsLoadPolicy::process().build_mmap_companion {
                tracing::info!(
                    target: "midnight_bench",
                    stage = "build_mmap_companion",
                    k = k as u64,
                );
                let reader = self
                    .get_file(
                        &name,
                        &format!("public parameters for k={k} not found in cache"),
                    )
                    .await?;
                let eager = ParamsProver::read(reader)?;
                return cache.open_or_build(&name, || Ok(eager));
            }
        }

        // Path B — eager `read_custom` (default) or seekable
        // skip-g_lagrange `read_custom_lazy` when
        // `MIDNIGHT_LAZY_PARAMS=1`. The lazy variant trades CPU
        // (one inverse-NTT recompute per first commit_lagrange) for
        // peak RAM during file parse.
        let reader = self
            .get_file(
                &name,
                &format!("public parameters for k={k} not found in cache"),
            )
            .await?;
        if ParamsLoadPolicy::process().lazy_params {
            ParamsProver::read_lazy(reader)
        } else {
            ParamsProver::read(reader)
        }
    }
}

/// A specific instance of the prover parameters.
#[derive(Clone)]
pub struct ParamsProver(pub Arc<ParamsKZG<Bls12>>);

impl AsRef<ParamsKZG<Bls12>> for ParamsProver {
    fn as_ref(&self) -> &ParamsKZG<Bls12> {
        &self.0
    }
}

impl ParamsProver {
    /// Reads the prover parameters from a data stream.
    ///
    /// Eager — parses both `g` and `g_lagrange` from the file. Peak
    /// resident heap during the parse is 2× the SRS size.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(ParamsProver(Arc::new(ParamsKZG::read_custom(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )?)))
    }

    /// Constructs prover parameters by memory-mapping a companion
    /// SRS file laid out by [`write_mmap_companion`](Self::write_mmap_companion).
    ///
    /// The returned `ParamsProver` holds an `Arc<Mmap>` internally;
    /// `g` and `g_lagrange` are slice views into the mapping, so
    /// the SRS contributes **zero heap allocation**. Touched pages
    /// count against RSS but the OS evicts cold pages under
    /// memory pressure — the win is during the heavy prove phases
    /// when FFT scratch dominates and the SRS is referenced only
    /// at the MSM call sites.
    ///
    /// Available only against the patched `midnight-proofs` fork, and
    /// only on targets that have `mmap(2)`. On wasm the method is
    /// absent rather than failing at runtime: `read_mmap_arc` is itself
    /// behind the fork's `mmap` feature there, so calling this could
    /// never have worked.
    ///
    /// # Safety
    ///
    /// A mapping is only sound while the mapped file is not modified or
    /// truncated by anyone — `memmap2::Mmap::map` states it, and a shortened
    /// or rewritten file behind a live `&[E::G1]` is undefined behaviour, not
    /// merely a wrong proof. This function maps **an arbitrary path**, so the
    /// caller must guarantee that no process will write to or truncate that
    /// file for as long as the returned value, or any clone of it, lives.
    ///
    /// The safe way to get a mapped `ParamsProver` is [`CompanionCache`],
    /// which only ever maps files it published itself and never rewrites a
    /// published inode. Use this function only for a file with an equivalent
    /// guarantee that this crate cannot see.
    ///
    /// # Trust boundary
    ///
    /// The companion is a local cache, not an interchange format: never fetch
    /// it, never sync it between devices, never accept one from another party.
    ///
    /// The header is validated before anything is mapped — magic, point size,
    /// every offset and count, and each block's alignment — so a malformed
    /// file fails with `InvalidData`. The *contents* are not: bytes inside a
    /// well-formed block become `E::G1` values without a curve check. A
    /// hostile file therefore produces wrong proofs rather than memory
    /// corruption, and only because every bit pattern is valid for the
    /// underlying field representation.
    #[cfg(not(target_family = "wasm"))]
    #[allow(unsafe_code)]
    pub unsafe fn read_mmap_path<P: AsRef<std::path::Path>>(path: P) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        // SAFETY: the caller has promised (see `# Safety`) that nothing will
        // modify or truncate this file while the mapping lives; that is the
        // whole obligation `Mmap::map` places on us, and it is the reason this
        // function is `unsafe` rather than documented-and-safe.
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        Ok(ParamsProver(Arc::new(ParamsKZG::read_mmap_arc(Arc::new(
            mmap,
        ))?)))
    }

    /// Publish the current params as a companion file at `path`, ready for
    /// [`CompanionCache::open`]. Use after a one-time eager `read` to produce
    /// the file that is then mapped on every subsequent run.
    ///
    /// **A published companion is never rewritten.** The bytes go to a
    /// private temp file in `path`'s directory, are validated and synced, and
    /// land under `path` by one atomic rename that refuses to replace an
    /// existing file. If `path` already exists this returns
    /// [`io::ErrorKind::AlreadyExists`] and leaves it untouched — some process
    /// may hold a mapping of that inode, and truncating it under them is the
    /// fault this crate does not commit. A caller that only needs *a*
    /// companion to exist should use [`CompanionCache::open_or_build`].
    ///
    /// Host-only for the same reason as [`read_mmap_path`](Self::read_mmap_path):
    /// writing a companion nothing on this target can map back is not a
    /// useful thing to be able to do.
    #[cfg(not(target_family = "wasm"))]
    pub fn write_mmap_companion<P: AsRef<std::path::Path>>(&self, path: P) -> io::Result<()> {
        let path = path.as_ref();
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "companion path must have a parent directory",
                )
            })?;
        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "companion path must name a file",
            )
        })?;
        match CompanionCache::new(dir)
            .publish_file(file_name, |file| self.0.write_mmap_companion(file))?
        {
            PublishOutcome::Published => Ok(()),
            PublishOutcome::AlreadyPublished => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "companion {} is already published; a published companion is never rewritten \
                     (it may be mapped) — use CompanionCache::open_or_build to reuse it",
                    path.display()
                ),
            )),
        }
    }

    /// Reads the prover parameters from a seekable data stream,
    /// skipping the on-disk `g_lagrange` block. The Lagrange basis is
    /// recomputed via inverse-NTT of `g` on first use and cached
    /// thereafter.
    ///
    /// Peak resident heap during the parse stays at 1× the SRS size
    /// (no second `Vec` is allocated). The first `commit_lagrange`
    /// in any subsequent prove pays one FFT to populate the cache.
    ///
    /// Available only against the patched `midnight-proofs` fork at
    /// `[patch.crates-io]`. Falls back to `read` if absent.
    pub fn read_lazy<R: Read + Seek>(mut reader: R) -> io::Result<Self> {
        Ok(ParamsProver(Arc::new(ParamsKZG::read_custom_lazy(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )?)))
    }

    pub(crate) fn as_verifier(&self) -> ParamsVerifier {
        ParamsVerifier(Arc::new(self.0.verifier_params()))
    }
}

/// What [`CompanionCache::publish_file`] did.
#[cfg(not(target_family = "wasm"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Our bytes were validated and now sit under the final name.
    Published,
    /// Another publisher won the rename; our temp file was discarded and the
    /// winner's complete file is the one to open.
    AlreadyPublished,
}

/// The one safe way to create and map SRS companion files.
///
/// A companion (`<name>.mmap`) is a memory-mapped cache of an SRS. Mapping is
/// only sound while the mapped file is never modified or truncated, so the
/// cache enforces the discipline the rest of this crate relies on:
///
/// - **A published inode is never rewritten.** Bytes go to a uniquely named
///   private temp file in the same directory, are validated by mapping them
///   through the same header checks a reader performs, are `sync_all`ed, and
///   then reach the final name by *one* atomic rename that refuses to replace
///   an existing file (`persist_noclobber`). Nothing this crate does can
///   shorten a file some other mapping holds.
/// - **Concurrent first builders have one winner.** Every builder writes its
///   own temp file; the first rename wins, every other publisher gets
///   [`PublishOutcome::AlreadyPublished`], drops its temp file and opens the
///   winner's complete file. No lock file, no partial header: a reader that
///   sees the final name sees a complete, validated file, because the name
///   appears only after the rename.
/// - **Crash recovery is cleanup, not repair.** A crash before the rename
///   leaves a `.<name>.mmap.tmp-*` file behind; the next publisher removes
///   temp files older than [`Self::STALE_TEMP_AGE`] before it starts. A crash
///   after the rename left a complete file. The directory entry is fsynced
///   after publication on Unix so the rename itself is durable.
///
/// # Trust boundary
///
/// The guarantee is against *this crate*: nothing here writes to a published
/// companion. It cannot be a guarantee against every other process. The
/// cache directory must be one where only cooperating code writes — the
/// application's own cache directory, not a shared or user-editable one. That
/// is the same trust already placed in the SRS files beside the companions;
/// a companion fetched, synced, or accepted from another party is outside it.
/// Mapping an arbitrary path that offers no such guarantee is
/// [`ParamsProver::read_mmap_path`], which is `unsafe` for exactly this
/// reason.
#[cfg(not(target_family = "wasm"))]
#[derive(Clone, Debug)]
pub struct CompanionCache {
    dir: std::path::PathBuf,
}

#[cfg(not(target_family = "wasm"))]
impl CompanionCache {
    /// Temp files older than this are treated as left by a crashed
    /// publisher and removed before a new publication starts. An hour is far
    /// beyond any companion write; a live publisher's temp file is seconds
    /// old.
    pub const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

    const TEMP_INFIX: &'static str = ".tmp-";

    /// A cache rooted at `dir`. See the type-level trust boundary for what
    /// `dir` must be.
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory companions are published into.
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Where the companion for the SRS called `name` lives once published.
    pub fn published_path(&self, name: &str) -> std::path::PathBuf {
        self.dir.join(Self::file_name(name))
    }

    fn file_name(name: &str) -> String {
        format!("{name}.mmap")
    }

    /// The prefix every temp file for `file_name` carries: hidden, and unique
    /// enough that a sweep cannot touch anything else in the directory.
    fn temp_prefix(file_name: &std::ffi::OsStr) -> String {
        format!(".{}{}", file_name.to_string_lossy(), Self::TEMP_INFIX)
    }

    /// Open the published companion for `name`, or `Ok(None)` when none is
    /// published yet. A file that exists is complete by construction; a file
    /// that fails validation is reported as `InvalidData`, never mapped.
    pub fn open(&self, name: &str) -> io::Result<Option<ParamsProver>> {
        let path = self.published_path(name);
        match std::fs::File::open(&path) {
            Ok(file) => Self::map_published(&file).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Open the published companion for `name`, building and publishing it
    /// first when there is none. `build` produces the eager parameters to
    /// publish; it may run in more than one process at once, and only one
    /// result is published — the others are discarded and their callers open
    /// the winner's file.
    pub fn open_or_build(
        &self,
        name: &str,
        build: impl FnOnce() -> io::Result<ParamsProver>,
    ) -> io::Result<ParamsProver> {
        if let Some(mapped) = self.open(name)? {
            return Ok(mapped);
        }
        let eager = build()?;
        let file_name = Self::file_name(name);
        self.publish_file(std::ffi::OsStr::new(&file_name), |file| {
            eager.0.write_mmap_companion(file)
        })?;
        drop(eager);
        self.open(name)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "companion {} disappeared between publication and open",
                    self.published_path(name).display()
                ),
            )
        })
    }

    /// Publish a companion under `file_name` in this cache's directory from
    /// whatever `write` produces: private same-directory temp file →
    /// validation by the reader's own header checks → `sync_all` →
    /// `persist_noclobber`. On any failure nothing is published and the temp
    /// file is removed. Returns [`PublishOutcome::AlreadyPublished`] when the
    /// final name already exists — before or during this call — and leaves
    /// that file untouched.
    pub fn publish_file(
        &self,
        file_name: &std::ffi::OsStr,
        write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
    ) -> io::Result<PublishOutcome> {
        let final_path = self.dir.join(file_name);
        if final_path.exists() {
            return Ok(PublishOutcome::AlreadyPublished);
        }
        self.sweep_stale_temps(file_name);

        let prefix = Self::temp_prefix(file_name);
        let mut temp = tempfile::Builder::new()
            .prefix(&prefix)
            .tempfile_in(&self.dir)?;
        // `NamedTempFile` removes the file on drop, so every early return
        // below — including the `?`s — leaves no temp file behind.
        write(temp.as_file_mut())?;
        temp.as_file().sync_all()?;
        Self::validate(temp.as_file())?;

        match temp.persist_noclobber(&final_path) {
            Ok(_) => {
                self.sync_dir();
                Ok(PublishOutcome::Published)
            }
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {
                // `e.file` is the temp file; dropping it removes it.
                Ok(PublishOutcome::AlreadyPublished)
            }
            Err(e) => Err(e.error),
        }
    }

    /// Run the reader's header validation over a file we alone hold, before
    /// it can be published. A companion that would fail to open is never
    /// given a name a reader could find.
    #[allow(unsafe_code)]
    fn validate(file: &std::fs::File) -> io::Result<()> {
        // SAFETY: `file` is our private, unpublished temp file — no other
        // party has its name, and this function holds the only mapping for
        // the duration of the check. The mapping is dropped before the rename.
        let mmap = unsafe { memmap2::Mmap::map(file)? };
        ParamsKZG::<Bls12>::read_mmap_arc(Arc::new(mmap)).map(|_| ())
    }

    /// Map a companion this cache published. The soundness argument is the
    /// cache's: nothing in this crate rewrites a published inode, and the
    /// directory is one where only cooperating code writes (type-level trust
    /// boundary).
    #[allow(unsafe_code)]
    fn map_published(file: &std::fs::File) -> io::Result<ParamsProver> {
        // SAFETY: see above — published companions are immutable by
        // construction of this type, which is the invariant `Mmap::map` asks
        // for; the cache directory's write access is the stated trust boundary.
        let mmap = unsafe { memmap2::Mmap::map(file)? };
        Ok(ParamsProver(Arc::new(ParamsKZG::read_mmap_arc(Arc::new(
            mmap,
        ))?)))
    }

    /// Remove temp files for `file_name` left by a publisher that did not
    /// reach its rename. Age-gated so a live publisher's file is never
    /// touched; failures are ignored — a stale temp file is harmless, and the
    /// publication that follows does not depend on the sweep.
    fn sweep_stale_temps(&self, file_name: &std::ffi::OsStr) {
        let prefix = Self::temp_prefix(file_name);
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let now = std::time::SystemTime::now();
        for entry in entries.flatten() {
            let candidate = entry.file_name();
            if !candidate.to_string_lossy().starts_with(&prefix) {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= Self::STALE_TEMP_AGE);
            if stale {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Make the directory entry durable after a publication. Best effort:
    /// filesystems that cannot fsync a directory still have the complete file,
    /// only its name may not survive a power loss — which the next publisher
    /// repairs by publishing again.
    fn sync_dir(&self) {
        #[cfg(unix)]
        {
            if let Ok(dir) = std::fs::File::open(&self.dir) {
                let _ = dir.sync_all();
            }
        }
    }
}

/**
 * The maximum degree supported by the standard verifier key.
 * This limits the number of public inputs usable.
 */
pub const VERIFIER_MAX_DEGREE: u8 = 14;

/// Parameters used for verifying with the `KZG` commitment scheme
#[derive(Clone)]
pub struct ParamsVerifier(Arc<ParamsVerifierKZG<Bls12>>);

impl ParamsVerifier {
    /// Reads in verifier parameters
    pub fn read<R: Read>(reader: R) -> io::Result<Self> {
        Ok(ParamsProver::read(reader)?.as_verifier())
    }
}

const PARAMS_VERIFIER_RAW: &[u8] = include_bytes!("../static/bls_midnight_2p14");

lazy_static! {
    /// The midnight verifier parameters, up to [`VERIFIER_MAX_DEGREE`].
    ///
    /// Note that using this *will* embed these into the binary at compile time, if that's not what
    /// you want, please use `ParamsVerifier::read` instead.
    pub static ref PARAMS_VERIFIER: ParamsVerifier = ParamsVerifier::read(PARAMS_VERIFIER_RAW).expect("Static verifier parameters should be valid.");
}

/// A zero-knowledge proof.
#[cfg_attr(feature = "proptest", derive(Arbitrary))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serializable, Storable)]
#[storable(base)]
#[tag = "proof[v5]"]
pub struct Proof(pub Vec<u8>);
tag_enforcement_test!(Proof);

/// A prover key, used for creating proofs.
#[derive(Clone)]
#[derive_where(Debug; T::ProverKey)]
pub struct ProverKey<T: Zkir>(Arc<Mutex<InnerProverKey<T>>>);

/// An intermediate representation for Midnight's circuits.
#[allow(async_fn_in_trait)]
pub trait Zkir: Any + Send + Sync + Debug + Sized {
    /// The key type used for proving
    type ProverKey: Send + Sync;

    /// Check that a proof preimage satisfies the circuit
    ///
    /// Returns which outputs were skipped in the proof preimage, and how many
    /// zero element to buffer them with. Specifically, because our circuits
    /// compile to JavaScript, and there do not evaluate untaken branches, this
    /// leads to the output of the JavaScript circuit targets omitting public
    /// inputs that occurred in an untaken branch. This information still needs
    /// to be included in the statement vectors, where it is padded with zero
    /// elements.
    ///
    /// Currently, we handle this by grouping the statement vector into 'blocks'
    /// of public inputs, with each block corresponding to exactly one VM
    /// instruction, and running `check` to figure out which blocks were
    /// omitted due to untaken branches, and how many zeros to pad them with.
    ///
    /// Long-term, we probably want to move to make this obsolete, by having the
    /// computer target gather information about untaken branches at run-time.
    fn check(&self, preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, ProvingError>;
    /// Proves a circuit.
    /// Returns the proof, the statement vector, and the skips from `check`.
    async fn prove(
        &self,
        rng: impl Rng + CryptoRng,
        params: &impl ParamsProverProvider,
        pk: ProverKey<Self>,
        preimage: &ProofPreimage,
    ) -> Result<(Proof, Vec<Fr>, Vec<Option<usize>>), ProvingError>;

    /// Returns the k value for this circuit
    fn k(&self) -> u8;

    /// Performs key generation on this circuit, outputting the verifier key
    async fn keygen_vk(
        &self,
        params: &impl ParamsProverProvider,
    ) -> Result<VerifierKey, anyhow::Error>;

    /// Performs key generation on this circuit, outputting the prover/verifier
    /// key pair
    async fn keygen(
        &self,
        params: &impl ParamsProverProvider,
    ) -> Result<(ProverKey<Self>, VerifierKey), anyhow::Error>;

    /// Loads IR from a tagged serialization. Separated from `Deserializable` to allow for
    /// backwards-compatible deserialization of old variants.
    fn load_ir_from_tagged(reader: impl Read + Seek) -> io::Result<Self>;

    /// Loads a prover key from a tagged serialization. Separated from `Deserializable` to allow
    /// for backwards-compatible deserialization of old variants.
    fn load_prover_key_from_tagged(reader: impl Read + Seek) -> io::Result<ProverKey<Self>>;

    /// Reads a raw (untagged) prover key from a byte stream.
    fn read_raw_pk(reader: impl Read) -> io::Result<Self::ProverKey>;
    /// Writes a raw (untagged) prover key to a byte stream.
    fn write_raw_pk(writer: impl Write, pk: &Self::ProverKey) -> io::Result<()>;
}

impl<T: Zkir> PartialEq for ProverKey<T> {
    fn eq(&self, other: &Self) -> bool {
        let mut self_ser = Vec::new();
        let mut other_ser = Vec::new();
        Serializable::serialize(self, &mut self_ser).expect("In-memory serialization must succeed");
        Serializable::serialize(other, &mut other_ser)
            .expect("In-memory serialization must succeed");
        self_ser == other_ser
    }
}

impl<T: Zkir> Eq for ProverKey<T> {}

impl<T: Zkir> Distribution<ProverKey<T>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ProverKey<T> {
        let size: u8 = rng.gen_range(0..32);
        let mut bytes = Vec::with_bounded_capacity(size as usize);
        rng.fill_bytes(&mut bytes);
        ProverKey(Arc::new(Mutex::new(InnerProverKey::Uninitialized(bytes))))
    }
}

#[derive(Debug, Clone)]
pub(crate) enum InnerProverKey<T: Zkir> {
    Uninitialized(Vec<u8>),
    Invalid(Vec<u8>),
    Initialized(Arc<T::ProverKey>),
}

impl<T: Zkir + Tagged> Tagged for ProverKey<T> {
    fn tag() -> Cow<'static, str> {
        Cow::Owned(format!("prover-key[v7]({})", T::tag()))
    }
    fn tag_unique_factor() -> String {
        format!("prover-key[v7]({})", T::tag())
    }
}

const PK_CACHE_SIZE: usize = 5;
/// Schema version for the on-disk prover-key blob consumed by
/// [`ProverKey::warm_pk_cache_with_disk`]. Bump when any input that
/// changes the serialized prover-key bytes changes (PK layout, gzip
/// settings, etc.) so stale blobs from before the change get
/// invalidated by filename instead of producing silent cache misses.
pub const PK_GZ_CACHE_SCHEMA_VERSION: u32 = 1;

lazy_static! {
    // forall<T> Arc<MidnightPK<T>>
    static ref PK_CACHE: Mutex<LruCache<HashOutput, Arc<dyn Any + Send + Sync>>> =
        Mutex::new(LruCache::new(NonZeroUsize::new(PK_CACHE_SIZE).unwrap()));
}

impl<T: Zkir> InnerProverKey<T> {
    fn try_cache(&mut self) {
        let hash = match self {
            InnerProverKey::Uninitialized(data) => persistent_hash(&data[..]),
            _ => return,
        };
        if let Some(pk) = PK_CACHE
            .lock()
            .ok()
            .and_then(|mut c| c.get(&hash).cloned())
            .and_then(|ptr| ptr.downcast().ok())
        {
            *self = InnerProverKey::Initialized(pk);
        }
    }
}

impl<T: Zkir> ProverKey<T> {
    /// Constructs a `ProverKey` from an already-initialized raw inner key.
    pub fn from_raw(raw: T::ProverKey) -> Self {
        ProverKey(Arc::new(Mutex::new(InnerProverKey::Initialized(Arc::new(
            raw,
        )))))
    }

    /// Initializes the lazy prover key
    pub fn init(&self) -> Result<Arc<T::ProverKey>, ProvingError> {
        let mut mutex = self.0.lock().expect("mutex is not poisoned");
        mutex.try_cache();
        let data = match &*mutex {
            InnerProverKey::Initialized(key) => {
                return Ok(key.clone());
            }
            InnerProverKey::Invalid(_) => {
                return Err(anyhow::anyhow!("known invalid verifier key"));
            }
            InnerProverKey::Uninitialized(data) => data.clone(),
        };
        let mut inner_reader = &mut &data[..];
        let read_inner = |inner_reader| {
            let pk = T::read_raw_pk(inner_reader)?;
            Ok(pk)
        };
        let res: Result<_, ProvingError> = read_inner(&mut inner_reader);
        match res {
            Ok(pk) => {
                let key = Arc::new(pk);
                PK_CACHE
                    .lock()
                    .ok()
                    .and_then(|mut c| c.put(persistent_hash(&data), key.clone()));
                *mutex = InnerProverKey::Initialized(key.clone());
                Ok(key)
            }
            Err(e) => {
                *mutex = InnerProverKey::Invalid(data);
                Err(e)
            }
        }
    }

    /// Pre-populate the process-wide `PK_CACHE` so that a subsequent
    /// `tagged_deserialize::<ProverKey<T>>` of bytes produced by
    /// serialising **this** key returns a `ProverKey` sharing the
    /// same `Arc<T::ProverKey>` — no rebuild and no extended-domain
    /// FFT recomputation.
    ///
    /// Designed for `Resolver::resolve_key` impls that hold an
    /// initialized `ProverKey` in process memory and feed it into
    /// the bytes-based prover pipeline. The bytes API at the prover
    /// boundary is preserved; the consumer's `try_cache` hits the
    /// freshly-inserted entry instead of paying the multi-GiB
    /// rebuild.
    ///
    /// # What is and is not measured
    ///
    /// The rebuild was observed at roughly 1.3 GiB for BLS12-381 at
    /// k=18 during early mobile work. That figure has not been
    /// reproduced on the current implementation and no k=20 figure was
    /// ever taken — the ~5 GiB that used to appear here was
    /// extrapolated from it, not measured.
    ///
    /// This doc previously called the rebuild *the main reason* a k=20
    /// proof dies on mobile. The laptop sweep does not support that:
    /// mapping the prover key is close to neutral on its own, and the
    /// memory that actually moves at k=20 is the coset working set
    /// (14.26 → 6.04 GiB physical footprint, and only with the coset
    /// spill enabled). Skipping the rebuild is worth doing and is not
    /// the dominant term.
    ///
    /// Numbers per `k`, host class and concurrency are being collected
    /// separately; until then, treat the figure above as an
    /// unreproduced observation rather than a benchmark.
    ///
    /// Returns `Ok(true)` if the key was `Initialized` and the
    /// cache was warmed; `Ok(false)` if the key was
    /// `Uninitialized`/`Invalid` (nothing to share).
    pub fn warm_pk_cache(&self) -> std::io::Result<bool> {
        let arc_pk = {
            let mutex = self.0.lock().expect("mutex not poisoned");
            match &*mutex {
                InnerProverKey::Initialized(key) => key.clone(),
                _ => return Ok(false),
            }
        };

        // Compute the exact bytes the consumer-side `try_cache` will
        // hash. Going through `T::write_raw_pk` is what makes that
        // exact rather than hopeful: `inner_serialize` writes an
        // `Initialized` key with the very same call, and the peer's
        // `deserialize` hashes what it reads back. Re-implementing the
        // encoding here — as the ledger-8 version did, gzipping in this
        // crate — would leave two copies that must agree by convention,
        // and a drift between them is silent: every lookup misses and
        // the multi-GiB rebuild happens anyway.
        let mut inner_buf = Vec::new();
        T::write_raw_pk(&mut inner_buf, &arc_pk)?;

        let hash = persistent_hash(&inner_buf);
        if let Ok(mut c) = PK_CACHE.lock() {
            c.put(hash, arc_pk as Arc<dyn Any + Send + Sync>);
        }
        Ok(true)
    }

    /// Like [`ProverKey::warm_pk_cache`], but persists the serialized PK
    /// blob to `gz_cache_path` on first miss and re-uses it from disk on
    /// subsequent process invocations. `T::write_raw_pk`'s output is
    /// deterministic for a given `(PK layout, SRS, IR)`, so the cached
    /// blob is safe to share across runs as long as none of those
    /// inputs change.
    ///
    /// Safety / correctness: if the file on disk is stale (a different
    /// PK), the `persistent_hash` registered in `PK_CACHE` simply will
    /// not match the consumer side's `try_cache` lookup hash, which is
    /// computed from the bytes the resolver actually ships. The cache
    /// entry is then dead weight and the consumer falls back to the
    /// regular rebuild path — no correctness hazard, just no speed-up.
    /// Cache schema is versioned via [`PK_GZ_CACHE_SCHEMA_VERSION`];
    /// embed it in the caller's filename so a schema bump invalidates
    /// stale files cleanly.
    ///
    /// Returns `Ok(true)` if the cache was warmed (from disk or after
    /// a fresh serialize + persist), `Ok(false)` if the key was not
    /// `Initialized`.
    pub fn warm_pk_cache_with_disk(
        &self,
        gz_cache_path: &std::path::Path,
    ) -> std::io::Result<bool> {
        let arc_pk = {
            let mutex = self.0.lock().expect("mutex not poisoned");
            match &*mutex {
                InnerProverKey::Initialized(key) => key.clone(),
                _ => return Ok(false),
            }
        };

        // Fast path: disk hit. Read the blob, hash it, install in
        // PK_CACHE keyed by that hash. No re-serialize on the prove
        // critical path.
        if let Ok(disk_bytes) = std::fs::read(gz_cache_path)
            && !disk_bytes.is_empty()
        {
            let hash = persistent_hash(&disk_bytes);
            if let Ok(mut c) = PK_CACHE.lock() {
                c.put(hash, arc_pk as Arc<dyn Any + Send + Sync>);
            }
            return Ok(true);
        }

        // Slow path: re-serialize, persist atomically, warm PK_CACHE.
        // The serialize itself is exactly the work `warm_pk_cache`
        // does — we just additionally write it out so the next process
        // can skip it.
        let mut inner_buf = Vec::new();
        T::write_raw_pk(&mut inner_buf, &arc_pk)?;

        let hash = persistent_hash(&inner_buf);
        if let Ok(mut c) = PK_CACHE.lock() {
            c.put(hash, arc_pk as Arc<dyn Any + Send + Sync>);
        }

        // Persist via tmpfile + rename so a crashed write never leaves
        // a half-written cache file. Best-effort: on failure we log
        // and continue — the in-memory PK_CACHE entry is already
        // installed.
        if let Some(parent) = gz_cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp_path = gz_cache_path.with_extension("bin.tmp");
        if let Err(e) = std::fs::write(&tmp_path, &inner_buf)
            .and_then(|_| std::fs::rename(&tmp_path, gz_cache_path))
        {
            tracing::warn!(
                target: "midnight_bench",
                stage = "warm_pk_cache_with_disk.persist_failed",
                path = %gz_cache_path.display(),
                err = %e,
            );
            let _ = std::fs::remove_file(&tmp_path);
        }
        Ok(true)
    }

    fn inner_serialize<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        match &*self.0.lock().expect("mutex is not poisoned") {
            InnerProverKey::Uninitialized(data) | InnerProverKey::Invalid(data) => {
                writer.write_all(data)?;
                Ok(())
            }
            InnerProverKey::Initialized(key) => T::write_raw_pk(&mut writer, key),
        }
    }
}

struct Count(usize);

impl std::io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<T: Zkir> Serializable for ProverKey<T> {
    fn serialize(&self, writer: &mut impl Write) -> std::io::Result<()> {
        let mut count = Count(0);
        self.inner_serialize(&mut count).ok();
        Serializable::serialize(&(count.0 as u64), writer)?;
        self.inner_serialize(writer)
    }

    fn serialized_size(&self) -> usize {
        let mut writer = Count(0);
        self.inner_serialize(&mut writer).ok();
        (writer.0 as u64).serialized_size() + writer.0
    }
}

impl<T: Zkir> Deserializable for ProverKey<T> {
    fn deserialize(reader: &mut impl Read, recursion_depth: u32) -> Result<Self, std::io::Error> {
        let buf = <Vec<u8> as Deserializable>::deserialize(reader, recursion_depth)?;
        let mut pk = InnerProverKey::Uninitialized(buf);
        pk.try_cache();
        Ok(Self(Arc::new(Mutex::new(pk))))
    }
}

/// A verifier key, used for checking proofs.
#[derive(Debug, Storable)]
#[storable(base)]
pub struct VerifierKey(Arc<Mutex<InnerVerifierKey>>);

#[cfg(feature = "proptest")]
simple_arbitrary!(VerifierKey);

impl Tagged for VerifierKey {
    fn tag() -> Cow<'static, str> {
        Cow::Borrowed("verifier-key[v7]")
    }
    fn tag_unique_factor() -> String {
        "verifier-key[v7]".into()
    }
}
tag_enforcement_test!(VerifierKey);

impl Distribution<VerifierKey> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> VerifierKey {
        let size: u8 = rng.r#gen();
        let mut bytes = Vec::with_bounded_capacity(size as usize);
        rng.fill_bytes(&mut bytes);
        VerifierKey(Arc::new(Mutex::new(InnerVerifierKey::Uninitialized(bytes))))
    }
}

impl From<MidnightVK> for VerifierKey {
    fn from(vk: MidnightVK) -> Self {
        let mut raw = Vec::new();
        vk.write(&mut raw, SerdeFormat::Processed)
            .expect("in-memory serialize");
        VerifierKey(Arc::new(Mutex::new(InnerVerifierKey::Initialized(vk, raw))))
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Some features don't try to initialize
#[allow(clippy::large_enum_variant)]
pub(crate) enum InnerVerifierKey {
    Uninitialized(Vec<u8>),
    Invalid(Vec<u8>),
    /// Parsed key alongside the original bytes it was decoded from, so that
    /// serialization stays a function of the value and does not change when a
    /// key is initialized in place (initialization is shared across clones via
    /// the `Arc<Mutex>`).
    Initialized(MidnightVK, Vec<u8>),
}

impl Clone for VerifierKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Deserializable for VerifierKey {
    fn deserialize(
        reader: &mut impl std::io::Read,
        recursion_depth: u32,
    ) -> Result<Self, std::io::Error> {
        const MAX_EXPECTED_SIZE: usize = 50_000;
        let buf = <Vec<u8> as Deserializable>::deserialize(reader, recursion_depth)?;
        if buf.len() > MAX_EXPECTED_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Declared vk size {} exceeded permitted limit of {MAX_EXPECTED_SIZE}",
                    buf.len()
                ),
            ));
        }
        Ok(Self(Arc::new(Mutex::new(InnerVerifierKey::Uninitialized(
            buf,
        )))))
    }
}

#[derive(Clone)]
struct DummyRelation;

// TODO: This is a temporary workaround for verifier key deserialization.
// Longer-term, we'll need to store information about the circuit architecture
// in the verifier key, and use that for deserializing, but those API endpoints
// do not currently exist in midnight-circuits.
impl Relation for DummyRelation {
    type Error = midnight_proofs::plonk::Error;
    type Instance = Vec<outer::Scalar>;
    type Witness = ();
    fn format_instance(
        instance: &Self::Instance,
    ) -> Result<Vec<outer::Scalar>, midnight_proofs::plonk::Error> {
        Ok(instance.clone())
    }
    fn circuit(
        &self,
        _std_lib: &midnight_zk_stdlib::ZkStdLib,
        _layouter: &mut impl midnight_proofs::circuit::Layouter<outer::Scalar>,
        _instance: midnight_proofs::circuit::Value<Self::Instance>,
        _witness: midnight_proofs::circuit::Value<Self::Witness>,
    ) -> Result<(), midnight_proofs::plonk::Error> {
        unimplemented!("should not attempt to execute dummy relation")
    }
    fn read_relation<R: io::Read>(_reader: &mut R) -> io::Result<Self> {
        unimplemented!("should not attempt to read dummy relation")
    }
    fn write_relation<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
        unimplemented!("should not attempt to write dummy relation")
    }
}

impl Serialize for VerifierKey {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut vec = Vec::new();
        <VerifierKey as Serializable>::serialize(self, &mut vec).map_err(S::Error::custom)?;
        ser.serialize_bytes(&vec)
    }
}

impl<'de> Deserialize<'de> for VerifierKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        <VerifierKey as Deserializable>::deserialize(&mut &bytes[..], 0)
            .map_err(serde::de::Error::custom)
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for VerifierKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut data = Vec::new();
        Serializable::serialize(&self, &mut data).ok();
        state.write(&data);
    }
}

impl Serializable for VerifierKey {
    fn serialize(&self, writer: &mut impl Write) -> Result<(), std::io::Error> {
        let mut count = Count(0);
        self.inner_serialize(&mut count).ok();
        Serializable::serialize(&(count.0 as u64), writer)?;
        self.inner_serialize(writer)
    }

    fn serialized_size(&self) -> usize {
        let mut writer = Count(0);
        self.inner_serialize(&mut writer).ok();
        (writer.0 as u64).serialized_size() + writer.0
    }
}

impl VerifierKey {
    /// Initializes the lazy verifier key
    pub fn init(&self) -> Result<(), VerifyingError> {
        self.force_init()?;
        Ok(())
    }

    // warning! This grabs the lock! Make sure to drop the result before re-running!
    #[allow(dead_code)] // Some features don't try to initialize
    pub(crate) fn force_init(&self) -> Result<MidnightVK, VerifyingError> {
        let mut mutex = self.0.lock().expect("mutex is not poisoned");
        let data = match &*mutex {
            InnerVerifierKey::Initialized(key, _) => {
                return Ok(key.clone());
            }
            InnerVerifierKey::Invalid(_) => {
                return Err(anyhow::anyhow!("known invalid verifier key"));
            }
            InnerVerifierKey::Uninitialized(data) => data.clone(),
        };
        let mut slice: &[u8] = &data;
        let vk = MidnightVK::read(&mut slice, SerdeFormat::Processed)
            .map_err(|_| anyhow::anyhow!("problem reading the verifier key"))?;
        // Reject keys with unconsumed trailing bytes: two encodings must not map
        // to the same key, and the trailing bytes would otherwise survive in the
        // preserved-original serialization.
        if !slice.is_empty() {
            return Err(anyhow::anyhow!("trailing bytes after verifier key"));
        }
        *mutex = InnerVerifierKey::Initialized(vk.clone(), data);
        Ok(vk)
    }

    fn inner_serialize<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        match &*self.0.lock().expect("mutex is not poisoned") {
            InnerVerifierKey::Uninitialized(data) | InnerVerifierKey::Invalid(data) => {
                writer.write_all(data)
            }
            InnerVerifierKey::Initialized(_, original) => writer.write_all(original),
        }
    }

    /// Returns the original raw bytes, preserved even after initialization.
    pub fn original_bytes(&self) -> Vec<u8> {
        match &*self.0.lock().expect("mutex is not poisoned") {
            InnerVerifierKey::Uninitialized(data) | InnerVerifierKey::Invalid(data) => data.clone(),
            InnerVerifierKey::Initialized(_, original) => original.clone(),
        }
    }

    /// Checks a proof against a statement.
    pub fn verify<F: Iterator<Item = Fr>>(
        &self,
        params: &ParamsVerifier,
        proof: &Proof,
        statement: F,
    ) -> Result<(), VerifyingError> {
        let vk = self.force_init()?;
        let pi = statement.map(|f| f.0).collect::<Vec<_>>();
        trace!(statement = ?pi, "verifying proof against statement");
        midnight_zk_stdlib::verify::<DummyRelation, TranscriptHash>(
            &params.0, &vk, &pi, None, &proof.0,
        )
        .map_err(|_| anyhow::anyhow!("Invalid proof"))
    }

    /// Mocks the checking of a proof against a statement
    ///
    /// We do this by running a number of CPU burn cycles calculated to be approximately
    /// equivalent in time-taken to real proof verification
    #[cfg(feature = "mock-verify")]
    pub fn mock_verify<F: Iterator<Item = Fr>>(&self, statement: F) -> Result<(), VerifyingError> {
        let pi_len = statement.count();
        crate::mock_verify::mock_verify_for(pi_len)
    }

    /// Checks a sequence of proofs against their corresponding statements and verifier keys
    pub fn batch_verify<
        'a,
        F: Iterator<Item = Fr>,
        V: Iterator<Item = (&'a VerifierKey, &'a Proof, F)>,
    >(
        params: &ParamsVerifier,
        parts: V,
    ) -> Result<(), VerifyingError> {
        use midnight_zk_stdlib::batch_verify;

        let mut vks = vec![];
        let mut pis = vec![];
        let mut proofs = vec![];

        for (vk, proof, stmt) in parts.into_iter() {
            let pi = stmt.map(|f| f.0).collect::<Vec<_>>();
            let vk = vk.force_init()?;
            vks.push(vk);
            pis.push(pi);
            proofs.push(proof.0.clone());
        }

        batch_verify::<TranscriptHash>(&params.0, &vks, &pis, &proofs)
            .map_err(|_| anyhow::anyhow!("Invalid proof"))
    }

    /// Mocks the checking of a sequence of proofs against a statement
    ///
    /// This is simulated by sequentially mocking each individual verification,
    /// it doesn't currently benefit from any performance benefits one should associate
    /// with batching
    #[cfg(feature = "mock-verify")]
    pub fn mock_batch_verify<
        'a,
        F: Iterator<Item = Fr>,
        V: Iterator<Item = (&'a VerifierKey, &'a Proof, F)>,
    >(
        parts: V,
    ) -> Result<(), VerifyingError> {
        for (vk, _proof, stmt) in parts {
            vk.mock_verify(stmt)?;
        }
        Ok(())
    }
}

/// A hint on where keys for a circuit can be found.
///
/// Circuit keys are associated with a string name, and are resolved at proving
/// time against a hash table of provided keys.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serializable)]
#[cfg_attr(feature = "proptest", derive(Arbitrary))]
pub struct KeyLocation(pub Cow<'static, str>);

impl Zeroize for KeyLocation {
    fn zeroize(&mut self) {
        if let Cow::Owned(s) = &mut self.0 {
            s.zeroize();
        }
        self.0 = Cow::Borrowed("");
    }
}

impl Tagged for KeyLocation {
    fn tag() -> Cow<'static, str> {
        Cow::Borrowed("string")
    }
    fn tag_unique_factor() -> String {
        "string".into()
    }
}

#[derive(Serializable)]
#[tag = "wrapped-ir"]
/// A container for just the IR part of [`ProofData`].
pub struct WrappedIr(pub Vec<u8>);
tag_enforcement_test!(WrappedIr);

#[derive(Clone, Serializable)]
#[tag = "proving-data"]
/// A container for the parts required for proving
pub struct ProvingKeyMaterial {
    /// The prover key
    pub prover_key: Vec<u8>,
    /// The verifier key
    pub verifier_key: Vec<u8>,
    /// The IR source
    pub ir_source: Vec<u8>,
}
tag_enforcement_test!(ProvingKeyMaterial);

/// A mechanism to retrieve / resolve zero-knowledge key material from a short location string.
pub trait Resolver {
    /// Resolves the given key to the key material it represents, if available.
    // Allowed as we do not need auto traits here
    #[allow(async_fn_in_trait)]
    async fn resolve_key(&self, key: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>>;
}

/// A tool that provides proving against opaque/serialized proof preimages
/// It is assumed (though not strictly required) that this also implements
/// `Resolver` to resolve keys.
#[allow(async_fn_in_trait)]
pub trait ProvingProvider {
    /// Check the proof preimage is valid, and if so returns the pi skip sequence
    async fn check(&self, preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error>;
    /// Produces the proof, optionally modifying the binding input in the proof preimage first.
    async fn prove(
        self,
        preimage: &ProofPreimage,
        overwrite_binding_input: Option<Fr>,
    ) -> Result<Proof, anyhow::Error>;
    /// Creates a copy of this provider. As providers often include an RNG, this
    /// may mutate the provider itself.
    fn split(&mut self) -> Self;
    /// Retrieves the resolver underlying this proving provider.
    fn resolver(&self) -> &impl Resolver;
}

/// Everything necessary to produce a proof.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serializable,
    Hash,
    Storable,
    Zeroize,
    ZeroizeOnDrop,
)]
#[storable(base)]
#[tag = "proof-preimage"]
#[cfg_attr(feature = "proptest", derive(Arbitrary))]
pub struct ProofPreimage {
    /// The inputs to be directly handed to the IR.
    pub inputs: Vec<Fr>,
    /// A private witness vector consumed by active witness calls in the IR.
    pub private_transcript: Vec<Fr>,
    /// A public statement vector encoding statement call information in the IR.
    pub public_transcript_inputs: Vec<Fr>,
    /// A public statement vector encoding statement call results in the IR.
    pub public_transcript_outputs: Vec<Fr>,
    /// An arbitrary input to be bound to in the proof.
    pub binding_input: Fr,
    /// The communications commitment that will be checked, and its randomness.
    /// May be [None], in which case inputs and outputs are not committed to.
    pub communications_commitment: Option<(Fr, Fr)>,
    /// Where the keys for carrying out the proving can be found.
    pub key_location: KeyLocation,
}
tag_enforcement_test!(ProofPreimage);

impl ProofPreimage {
    /// Runs witness generation and checks for correctness without generating a
    /// proof
    #[allow(unused_variables)]
    pub fn check(&self, ir: &impl Zkir) -> Result<Vec<Option<usize>>, ProvingError> {
        ir.check(self)
    }

    /// Carries out the actual proving of the proof preimage.
    #[allow(unreachable_code, unused_variables)]
    pub async fn prove<Z: Zkir>(
        &self,
        rng: impl Rng + CryptoRng,
        params: &impl ParamsProverProvider,
        resolver: &impl Resolver,
    ) -> Result<(Proof, Vec<Option<usize>>), ProvingError> {
        let proof_data = resolver
            .resolve_key(self.key_location.clone())
            .await?
            .ok_or(anyhow::Error::msg(format!(
                "failed to find proving key for '{}'",
                self.key_location.0
            )))?;
        let ir = Z::load_ir_from_tagged(io::Cursor::new(&proof_data.ir_source[..]))?;
        let verifier_key = tagged_deserialize::<VerifierKey>(&mut &proof_data.verifier_key[..])?;
        let prover_key =
            Z::load_prover_key_from_tagged(io::Cursor::new(&proof_data.prover_key[..]))?;
        let (proof, pis, pi_skips) = ir.prove(rng, params, prover_key, self).await?;
        debug!("proof created; verifying to make sure");
        let k = verifier_key.force_init()?.k();
        if let Err(e) = verifier_key.verify(
            &params.get_params(k).await?.as_verifier(),
            &proof,
            pis.iter().copied(),
        ) {
            error!(error = ?e, ?pis, ?ir, "self-verification failed! This may be a bug, check that your keys match!");
            return Err(e);
        }
        debug!("proof ok");
        Ok((proof, pi_skips))
    }
}

impl PartialEq for VerifierKey {
    fn eq(&self, other: &Self) -> bool {
        let mut self_ser = Vec::new();
        let mut other_ser = Vec::new();
        Serializable::serialize(self, &mut self_ser).expect("In-memory serialization must succeed");
        Serializable::serialize(other, &mut other_ser)
            .expect("In-memory serialization must succeed");
        self_ser == other_ser
    }
}

impl Eq for VerifierKey {}

impl PartialOrd for VerifierKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VerifierKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut self_ser = Vec::new();
        let mut other_ser = Vec::new();
        Serializable::serialize(self, &mut self_ser).expect("In-memory serialization must succeed");
        Serializable::serialize(other, &mut other_ser)
            .expect("In-memory serialization must succeed");
        self_ser.cmp(&other_ser)
    }
}

/// An error during proving. The type of this should not be considered part of
/// the public API, although it may be assumed to be [`Debug`]` +
/// `[`Display`](std::fmt::Display).
pub type ProvingError = anyhow::Error;
/// An error during verifying. The type of this should not be considered part of
/// the public API, although it may be assumed to be [`Debug`]` +
/// `[`Display`](std::fmt::Display).
pub type VerifyingError = anyhow::Error;

/// Tests for the companion cache's publication protocol.
///
/// Every test uses a tiny real SRS (`k = 4`) so the header validation and the
/// mapping are the production code paths, not stubs. What cannot be injected
/// portably is a failing `fsync`: the structure covers it — `sync_all` runs
/// before the rename and any error propagates through `?`, leaving nothing
/// published — and the short-write and rename-failure tests exercise the same
/// early-return path.
#[cfg(all(test, not(target_family = "wasm")))]
mod companion_cache_tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    const NAME: &str = "bls_test_2p4";

    fn small_params() -> ParamsProver {
        ParamsProver(Arc::new(ParamsKZG::<Bls12>::unsafe_setup(
            4,
            rand::rngs::OsRng,
        )))
    }

    fn digest(p: &ParamsProver) -> Vec<u8> {
        let mut bytes = Vec::new();
        p.0.write_custom(&mut bytes, SerdeFormat::RawBytesUnchecked)
            .expect("serialise params");
        bytes
    }

    fn temps_in(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("read cache dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    }

    #[test]
    fn nothing_published_opens_as_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = CompanionCache::new(dir.path());
        assert!(cache.open(NAME).expect("open").is_none());
        assert!(!cache.published_path(NAME).exists());
    }

    #[test]
    fn concurrent_first_builders_share_one_complete_publication() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = small_params();
        let expected = digest(&source);
        let builds = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let cache = CompanionCache::new(dir.path());
                let source = source.clone();
                let builds = Arc::clone(&builds);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cache.open_or_build(NAME, || {
                        builds.fetch_add(1, AtomicOrdering::SeqCst);
                        Ok(source)
                    })
                })
            })
            .collect();
        for h in handles {
            let mapped = h.join().expect("thread").expect("open_or_build");
            assert_eq!(digest(&mapped), expected, "every caller sees the same SRS");
        }
        assert!(builds.load(AtomicOrdering::SeqCst) >= 1);
        assert!(cache_has_exactly_one_published(dir.path()));
        assert!(
            temps_in(dir.path()).is_empty(),
            "no temp file survives publication"
        );
    }

    fn cache_has_exactly_one_published(dir: &std::path::Path) -> bool {
        std::fs::read_dir(dir)
            .expect("read cache dir")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".mmap"))
            .count()
            == 1
    }

    #[test]
    fn a_published_companion_is_never_rewritten_while_mapped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = CompanionCache::new(dir.path());
        let first = small_params();
        let mapped = cache
            .open_or_build(NAME, || Ok(first.clone()))
            .expect("first publication");
        let path = cache.published_path(NAME);
        let bytes_before = std::fs::read(&path).expect("read companion");

        // A second, different SRS asks to be written to the same path while
        // `mapped` is alive. It must be refused without touching the inode.
        let second = small_params();
        let err = second
            .write_mmap_companion(&path)
            .expect_err("a published companion must not be rewritten");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert_eq!(
            std::fs::read(&path).expect("re-read"),
            bytes_before,
            "bytes unchanged"
        );
        assert_eq!(
            digest(&mapped),
            digest(&first),
            "the live mapping still reads the first SRS"
        );
        assert!(temps_in(dir.path()).is_empty());
    }

    #[test]
    fn a_reader_racing_a_builder_sees_a_complete_file_or_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = small_params();
        let expected = digest(&source);
        let barrier = Arc::new(Barrier::new(5));
        let builder = {
            let cache = CompanionCache::new(dir.path());
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                cache.open_or_build(NAME, || Ok(source))
            })
        };
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let cache = CompanionCache::new(dir.path());
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    // Spin until the name appears; every success must be a
                    // complete, validated file — `open` never returns a
                    // partial one because the name is created by the rename.
                    for _ in 0..10_000 {
                        match cache.open(NAME) {
                            Ok(Some(p)) => return Ok(p),
                            Ok(None) => std::thread::yield_now(),
                            Err(e) => return Err(e),
                        }
                    }
                    Err(io::Error::other("reader gave up"))
                })
            })
            .collect();
        builder.join().expect("builder thread").expect("build");
        for r in readers {
            let p = r
                .join()
                .expect("reader thread")
                .expect("reader must not see a partial file");
            assert_eq!(digest(&p), expected);
        }
    }

    #[test]
    fn a_write_failure_publishes_nothing_and_leaves_no_temp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = CompanionCache::new(dir.path());
        let outcome = cache.publish_file(std::ffi::OsStr::new("k4.mmap"), |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("injected write failure"))
        });
        let err = outcome.expect_err("injected failure must propagate");
        assert_eq!(err.to_string(), "injected write failure");
        assert!(!dir.path().join("k4.mmap").exists());
        assert!(temps_in(dir.path()).is_empty());
    }

    #[test]
    fn a_short_write_fails_validation_and_publishes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = CompanionCache::new(dir.path());
        let full = {
            let mut buf = Vec::new();
            small_params()
                .0
                .write_mmap_companion(&mut buf)
                .expect("write");
            buf
        };
        let half = &full[..full.len() / 2];
        let err = cache
            .publish_file(std::ffi::OsStr::new("k4.mmap"), |file| file.write_all(half))
            .expect_err("a truncated companion must not be published");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(!dir.path().join("k4.mmap").exists());
        assert!(temps_in(dir.path()).is_empty());
    }

    #[test]
    fn a_rename_failure_publishes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir(&cache_dir).expect("mkdir");
        let cache = CompanionCache::new(&cache_dir);
        let cache_dir_for_hook = cache_dir.clone();
        let err = cache
            .publish_file(std::ffi::OsStr::new("k4.mmap"), move |file| {
                small_params().0.write_mmap_companion(file)?;
                // Pull the directory out from under the rename: on this
                // platform an open temp file survives, the rename cannot.
                std::fs::remove_dir_all(&cache_dir_for_hook)
            })
            .expect_err("the rename must fail");
        assert_ne!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert!(!cache_dir.join("k4.mmap").exists());
    }

    #[test]
    fn an_interrupted_publication_is_swept_and_a_fresh_one_is_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = CompanionCache::new(dir.path());
        let prefix = CompanionCache::temp_prefix(std::ffi::OsStr::new(&format!("{NAME}.mmap")));

        // A crashed publisher from long ago: garbage bytes, two hours old.
        let stale = dir.path().join(format!("{prefix}stale"));
        std::fs::write(&stale, b"left behind by a crash").expect("write stale");
        let two_hours_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .expect("open stale")
            .set_times(std::fs::FileTimes::new().set_modified(two_hours_ago))
            .expect("age the stale temp");
        // A publisher that is alive right now: must be left alone.
        let fresh = dir.path().join(format!("{prefix}fresh"));
        std::fs::write(&fresh, b"in progress").expect("write fresh");

        let source = small_params();
        let mapped = cache
            .open_or_build(NAME, || Ok(source.clone()))
            .expect("publication succeeds despite leftovers");
        assert_eq!(digest(&mapped), digest(&source));
        assert!(!stale.exists(), "the stale temp file is swept");
        assert!(
            fresh.exists(),
            "a live publisher's temp file is not touched"
        );
        assert!(cache.published_path(NAME).exists());
    }

    #[test]
    fn open_or_build_reuses_a_publication_without_building() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = CompanionCache::new(dir.path());
        let source = small_params();
        cache
            .open_or_build(NAME, || Ok(source.clone()))
            .expect("first");
        let reused = cache
            .open_or_build(NAME, || {
                panic!("the builder must not run when a companion is published")
            })
            .expect("second");
        assert_eq!(digest(&reused), digest(&source));
    }
}
