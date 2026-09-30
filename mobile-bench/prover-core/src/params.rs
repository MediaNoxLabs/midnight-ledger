use std::path::{Path, PathBuf};
use std::sync::Arc;

use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use ledger::dust::{DUST_EXPECTED_FILES, DustResolver};
use transient_crypto::proofs::{MappedParams, TrustedParamsDir};
use zswap::{ZSWAP_EXPECTED_FILES, prove::ZswapResolver};

/// Wraps the existing `MidnightDataProvider` machinery. On first call, files
/// listed in `DUST_EXPECTED_FILES` / `ZSWAP_EXPECTED_FILES` are downloaded into
/// `dir`. Subsequent calls hit the cache.
#[allow(dead_code)] // fields read by zkir/dust modules in later tasks
pub(crate) struct ParamsCache {
    dir: PathBuf,
    pub(crate) zswap: Arc<ZswapResolver>,
    pub(crate) dust: Arc<DustResolver>,
    /// The SRS provider this harness proves with.
    ///
    /// Mapping published companions is the thing this harness exists to
    /// measure, so it opts in explicitly. A consumer that does not opt in gets
    /// eager loads — sound, and much heavier at k=20, which is exactly the
    /// difference the benchmark reports.
    pub(crate) mapped: Arc<MappedParams<MidnightDataProvider>>,
}

impl ParamsCache {
    pub(crate) fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;

        // base_crypto::data_provider::MidnightDataProvider reads MIDNIGHT_PP
        // (see base-crypto/src/data_provider.rs:225) to choose its on-disk
        // cache root. We pin it to our caller-supplied `dir` if not already
        // set by the embedding process — letting tests override.
        if std::env::var_os("MIDNIGHT_PP").is_none() {
            // SAFETY: setting env vars is unsafe in Rust 2024; we only do this
            // once at construction and the value is a path under our control.
            unsafe {
                std::env::set_var("MIDNIGHT_PP", &dir);
            }
        }

        let zswap = ZswapResolver(MidnightDataProvider::new(
            FetchMode::OnDemand,
            OutputMode::Log,
            ZSWAP_EXPECTED_FILES.to_vec(),
        )?);
        let dust = DustResolver(MidnightDataProvider::new(
            FetchMode::OnDemand,
            OutputMode::Log,
            DUST_EXPECTED_FILES.to_owned(),
        )?);

        // SAFETY: the parameter cache belongs to this harness. It creates the
        // directory above, pins `MIDNIGHT_PP` to it when the embedding process
        // has not, and is the only writer for the run. Nothing else publishes
        // or rewrites companions there while a measurement is in flight — and
        // a benchmark that shares its cache directory with another writer is
        // not measuring anything meaningful anyway.
        let trusted = unsafe { TrustedParamsDir::new(zswap.0.dir.clone()) };
        let mapped = MappedParams::new(zswap.0.clone(), trusted);

        Ok(Self {
            dir,
            zswap: Arc::new(zswap),
            dust: Arc::new(dust),
            mapped: Arc::new(mapped),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }
}
