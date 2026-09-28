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

use std::sync::Arc;

use ledger::prove::Resolver;
use rand::rngs::OsRng;
#[allow(unused_imports)]
use serialize::{peek_tag, tagged_deserialize};
use std::io::Cursor;
use transient_crypto::proofs::{
    MappedParams, ParamsProver, ParamsProverProvider, Proof, ProofPreimage, ProvingError, Zkir,
};
use zkir as zkir_v2;

pub(crate) fn k(request: &[u8]) -> Result<u8, String> {
    let tag = peek_tag(&mut std::io::Cursor::new(request)).map_err(|e| e.to_string())?;
    match tag.as_str() {
        "ir-source[v2]" | "ir-source[v2-generic]" => {
            let ir_v2 = zkir_v2::IrSource::load_from_tagged(Cursor::new(request))
                .map_err(|e| e.to_string())?;
            Ok(ir_v2.k())
        }
        "ir-source[v3-generic]" => {
            let ir_v3 =
                tagged_deserialize::<zkir_v3::IrSource>(request).map_err(|e| e.to_string())?;
            Ok(ir_v3.k())
        }
        _ => Err(format!("Unsupported ZKIR tag: '{tag}'")),
    }
}

pub(crate) fn check(ppi: Arc<ProofPreimage>, ir: &[u8]) -> Result<Vec<Option<usize>>, String> {
    let tag = peek_tag(&mut std::io::Cursor::new(ir)).map_err(|e| e.to_string())?;
    match tag.as_str() {
        "ir-source[v2]" | "ir-source[v2-generic]" => {
            let ir_v2 =
                zkir_v2::IrSource::load_from_tagged(Cursor::new(ir)).map_err(|e| e.to_string())?;
            ppi.check(&ir_v2).map_err(|e| e.to_string())
        }
        "ir-source[v3-generic]" => {
            let ir_v3 = tagged_deserialize::<zkir_v3::IrSource>(ir).map_err(|e| e.to_string())?;
            ppi.check(&ir_v3).map_err(|e| e.to_string())
        }
        _ => Err(format!("Unsupported ZKIR tag: '{tag}'")),
    }
}

/// Why a proof could not be produced, split the way HTTP needs it split.
///
/// The prover reports everything as one `anyhow::Error`, but two different
/// parties are to blame for two different kinds of failure: a request that
/// carries a malformed key or an IR the prover cannot handle is the client's
/// problem, while a spill directory the server cannot create files in is the
/// operator's. Answering the second with `400 bad input` sends the client
/// looking for a bug in a valid request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProveError {
    /// The request is at fault: answer 400.
    BadInput(String),
    /// The server's own environment is at fault: answer 500.
    ServerEnvironment(String),
}

/// A marker placed in an error chain by [`TaggedServerParams`]: this failure
/// happened while loading *this server's* public parameters, so nothing the
/// request carried can be responsible for it.
///
/// It exists because an `io::ErrorKind` does not name the owner of the data
/// that failed. A corrupt or incompatible `bls_midnight_2pN.mmap` in the
/// server's own cache fails with `InvalidData`, which reads exactly like a
/// client sending malformed key bytes — and for a while this server answered
/// it with 400, sending the operator's problem to the client as a bug report
/// about their own valid request (F-035).
#[derive(Debug)]
struct ServerParamsFailure {
    k: u8,
    source: std::io::Error,
}

impl std::fmt::Display for ServerParamsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "loading this server's public parameters for k={}: {}",
            self.k, self.source
        )
    }
}

impl std::error::Error for ServerParamsFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Wraps the server's parameter provider so that its failures carry
/// [`ServerParamsFailure`] — the provenance the classifier needs and cannot
/// otherwise recover, since by the time the prover has wrapped everything in
/// one `anyhow::Error` the only thing left to look at is an error kind.
struct TaggedServerParams<'a, P>(&'a P);

impl<P: ParamsProverProvider> ParamsProverProvider for TaggedServerParams<'_, P> {
    async fn get_params(&self, k: u8) -> std::io::Result<ParamsProver> {
        self.0.get_params(k).await.map_err(|source| {
            // Keep the kind, so anything that reads kinds still sees the
            // truth about *what* failed; the tag says *whose* it was.
            std::io::Error::new(source.kind(), ServerParamsFailure { k, source })
        })
    }
}

/// Classify a prover error by the provenance of the input that failed.
///
/// Two tests, in order:
///
/// 1. **A tagged server-parameter failure** is the server's, whatever its kind
///    — that is the whole point of the tag.
/// 2. **A filesystem refusal** is the server's too. This one is a kind test,
///    and it is sound only because of the ordering: once the parameters are
///    tagged, the only filesystem the prover still touches on its own account
///    is the spill directory the server's policy chose. Every remaining path
///    reads bytes the request supplied, from memory.
///
/// Everything else is the request's: a malformed key, an IR class this prover
/// refuses, a constraint that does not hold. Those carry no `io::Error` at all,
/// or carry one describing bytes the client sent.
pub(crate) fn classify(e: ProvingError) -> ProveError {
    use std::io::ErrorKind::*;

    let io_causes = || {
        e.chain()
            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
    };

    let server_params = io_causes().any(|io| {
        io.get_ref()
            .is_some_and(|inner| inner.is::<ServerParamsFailure>())
    });

    let filesystem_refusal = io_causes().any(|io| {
        matches!(
            io.kind(),
            NotFound
                | PermissionDenied
                | StorageFull
                | ReadOnlyFilesystem
                | Unsupported
                | OutOfMemory
                | ResourceBusy
                | QuotaExceeded
        )
    });

    if server_params || filesystem_refusal {
        ProveError::ServerEnvironment(format!("{e:#}"))
    } else {
        ProveError::BadInput(format!("{e:#}"))
    }
}

pub(crate) async fn prove(
    ppi: Arc<ProofPreimage>,
    ir_source: &[u8],
    resolver: &Resolver,
) -> Result<(Proof, Vec<Option<usize>>), ProveError> {
    // Mapping is opt-in: without the operator's promise this takes the eager
    // path, which owns its memory and cannot be invalidated by anything on
    // disk. See `endpoints::trusted_params_dir`.
    match crate::endpoints::trusted_params_dir() {
        Some(dir) => {
            let params = MappedParams::new(crate::endpoints::PUBLIC_PARAMS.clone(), dir);
            prove_with_params(ppi, ir_source, resolver, &params).await
        }
        None => {
            prove_with_params(ppi, ir_source, resolver, &*crate::endpoints::PUBLIC_PARAMS).await
        }
    }
}

/// [`prove`], with the server's parameter provider passed in rather than read
/// from the process-wide one.
///
/// The seam exists so a test can hand in a provider that fails the way a
/// corrupt companion in the server's cache fails, and prove that the answer is
/// 500 rather than 400. `PUBLIC_PARAMS` is a `lazy_static` shared by every
/// handler, so there is no other way to reach that path from a test without
/// mutating process state.
pub(crate) async fn prove_with_params(
    ppi: Arc<ProofPreimage>,
    ir_source: &[u8],
    resolver: &Resolver,
    params: &impl ParamsProverProvider,
) -> Result<(Proof, Vec<Option<usize>>), ProveError> {
    let params = TaggedServerParams(params);
    let bad = |e: &dyn std::fmt::Display| ProveError::BadInput(e.to_string());
    let tag = peek_tag(&mut std::io::Cursor::new(ir_source)).map_err(|e| bad(&e))?;
    match tag.as_str() {
        "ir-source[v2]" | "ir-source[v2-generic]" => {
            let ir =
                zkir_v2::IrSource::load_from_tagged(Cursor::new(ir_source)).map_err(|e| bad(&e))?;
            // Use LocalProvingProvider for v2 IRs to handle V0/V1 backward compat routing.
            use base_crypto::rng::SplittableRng;
            use transient_crypto::proofs::ProvingProvider;

            let mut provider = zkir_v2::LocalProvingProvider {
                rng: OsRng.split(),
                resolver,
                params: &params,
            };
            let proof = provider.split().prove(&ppi, None).await.map_err(classify)?;
            let skips = ppi.check(&ir).map_err(|e| bad(&e))?;
            Ok((proof, skips))
        }
        "ir-source[v3-generic]" => {
            //let ir_source = tagged_deserialize::<zkir_v3::IrSource>(ir_source).map_err(|e| e.to_string())?;
            ppi.prove::<zkir_v3::IrSource>(OsRng, &params, resolver)
                .await
                .map_err(classify)
        }
        _ => Err(ProveError::BadInput(format!(
            "Unsupported ZKIR tag: '{tag}'"
        ))),
    }
}

#[cfg(test)]
mod classify_tests {
    use super::*;
    use std::io;

    #[test]
    fn a_missing_spill_directory_is_the_servers_fault() {
        let root = io::Error::new(
            io::ErrorKind::NotFound,
            "create spill temp file in /spill: No such file or directory",
        );
        let e = ProvingError::from(root).context("Could not init pk");
        match classify(e) {
            ProveError::ServerEnvironment(msg) => {
                assert!(msg.contains("Could not init pk"), "{msg}");
                assert!(
                    msg.contains("/spill"),
                    "the operator must see the directory: {msg}"
                );
            }
            other => panic!("expected a server-environment error, got {other:?}"),
        }
    }

    /// The case F-035 named. A corrupt or incompatible companion in the
    /// server's *own* cache fails with `InvalidData` — indistinguishable by
    /// kind from a client sending malformed key bytes, which the test below
    /// asserts still reads as the client's fault. Only the provenance tag
    /// separates them.
    #[test]
    fn a_corrupt_server_companion_is_the_servers_fault_despite_its_kind() {
        let root = io::Error::new(
            io::ErrorKind::InvalidData,
            "bls_midnight_2p14.mmap: header magic mismatch",
        );
        let tagged = io::Error::new(
            root.kind(),
            ServerParamsFailure {
                k: 14,
                source: root,
            },
        );
        let e = ProvingError::from(tagged).context("proving");
        match classify(e) {
            ProveError::ServerEnvironment(msg) => {
                assert!(
                    msg.contains("bls_midnight_2p14.mmap"),
                    "the operator must see which file: {msg}"
                );
                assert!(msg.contains("k=14"), "and for which k: {msg}");
            }
            other => panic!("expected a server-environment error, got {other:?}"),
        }
    }

    /// The tag survives the wrapping the prover actually does, not just a
    /// hand-built chain: `get_params` returns `io::Result`, `prove` converts it
    /// with `?` into `anyhow`, and layers of `context` go on top.
    #[test]
    fn the_provenance_tag_survives_the_provers_error_wrapping() {
        let tagged = io::Error::new(
            io::ErrorKind::InvalidData,
            ServerParamsFailure {
                k: 20,
                source: io::Error::new(io::ErrorKind::InvalidData, "truncated"),
            },
        );
        let e = ProvingError::from(tagged)
            .context("Could not init pk")
            .context("create_proof")
            .context("prove");
        assert!(matches!(classify(e), ProveError::ServerEnvironment(_)));
    }

    /// The wrapper is what puts the tag there, so it is the thing under test —
    /// a bare provider gives the classifier nothing to go on.
    #[tokio::test]
    async fn the_wrapper_tags_what_the_bare_provider_does_not() {
        struct Broken;
        impl ParamsProverProvider for Broken {
            async fn get_params(&self, _k: u8) -> io::Result<ParamsProver> {
                Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"))
            }
        }

        // `ParamsProver` is not `Debug`, so neither of these can use
        // `expect_err`.
        let Err(bare) = Broken.get_params(14).await else {
            panic!("the provider must fail");
        };
        assert!(
            classify_kind_only(&bare),
            "without the tag this is indistinguishable from a client error"
        );

        let Err(tagged) = TaggedServerParams(&Broken).get_params(14).await else {
            panic!("the wrapped provider must fail");
        };
        assert_eq!(
            tagged.kind(),
            io::ErrorKind::InvalidData,
            "the kind is preserved, so anything reading kinds still sees the truth"
        );
        let e = ProvingError::from(tagged);
        assert!(matches!(classify(e), ProveError::ServerEnvironment(_)));
    }

    /// True when the error carries nothing but its kind — the situation the
    /// classifier used to be in for every failure.
    fn classify_kind_only(e: &io::Error) -> bool {
        e.get_ref()
            .is_none_or(|inner| !inner.is::<ServerParamsFailure>())
    }

    #[test]
    fn malformed_key_bytes_stay_the_clients_fault() {
        let root = io::Error::new(io::ErrorKind::InvalidData, "bad magic");
        let e = ProvingError::from(root).context("Could not init pk");
        assert!(matches!(classify(e), ProveError::BadInput(_)));
    }

    #[test]
    fn a_legacy_circuit_class_is_the_clients_fault() {
        let e = ProvingError::msg(
            "V0/V1 circuits must use transient_crypto_old::proofs::Zkir for proving",
        );
        assert!(matches!(classify(e), ProveError::BadInput(_)));
    }
}
