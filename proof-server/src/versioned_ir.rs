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
use transient_crypto::proofs::{Proof, ProofPreimage, ProvingError, Zkir};
use zkir as zkir_v2;

use crate::endpoints::PUBLIC_PARAMS;

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

/// Classify a prover error by the `io::Error` at the root of its chain.
///
/// Environment kinds — the filesystem said no — are the server's fault; data
/// kinds (`InvalidData`, `UnexpectedEof`, …) come from parsing what the client
/// sent. Errors with no `io::Error` in the chain are request-shaped too: a
/// legacy IR class, a circuit the prover refuses, a failed constraint.
pub(crate) fn classify(e: ProvingError) -> ProveError {
    use std::io::ErrorKind::*;
    let environment = e.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
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
        })
    });
    if environment {
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
                params: &*PUBLIC_PARAMS,
            };
            let proof = provider.split().prove(&ppi, None).await.map_err(classify)?;
            let skips = ppi.check(&ir).map_err(|e| bad(&e))?;
            Ok((proof, skips))
        }
        "ir-source[v3-generic]" => {
            //let ir_source = tagged_deserialize::<zkir_v3::IrSource>(ir_source).map_err(|e| e.to_string())?;
            ppi.prove::<zkir_v3::IrSource>(OsRng, &*PUBLIC_PARAMS, resolver)
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
