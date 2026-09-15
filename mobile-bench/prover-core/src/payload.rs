//! Proof-server request payloads for benchmarking, and the matching external
//! verification.
//!
//! The proof server's `/prove` endpoint takes a tagged
//! `(ProofPreimageVersioned, Option<ProvingKeyMaterial>, Option<Fr>)`. Its
//! resolver knows only the four published zswap/dust circuits, so any other
//! circuit must carry its own proving-key material in the request. That is
//! what a benchmark wants anyway: the *same bytes* to every image under test,
//! with `k` chosen by the caller rather than by the circuit.
//!
//! `k` is chosen through [`zkir::IrSource::v2_keygen_at`]: the minimal zkir
//! circuit is padded to `2^k` rows, so a k=20 request exercises the prover at
//! k=20 — FFTs over 2^20 rows, MSMs of 2^20 points, the coset working set —
//! while staying trivially valid (one input, one `assert`). What it does not
//! exercise is circuit *content*; the numbers say how the prover behaves at a
//! size, which is the question the container comparison asks.

use std::sync::Arc;

use ledger::structure::{ProofPreimageVersioned, ProofVersioned};
use serialize::{tagged_deserialize, tagged_serialize};
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{PARAMS_VERIFIER, ProofPreimage, ProvingKeyMaterial, VerifierKey};
use zkir::IrSource;

use crate::resolver::ExampleResolver;
use crate::zkir_example::{BINDING_INPUT_RAW, LABEL, MINIMAL_IR_JSON, minimal_preimage};
use crate::{Error, ProverCore, Result};

/// Everything a benchmark needs to send one request and check its answer.
pub struct GeneratedPayload {
    /// The circuit the request proves.
    pub label: &'static str,
    /// The `k` the keys were generated at (the circuit's own minimum if lower).
    pub k: u8,
    /// The exact `/prove` request body.
    pub request: Vec<u8>,
    /// The tagged verifier key, for [`verify_response`].
    pub verifier_key: Vec<u8>,
    /// The public binding input the verifier must be given.
    pub binding_input: Fr,
}

/// Encode a `/prove` request: mirrors `proof-server/src/endpoints.rs`, which
/// tagged-deserializes `(ProofPreimageVersioned, Option<ProvingKeyMaterial>,
/// Option<Fr>)`. Supplying `Some(pkm)` makes the server skip key resolution.
pub fn build_payload(preimage: ProofPreimage, pkm: ProvingKeyMaterial) -> Result<Vec<u8>> {
    let triple: (
        ProofPreimageVersioned,
        Option<ProvingKeyMaterial>,
        Option<Fr>,
    ) = (
        ProofPreimageVersioned::V2(Arc::new(preimage)),
        Some(pkm),
        None,
    );
    let mut body = Vec::new();
    tagged_serialize(&triple, &mut body)
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("serialize payload: {e}")))?;
    Ok(body)
}

/// Verify a `/prove` response body against a tagged verifier key — outside
/// any container, with the same verifier the library uses. Returns `Ok(true)`
/// only if the proof verifies; a malformed response is an error, not `false`.
pub fn verify_response(verifier_key: &[u8], response: &[u8], binding_input: Fr) -> Result<bool> {
    let vk: VerifierKey = tagged_deserialize(verifier_key)
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("deserialize verifier key: {e}")))?;
    let versioned: ProofVersioned = tagged_deserialize(response)
        .map_err(|e| Error::Anyhow(anyhow::anyhow!("deserialize proof: {e}")))?;
    let ProofVersioned::V2(proof) = versioned else {
        return Err(Error::Anyhow(anyhow::anyhow!(
            "unexpected ProofVersioned variant"
        )));
    };
    Ok(vk
        .verify(&PARAMS_VERIFIER, &proof, std::iter::once(binding_input))
        .is_ok())
}

impl ProverCore {
    /// Generate a `/prove` request for the minimal zkir circuit keyed at `k`.
    ///
    /// `k` below the circuit's minimum is rejected by keygen; the minimum is
    /// small, so any benchmark size from 10 upward works. Params for `k` come
    /// from the cache directory (or are fetched into it).
    pub async fn generate_payload(&self, k: u8) -> Result<GeneratedPayload> {
        let ir = IrSource::load(MINIMAL_IR_JSON.as_bytes())
            .map_err(|e| Error::Anyhow(anyhow::anyhow!("load ir: {e}")))?;
        let (pk, vk) = ir
            .v2_keygen_at(k, &self.params.zswap.0)
            .await
            .map_err(|e| Error::Anyhow(anyhow::anyhow!("keygen at k={k}: {e}")))?;
        let resolver = ExampleResolver { pk, vk, ir };
        let pkm = resolver
            .proving_key_material()
            .map_err(|e| Error::Anyhow(anyhow::anyhow!("serialize keys: {e}")))?;
        let verifier_key = pkm.verifier_key.clone();
        let preimage = minimal_preimage();
        let binding_input = preimage.binding_input;
        debug_assert_eq!(binding_input, Fr::from(BINDING_INPUT_RAW));
        let request = build_payload(preimage, pkm)?;
        Ok(GeneratedPayload {
            label: LABEL,
            k,
            request,
            verifier_key,
            binding_input,
        })
    }
}

#[cfg(test)]
mod tests {
    //! The request must survive the round trip the server performs on it:
    //! deserialize the triple, deserialize the supplied prover key, `init()`
    //! it (which re-reads the raw halo2 key at the `k` stored in its bytes).
    //! A key generated at a forced `k` is exactly the case worth pinning,
    //! because the reader rebuilds the circuit from the embedded relation.

    use super::*;
    use transient_crypto::proofs::{ProverKey, Zkir};

    async fn core() -> ProverCore {
        let dir = std::env::var_os("MIDNIGHT_PP")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
                    .join(".cache/midnight/zk-params")
            });
        ProverCore::new(dir).await.expect("core")
    }

    #[tokio::test]
    async fn a_forced_k_key_round_trips_through_the_servers_path() {
        let p = core()
            .await
            .generate_payload(12)
            .await
            .expect("payload at k=12");
        let (ppi, pkm, extra): (ProofPreimageVersioned, Option<ProvingKeyMaterial>, Option<Fr>) =
            tagged_deserialize(&p.request[..]).expect("triple deserializes");
        assert!(matches!(ppi, ProofPreimageVersioned::V2(_)));
        assert!(extra.is_none());
        let pkm = pkm.expect("key material present");
        let pk: ProverKey<IrSource> =
            tagged_deserialize(&pkm.prover_key[..]).expect("prover key deserializes");
        let inner = pk.init().expect("prover key initialises at the forced k");
        assert_eq!(inner.k(), 12, "the key must carry the forced k");
        let ir: IrSource = tagged_deserialize(&pkm.ir_source[..]).expect("ir deserializes");
        assert!(
            ir.k() < 12,
            "the fixture's natural k must be below the forced one for this test to mean anything"
        );
    }
}
