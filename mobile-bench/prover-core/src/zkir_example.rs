use std::time::Instant;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serialize::tagged_serialize;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{PARAMS_VERIFIER, ProofPreimage, Zkir};
use zkir::IrSource;

use crate::resolver::{ExampleResolver, make_preimage};
use crate::{BenchOpts, Error, ProofRun, ProverCore, Result};

pub(crate) const LABEL: &str = "zkir-minimal-assert";

/// A trivial 1-input "assert(cond == 0)" circuit. Mirrors `test_minimal_proof`
/// in zkir/tests/proofs.rs — exercises the full halo2-kzg prove/verify pipeline
/// with the smallest possible circuit so we can validate it end-to-end on
/// every target (desktop, Android emulator, S24 Ultra) without depending on
/// captured contract preimages.
// `minor` is the IR *class*: 0 and 1 route to the legacy v1 prover
// (`transient_crypto_old`), 2 to the zk-stdlib-v2 prover this line keys
// with. A `minor: 0` circuit could not be keyed or proven here at all
// ("V0/V1 circuits must use transient_crypto_old"), and a proof server
// handed a v2 key for it answered `Could not init pk`.
pub(crate) const MINIMAL_IR_JSON: &str = r#"{
    "version": { "major": 2, "minor": 2 },
    "num_inputs": 1,
    "do_communications_commitment": false,
    "instructions": [
        { "op": "assert", "cond": 0 }
    ]
}"#;

/// Single binding input the verifier checks. Arbitrary; matches what
/// `prove_zkir_example` and `prove_via_http` both use so the verify call is
/// reproducible.
pub(crate) const BINDING_INPUT_RAW: u64 = 42;

pub(crate) fn minimal_preimage() -> ProofPreimage {
    make_preimage(vec![Fr::from(1u64)], Fr::from(BINDING_INPUT_RAW), "minimal")
}

impl ProverCore {
    /// Loads the minimal IR and runs keygen. Both library and HTTP paths use
    /// this so the same circuit is exercised regardless of transport.
    pub(crate) async fn keygen_minimal(&self) -> Result<ExampleResolver> {
        let ir = IrSource::load(MINIMAL_IR_JSON.as_bytes())
            .map_err(|e| Error::Anyhow(anyhow::anyhow!("load ir: {e}")))?;
        let (pk, vk) = ir
            .keygen(&self.params.zswap.0)
            .await
            .map_err(|e| Error::Anyhow(anyhow::anyhow!("keygen: {e}")))?;
        Ok(ExampleResolver { pk, vk, ir })
    }

    pub async fn prove_zkir_example(&self, opts: BenchOpts) -> Result<ProofRun> {
        let seed = opts.seed.unwrap_or(0x42);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);

        let resolver = self.keygen_minimal().await?;
        let k = resolver.ir.k();
        let preimage = minimal_preimage();
        let binding_input = preimage.binding_input;

        let started = Instant::now();
        let (proof, _pi_skips) = preimage
            .prove::<IrSource>(&mut rng, &self.params.zswap.0, &resolver)
            .await
            .map_err(|e| Error::Anyhow(anyhow::anyhow!("prove: {e}")))?;
        let elapsed = started.elapsed();

        let proof_bytes = {
            let mut buf = Vec::new();
            tagged_serialize(&proof, &mut buf)
                .map_err(|e| Error::Anyhow(anyhow::anyhow!("serialize proof: {e}")))?;
            buf
        };

        let (verified, verify_elapsed) = if opts.verify_after {
            let v_started = Instant::now();
            // PARAMS_VERIFIER is embedded for k <= 14; binding_input is the
            // single public input.
            let ok = resolver
                .vk
                .verify(&PARAMS_VERIFIER, &proof, std::iter::once(binding_input))
                .is_ok();
            (Some(ok), Some(v_started.elapsed()))
        } else {
            (None, None)
        };

        Ok(ProofRun {
            label: LABEL,
            k,
            elapsed,
            verify_elapsed,
            verified,
            proof_bytes,
        })
    }
}
