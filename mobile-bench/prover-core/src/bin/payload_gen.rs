//! payload-gen: make proof-server benchmark requests at a chosen `k`, and
//! verify the responses outside the container.
//!
//! Usage:
//!   payload-gen gen --k 14 [--out DIR]
//!       writes DIR/k14-request.bin, DIR/k14-vk.bin, DIR/k14-manifest.json
//!   payload-gen verify --vk DIR/k14-vk.bin --proof response.bin
//!       prints `verified` and exits 0, or `NOT VERIFIED` and exits 1
//!
//! Params come from $MIDNIGHT_PP (default ~/.cache/midnight/zk-params) and
//! are fetched into it when missing. The request carries the proving-key
//! material, so every image under test receives byte-identical input and
//! needs no key resolver of its own.

use std::path::PathBuf;
use std::process::ExitCode;

use prover_core::ProverCore;
use transient_crypto::curve::Fr;

const BINDING_INPUT_RAW: u64 = 42;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn cache_dir() -> PathBuf {
    std::env::var_os("MIDNIGHT_PP")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default();
            home.join(".cache/midnight/zk-params")
        })
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: payload-gen gen --k <k> [--out DIR]\n       payload-gen verify --vk FILE --proof FILE"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen") => {
            let Some(k) = arg(&args, "--k").and_then(|s| s.parse::<u8>().ok()) else {
                return usage();
            };
            let out = arg(&args, "--out")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            let result = rt.block_on(async {
                let pc = ProverCore::new(cache_dir()).await?;
                pc.generate_payload(k).await
            });
            match result {
                Ok(p) => {
                    if let Err(e) = std::fs::create_dir_all(&out) {
                        eprintln!("create {}: {e}", out.display());
                        return ExitCode::FAILURE;
                    }
                    let req = out.join(format!("k{k}-request.bin"));
                    let vk = out.join(format!("k{k}-vk.bin"));
                    let manifest = out.join(format!("k{k}-manifest.json"));
                    if let Err(e) = std::fs::write(&req, &p.request)
                        .and_then(|()| std::fs::write(&vk, &p.verifier_key))
                        .and_then(|()| {
                            std::fs::write(
                                &manifest,
                                serde_json::to_vec_pretty(&serde_json::json!({
                                    "label": p.label,
                                    "k": p.k,
                                    "request_bytes": p.request.len(),
                                    "verifier_key_bytes": p.verifier_key.len(),
                                    "binding_input": BINDING_INPUT_RAW,
                                    "request": req.file_name().and_then(|f| f.to_str()),
                                    "verifier_key": vk.file_name().and_then(|f| f.to_str()),
                                }))
                                .expect("json"),
                            )
                        })
                    {
                        eprintln!("write: {e}");
                        return ExitCode::FAILURE;
                    }
                    println!(
                        "k={} request={} bytes vk={} bytes → {}",
                        p.k,
                        p.request.len(),
                        p.verifier_key.len(),
                        out.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("gen failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("verify") => {
            let (Some(vk), Some(proof)) = (arg(&args, "--vk"), arg(&args, "--proof")) else {
                return usage();
            };
            let read = |p: &str| std::fs::read(p).map_err(|e| format!("read {p}: {e}"));
            let (vk, proof) = match (read(&vk), read(&proof)) {
                (Ok(v), Ok(p)) => (v, p),
                (Err(e), _) | (_, Err(e)) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            match prover_core::verify_response(&vk, &proof, Fr::from(BINDING_INPUT_RAW)) {
                Ok(true) => {
                    println!("verified");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    println!("NOT VERIFIED");
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("verify failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => usage(),
    }
}
