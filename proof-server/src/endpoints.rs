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

#![deny(unreachable_pub)]
#![deny(warnings)]
use actix_web::error::{ErrorBadRequest, ErrorPayloadTooLarge, ErrorRequestTimeout};
use actix_web::http::StatusCode;
use actix_web::web::{self, Bytes, BytesMut, Data, Payload};
use actix_web::{Error, HttpRequest, HttpResponse, HttpResponseBuilder, Responder, get, post};
use base_crypto::data_provider::{self, MidnightDataProvider};
use base_crypto::data_provider::{FetchMode, OutputMode};
use futures_util::stream::StreamExt;
use hex::ToHex;
use introspection::Introspection;
use lazy_static::lazy_static;
use ledger::dust::DustResolver;
use ledger::prove::Resolver;
use ledger::structure::{
    INITIAL_TRANSACTION_COST_MODEL, ProofPreimageMarker, ProofPreimageVersioned, ProofVersioned,
    Signature, Transaction,
};
use rand::rngs::OsRng;
use serialize::{tagged_deserialize, tagged_serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use storage::db::InMemoryDB;
use tracing::{debug, info, warn};
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{KeyLocation, ProvingKeyMaterial, Resolver as ResolverT, WrappedIr};

use zkir as zkir_v2;
use zswap::prove::ZswapResolver;

use crate::versioned_ir;
use crate::worker_pool::{JobStatus, Reservation, WorkError, WorkerPool};

lazy_static! {
    pub static ref PUBLIC_PARAMS: ZswapResolver = ZswapResolver(
        MidnightDataProvider::new(
            data_provider::FetchMode::OnDemand,
            data_provider::OutputMode::Log,
            zswap::ZSWAP_EXPECTED_FILES.to_vec(),
        )
        .expect("data provider initialization failed")
    );
}

/// How much of a request the server is willing to take in before it knows it
/// can serve it.
///
/// A value rather than an environment read at the point of use: the limit has
/// to be settable in a test, and `std::env::set_var` is `unsafe` under Rust
/// 2024 and races every other test in the binary. [`Self::from_env`] is the
/// one place the environment is consulted, at the server's construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressConfig {
    /// Largest request body the server will buffer, in bytes.
    ///
    /// A `/prove` body carries the whole proving-key material inline: at k=20
    /// that is on the order of 269 MB, so the default has to clear it with
    /// room to spare while still being a bound.
    pub max_request_bytes: usize,

    /// How long the server will spend receiving one request body.
    ///
    /// The byte bound alone does not stop a client that sends its body one
    /// slow byte at a time: it holds the buffer, and the reserved queue slot,
    /// for as long as it likes. Actix's own `client_request_timeout` does not
    /// cover this — it is a deadline for reading the request *head* — so the
    /// body drain carries its own.
    pub read_timeout: Duration,
}

impl IngressConfig {
    /// The default bound: 512 MiB.
    pub const DEFAULT_MAX_REQUEST_BYTES: usize = 512 * 1024 * 1024;

    /// The default body deadline: 120 s. Generous enough for a few hundred MB
    /// over a slow link, short enough that a stalled sender gives the slot up.
    pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(120);

    /// Read the limit from `MIDNIGHT_PROOF_SERVER_MAX_REQUEST_BYTES`.
    ///
    /// An unset, empty or unparseable value falls back to the default and
    /// warns: a malformed tuning knob should not stop a server that would
    /// otherwise work.
    pub fn from_env() -> Self {
        let max_request_bytes = match std::env::var("MIDNIGHT_PROOF_SERVER_MAX_REQUEST_BYTES")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| v.parse::<usize>())
        {
            Some(Ok(bytes)) if bytes > 0 => bytes,
            Some(_) => {
                warn!(
                    default = Self::DEFAULT_MAX_REQUEST_BYTES,
                    "MIDNIGHT_PROOF_SERVER_MAX_REQUEST_BYTES is not a positive integer; \
                     using the default"
                );
                Self::DEFAULT_MAX_REQUEST_BYTES
            }
            None => Self::DEFAULT_MAX_REQUEST_BYTES,
        };
        let read_timeout = match std::env::var("MIDNIGHT_PROOF_SERVER_READ_TIMEOUT")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| v.parse::<u64>())
        {
            Some(Ok(secs)) if secs > 0 => Duration::from_secs(secs),
            Some(_) => {
                warn!(
                    "MIDNIGHT_PROOF_SERVER_READ_TIMEOUT is not a positive number of seconds; \
                     using the default"
                );
                Self::DEFAULT_READ_TIMEOUT
            }
            None => Self::DEFAULT_READ_TIMEOUT,
        };
        Self {
            max_request_bytes,
            read_timeout,
        }
    }
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: Self::DEFAULT_MAX_REQUEST_BYTES,
            read_timeout: Self::DEFAULT_READ_TIMEOUT,
        }
    }
}

/// Take a queue slot before reading the body, or answer 429 now.
///
/// `job_capacity` bounded proving but not ingress: the body was buffered, then
/// deserialised, then the proving-key material deep-copied, and only then was
/// admission checked. Any number of in-flight requests could therefore hold a
/// k=20 body each — hundreds of MB apiece — while the queue that was supposed
/// to bound the server sat full.
///
/// A *check* would not have fixed that: several requests can each observe
/// spare capacity, none of them having taken it, and then buffer a body apiece.
/// The reservation is the fix — the slot is Pending from this moment, so the
/// memory in flight is bounded by `job_capacity` and not by the number of
/// connections. The guard hands the slot back if the request never becomes
/// work, whether because the body was too large, arrived too slowly, or did
/// not deserialise.
async fn reserve_or_reject(pool: &WorkerPool) -> Result<Reservation, Error> {
    Ok(pool.reserve().await?)
}

/// Read a request body, refusing one larger than [`max_request_bytes`].
///
/// The declared `Content-Length` is checked first so an oversize request is
/// refused before a byte of it is read; a body that lies about its length, or
/// arrives chunked with none declared, is cut off at the same bound while
/// streaming. Actix's `PayloadConfig` does not cover this path: it bounds the
/// `Bytes` and `String` extractors, not a raw `Payload` the handler drains
/// itself.
async fn payload_to_bytes(req: &HttpRequest, payload: Payload) -> Result<Bytes, Error> {
    // A server built by `crate::server` always carries this; the defaults are
    // the same bounds, so a handler mounted without it is bounded too.
    let config = req
        .app_data::<Data<IngressConfig>>()
        .map(|c| **c.clone())
        .unwrap_or_default();
    tokio::time::timeout(
        config.read_timeout,
        read_payload(req, payload, config.max_request_bytes),
    )
    .await
    .map_err(|_| {
        ErrorRequestTimeout(format!(
            "request body not received within {} seconds",
            config.read_timeout.as_secs()
        ))
    })?
}

async fn read_payload(req: &HttpRequest, mut payload: Payload, max: usize) -> Result<Bytes, Error> {
    if let Some(declared) = req
        .headers()
        .get(actix_web::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        && declared > max
    {
        return Err(ErrorPayloadTooLarge(format!(
            "request declares {declared} bytes; the limit is {max}"
        )));
    }

    let mut body = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > max {
            return Err(ErrorPayloadTooLarge(format!(
                "request body exceeds the limit of {max} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// Hex-dump a request body at debug level, but only a small one.
///
/// The dump is twice the body's size in a `String`, so doing it for a k=20
/// `/prove` body meant half a gigabyte of hex on top of the body itself —
/// under `--verbose`, on a server whose whole problem is memory.
fn debug_request_body(what: &str, request: &Bytes) {
    const MAX_DUMP_BYTES: usize = 64 * 1024;
    if request.len() <= MAX_DUMP_BYTES {
        debug!("{what}: {}", (&request[..]).encode_hex::<String>());
    } else {
        debug!(
            "{what}: {} bytes, not dumped (over {MAX_DUMP_BYTES})",
            request.len()
        );
    }
}

type TransactionProvePayload<S> = (
    Transaction<S, ProofPreimageMarker, PedersenRandomness, InMemoryDB>,
    HashMap<String, ProvingKeyMaterial>,
);

#[get("/version")]
pub(crate) async fn version() -> impl Responder {
    env!("CARGO_PKG_VERSION")
}

#[get("/fetch-params/{k}")]
pub(crate) async fn fetch_k(path: web::Path<u8>) -> impl Responder {
    let k = path.into_inner();
    if !(0..=25).contains(&k) {
        return Err(ErrorBadRequest(format!("k={k} out of range")));
    }
    PUBLIC_PARAMS.0.fetch_k(k).await?;
    Ok("success")
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HealthResponse {
    status: &'static str,
    timestamp: time::OffsetDateTime,
}

pub(crate) async fn health() -> Result<web::Json<HealthResponse>, Error> {
    let status = HealthResponse {
        status: "ok",
        timestamp: time::OffsetDateTime::now_utc(),
    };
    Ok(web::Json(status))
}

#[derive(Clone, Copy, serde::Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Status {
    Ok,
    Busy,
}

impl From<Status> for StatusCode {
    fn from(val: Status) -> Self {
        match val {
            Status::Ok => StatusCode::OK,
            Status::Busy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadyResponse {
    status: Status,
    jobs_processing: usize,
    jobs_pending: usize,
    job_capacity: usize,
    timestamp: time::OffsetDateTime,
}

#[get("/ready")]
pub(crate) async fn ready(pool: web::Data<Arc<WorkerPool>>) -> Result<HttpResponse, Error> {
    let jobs_processing = pool.requests.processing_count().await;
    let jobs_pending = pool.requests.pending_count().await;
    let job_capacity = pool.requests.capacity;
    let status = ReadyResponse {
        status: if pool.requests.is_full().await {
            Status::Busy
        } else {
            Status::Ok
        },
        jobs_processing,
        jobs_pending,
        job_capacity,
        timestamp: time::OffsetDateTime::now_utc(),
    };

    let builder = HttpResponseBuilder::new(status.status.into()).json(status);
    Ok(builder)
}

#[get("/proof-versions")]
pub(crate) async fn proof_versions() -> impl Responder {
    let mut fields = ProofVersioned::introspection().fields;
    fields.retain(|x| x != "Dummy");
    format!("{:?}", fields)
}

#[post("/k")]
pub(crate) async fn get_k(req: HttpRequest, payload: Payload) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /k...");
    let request = payload_to_bytes(&req, payload).await?;
    debug_request_body("Received request", &request);

    let k = versioned_ir::k(&request).map_err(ErrorBadRequest)?;

    Ok(HttpResponse::Ok().body(format!("{k}")))
}

#[post("/check")]
pub(crate) async fn check(
    req: HttpRequest,
    pool: Data<Arc<WorkerPool>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /check...");
    let reservation = reserve_or_reject(&pool).await?;
    let request = payload_to_bytes(&req, payload).await?;
    debug_request_body("Received request", &request);
    let (ppi, ir): (ProofPreimageVersioned, Option<WrappedIr>) =
        tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;
    let (_id, updates) = pool
        .submit_reserved(reservation, move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async move {
                let ir = match ir {
                    Some(ir) => ir.0,
                    None => {
                        let resolver = Resolver::new(
                            PUBLIC_PARAMS.clone(),
                            DustResolver(
                                MidnightDataProvider::new(
                                    FetchMode::OnDemand,
                                    OutputMode::Log,
                                    ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                                )
                                .expect("data provider initialization failed"),
                            ),
                            Box::new(move |_: KeyLocation| Box::pin(std::future::ready(Ok(None)))),
                        );
                        let proof_data = resolver
                            .resolve_key(ppi.key_location().clone())
                            .await
                            .map_err(|e| WorkError::BadInput(e.to_string()))?;

                        proof_data
                            .ok_or_else(|| {
                                WorkError::BadInput(format!(
                                    "couldn't find built-in key {}",
                                    ppi.key_location().0
                                ))
                            })?
                            .ir_source
                    }
                };
                let result = match ppi {
                    ProofPreimageVersioned::V2(ppi) => {
                        versioned_ir::check(ppi, &ir).map_err(WorkError::BadInput)?
                    }
                    // Footgun: If we add a new version, this needs to be covered here, but it's marked
                    // #[non_exhaustive], so we always need the base case.
                    _ => unreachable!(),
                };
                let result = result
                    .into_iter()
                    .map(|i| i.map(|i| i as u64))
                    .collect::<Vec<_>>();
                let mut response = Vec::new();
                tagged_serialize(&result, &mut response)
                    .map_err(|e| WorkError::InternalError(e.to_string()))?;
                Ok(response)
            })
        })
        .await?;
    let response = JobStatus::wait_for_success(&updates).await?;

    Ok(HttpResponse::Ok().body(response))
}

#[post("/prove")]
pub(crate) async fn prove(
    req: HttpRequest,
    pool: Data<Arc<WorkerPool>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /prove...");
    // Held across the body read: the slot is taken now, and given back
    // automatically if this request never becomes work.
    let reservation = reserve_or_reject(&pool).await?;
    let request = payload_to_bytes(&req, payload).await?;
    debug_request_body("Received request", &request);
    let (ppi, data, binding_input): (
        ProofPreimageVersioned,
        Option<ProvingKeyMaterial>,
        Option<Fr>,
    ) = tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;

    // Share the proving-key material rather than deep-copying it. It is three
    // `Vec<u8>` that reach 269 MB at k=20, and the copy existed only so the
    // resolver closure could own one; behind an `Arc` the resolver pays for a
    // copy if and when it is actually consulted, and the common path pays for
    // none.
    let data = data.map(Arc::new);
    let data_resolver = data.clone();
    let (_id, updates) = pool
        .submit_reserved(reservation, move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let resolver = Resolver::new(
                    PUBLIC_PARAMS.clone(),
                    DustResolver(
                        MidnightDataProvider::new(
                            FetchMode::OnDemand,
                            OutputMode::Log,
                            ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                        )
                        .expect("data provider initialization failed"),
                    ),
                    Box::new(move |_: KeyLocation| {
                        Box::pin(std::future::ready(Ok(data_resolver.as_deref().cloned())))
                    }),
                );
                let proof = match ppi {
                    ProofPreimageVersioned::V2(mut ppi) => {
                        if let Some(binding_input) = binding_input {
                            let mut inner = (*ppi).clone();
                            inner.binding_input = binding_input;
                            ppi = Arc::new(inner);
                        }
                        let proving_data: Arc<ProvingKeyMaterial> = match data {
                            Some(pkm) => pkm,
                            None => Arc::new(
                                resolver
                                    .resolve_key(ppi.key_location.clone())
                                    .await
                                    .map_err(|e| WorkError::BadInput(e.to_string()))?
                                    .ok_or_else(|| {
                                        WorkError::BadInput(format!(
                                            "couldn't find key {}",
                                            ppi.key_location.0
                                        ))
                                    })?,
                            ),
                        };

                        let proof = versioned_ir::prove(ppi, &proving_data.ir_source, &resolver)
                            .await
                            .map_err(|e| match e {
                                versioned_ir::ProveError::BadInput(msg) => WorkError::BadInput(msg),
                                versioned_ir::ProveError::ServerEnvironment(msg) => {
                                    // The request was fine; this server is not.
                                    // Say so in the log, where the operator
                                    // looks, and answer 500, not 400.
                                    warn!("proving failed on the server's environment: {msg}");
                                    WorkError::InternalError(msg)
                                }
                            })?
                            .0;

                        ProofVersioned::V2(proof)
                    }
                    // Footgun: If we add a new version, this needs to be covered here, but it's marked
                    // #[non_exhaustive], so we always need the base case.
                    _ => unreachable!(),
                };
                let mut response = Vec::new();
                tagged_serialize(&proof, &mut response)
                    .map_err(|e| WorkError::InternalError(e.to_string()))?;
                Ok(response)
            })
        })
        .await?;
    let response = JobStatus::wait_for_success(&updates).await?;

    Ok(HttpResponse::Ok().body(response))
}

#[post("/prove-tx")]
pub(crate) async fn prove_transaction(
    req: HttpRequest,
    pool: Data<Arc<WorkerPool>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /prove-tx...");
    let reservation = reserve_or_reject(&pool).await?;
    let request = payload_to_bytes(&req, payload).await?;
    debug_request_body("Received request", &request);
    let (tx, keys): TransactionProvePayload<Signature> =
        tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;
    let (_id, updates) = pool
        .submit_reserved(reservation, move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut response = Vec::new();
                let resolver = Resolver::new(
                    PUBLIC_PARAMS.clone(),
                    DustResolver(
                        MidnightDataProvider::new(
                            FetchMode::OnDemand,
                            OutputMode::Log,
                            ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                        )
                        .expect("data provider initialization failed"),
                    ),
                    Box::new(move |loc| {
                        Box::pin(std::future::ready(Ok(keys.get(loc.0.as_ref()).cloned())))
                    }),
                );
                let provider = zkir_v2::LocalProvingProvider {
                    rng: OsRng,
                    params: &resolver,
                    resolver: &resolver,
                };
                // NOTE: The initial cost model here is part of why this is deprecated!
                // Use /prove instead!
                tagged_serialize(
                    &tx.prove(provider, &INITIAL_TRANSACTION_COST_MODEL.runtime_cost_model)
                        .await
                        .map_err(|e| WorkError::BadInput(e.to_string()))?,
                    &mut response,
                )
                .map_err(|e| WorkError::InternalError(e.to_string()))?;
                Ok(response)
            })
        })
        .await?;
    let response = JobStatus::wait_for_success(&updates).await?;
    Ok(HttpResponse::Ok().body(response))
}
