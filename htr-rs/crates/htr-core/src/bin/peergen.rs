// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, ValueHint};
use humantime::format_duration;
use indicatif::{HumanCount, HumanDuration, HumanFloatCount, ProgressStyle};
use thiserror::Error;
use tracing_indicatif::{
    IndicatifLayer,
    filter::{IndicatifFilter, hide_indicatif_span_fields},
    span_ext::IndicatifSpanExt,
};
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    layer::{Layer, SubscriberExt},
    util::SubscriberInitExt,
};

use htr_core::crypto::KeygenParams;
use htr_core::peer::{PeerAddress, PeerId, PrivatePeer};

type VanitySearchResult = Result<(PrivatePeer, PeerId), VanitySearchError>;

/// Simple generator for peer.json files.
#[derive(Debug, Parser)]
#[command(
    name = "peergen",
    about = "Generate a peer.json with selected key algorithm"
)]
struct Args {
    /// Key algorithm. Examples: rsa, rsa-2048, rsa-3072, rsa-4096, ecdsa, ecdsa-p256, ecdsa-p384, ed25519
    #[arg(long = "algo", value_name = "ALGO", value_hint = ValueHint::Other, value_enum)]
    algo: Option<KeygenParams>,

    /// Endpoint(s) to include; repeat to add multiple (e.g., -E tcp://127.0.0.1:8001)
    #[arg(short = 'E', long = "endpoint", value_name = "ENDPOINT", value_hint = ValueHint::Other)]
    endpoints: Vec<PeerAddress>,

    /// Output file path. If omitted, writes JSON to stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE", value_hint = ValueHint::FilePath)]
    output: Option<PathBuf>,

    /// Vanity prefix for the peer-id (hex, case-insensitive). When set, peergen brute-forces keys until the peer-id starts with this prefix.
    #[arg(long = "vanity-prefix", value_name = "HEX", value_hint = ValueHint::Other)]
    vanity_prefix: Option<String>,

    /// Number of worker threads used for vanity search (defaults to available parallelism).
    #[arg(long = "vanity-threads", value_name = "N", value_hint = ValueHint::Other, requires = "vanity_prefix")]
    vanity_threads: Option<usize>,
}

#[derive(Debug)]
struct VanityOptions {
    prefix_str: String,
    prefix_nibbles: Arc<[u8]>,
    threads: usize,
    progress_interval: Duration,
}

impl VanityOptions {
    fn new(prefix: &str, threads: Option<usize>) -> Result<Self, VanitySearchError> {
        let trimmed = prefix.trim();
        let normalized = trimmed.to_ascii_lowercase();
        if normalized.len() > 64 {
            return Err(VanitySearchError::PrefixTooLong {
                len: normalized.len(),
            });
        }
        if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VanitySearchError::InvalidPrefix {
                prefix: trimmed.to_owned(),
                reason: "must contain only hexadecimal characters (0-9, a-f)",
            });
        }

        let nibble_vec: Vec<u8> = normalized
            .bytes()
            .map(|b| hex_char_to_nibble(b).expect("validated above"))
            .collect();
        let threads = match threads {
            Some(0) => {
                return Err(VanitySearchError::InvalidThreadCount);
            }
            Some(n) => n,
            None => default_thread_count(),
        };

        Ok(Self {
            prefix_str: normalized,
            prefix_nibbles: Arc::from(nibble_vec.into_boxed_slice()),
            threads,
            progress_interval: Duration::from_secs(2),
        })
    }
}

struct VanityResult {
    peer: PrivatePeer,
    peer_id: PeerId,
    attempts: u64,
    elapsed: Duration,
}

#[derive(Debug, Error)]
enum VanitySearchError {
    #[error("invalid vanity prefix '{prefix}': {reason}")]
    InvalidPrefix {
        prefix: String,
        reason: &'static str,
    },
    #[error("vanity prefix length {len} exceeds peer-id length (64 hex characters)")]
    PrefixTooLong { len: usize },
    #[error("vanity thread count must be at least 1")]
    InvalidThreadCount,
    #[error("all workers exited without producing a result")]
    NoResult,
    #[error("key generation failed: {0}")]
    KeyGeneration(#[from] htr_core::peer::Error),
    #[error("failed to build thread pool: {0}")]
    ThreadPoolBuild(#[from] rayon::ThreadPoolBuildError),
    #[error("progress reporter thread panicked")]
    ProgressThreadPanicked,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let indicatif_layer = IndicatifLayer::new().with_span_field_formatter(
        hide_indicatif_span_fields(tracing_subscriber::fmt::format::DefaultFields::new()),
    );
    let stderr_writer = indicatif_layer.get_stderr_writer();
    let indicatif_layer = indicatif_layer.with_filter(IndicatifFilter::new(false));
    let env_filter = EnvFilter::builder()
        .with_env_var("HATHOR_LOG")
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_writer(stderr_writer)
        .with_filter(env_filter);
    let _ = tracing_subscriber::registry()
        .with(fmt_layer)
        .with(indicatif_layer)
        .try_init();

    let args = Args::parse();

    // Select keygen params
    let params: KeygenParams = args.algo.unwrap_or_default();

    // Generate peer
    let vanity_result = if let Some(prefix) = args.vanity_prefix.as_deref() {
        let options = VanityOptions::new(prefix, args.vanity_threads)?;
        eprintln!(
            "Searching for peer-id starting with '{}' using {} thread(s)...",
            options.prefix_str, options.threads,
        );
        let result = search_vanity(params, &options)?;
        eprintln!(
            "Found vanity peer-id {} after {} attempts in {}.",
            result.peer_id,
            result.attempts,
            format_duration(result.elapsed),
        );
        result.peer
    } else {
        PrivatePeer::generate(params)?
    };

    let mut peer = vanity_result;

    // Add endpoints without peer-id (PeerAddress -> PeerEndpoint)
    peer.endpoints
        .extend(args.endpoints.into_iter().map(Into::into));

    // Serialize JSON
    let json = serde_json::to_string_pretty(&peer)?;

    match args.output {
        Some(path) => {
            let mut f = File::create(&path)?;
            f.write_all(json.as_bytes())?;
            eprintln!("Wrote {}", path.display());
        }
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(json.as_bytes())?;
            stdout.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn search_vanity(
    params: KeygenParams,
    options: &VanityOptions,
) -> Result<VanityResult, VanitySearchError> {
    let start = Instant::now();
    let attempts = Arc::new(AtomicU64::new(0));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads)
        .build()?;

    let progress_span =
        tracing::info_span!("peergen_vanity", indicatif.pb_show = tracing::field::Empty);
    let progress_style = ProgressStyle::with_template("{spinner:.green} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner());
    progress_span.pb_set_style(&progress_style);
    let progress_guard = progress_span.enter();
    let initial_message = format!("prefix '{}' — warming up…", options.prefix_str);
    progress_span.pb_set_message(&initial_message);

    let done = Arc::new(AtomicBool::new(false));
    let progress_attempts = Arc::clone(&attempts);
    let progress_done = Arc::clone(&done);
    let progress_prefix = options.prefix_str.clone();
    let progress_interval = options.progress_interval;
    let prefix_bits = options.prefix_nibbles.len() * 4;
    let span_for_progress = progress_span.clone();
    let progress_start = start;
    let progress_handle = thread::spawn(move || {
        let mut last_attempts = 0u64;
        let mut last_tick = progress_start;
        while !progress_done.load(Ordering::Relaxed) {
            thread::sleep(progress_interval);
            let now = Instant::now();
            let total_attempts = progress_attempts.load(Ordering::Relaxed);
            let total_elapsed = now.duration_since(progress_start);
            let interval_elapsed = now.duration_since(last_tick);
            let interval_attempts = total_attempts - last_attempts;
            let total_rate = rate(total_attempts, total_elapsed);
            let recent_rate = rate(interval_attempts, interval_elapsed);
            let expectation_segment =
                expectation_summary(prefix_bits, total_rate).map(|summary| format!(", {summary}"));
            let attempts_str = HumanCount(total_attempts).to_string();
            let total_rate_str = HumanFloatCount(total_rate).to_string();
            let recent_rate_str = HumanFloatCount(recent_rate).to_string();
            let message = if let Some(summary) = expectation_segment {
                format!(
                    "prefix '{}' — {} attempts (total {} keys/s, recent {} keys/s{summary})",
                    progress_prefix, attempts_str, total_rate_str, recent_rate_str,
                )
            } else {
                format!(
                    "prefix '{}' — {} attempts (total {} keys/s, recent {} keys/s)",
                    progress_prefix, attempts_str, total_rate_str, recent_rate_str,
                )
            };
            span_for_progress.pb_set_message(&message);
            last_attempts = total_attempts;
            last_tick = now;
        }
    });

    let prefix = Arc::clone(&options.prefix_nibbles);
    let attempts_shared = Arc::clone(&attempts);
    let found = Arc::new(AtomicBool::new(false));
    let result_slot: Arc<Mutex<Option<VanitySearchResult>>> = Arc::new(Mutex::new(None));
    const ATTEMPT_FLUSH_BATCH: u64 = 64;

    pool.scope(|scope| {
        for _ in 0..options.threads {
            let attempts_for_worker = Arc::clone(&attempts_shared);
            let prefix = Arc::clone(&prefix);
            let found = Arc::clone(&found);
            let result_slot = Arc::clone(&result_slot);
            scope.spawn(move |_| {
                let mut local_attempts = 0u64;
                while !found.load(Ordering::Relaxed) {
                    match PrivatePeer::generate(params) {
                        Ok(peer) => {
                            local_attempts += 1;
                            let peer_id = peer.get_public_key_der().gen_peer_id();
                            if peer_id_matches(&peer_id, prefix.as_ref()) {
                                attempts_for_worker.fetch_add(local_attempts, Ordering::Relaxed);
                                local_attempts = 0;
                                if !found.swap(true, Ordering::Relaxed) {
                                    let mut slot = result_slot.lock().unwrap();
                                    *slot = Some(Ok((peer, peer_id)));
                                }
                                break;
                            }
                            if local_attempts >= ATTEMPT_FLUSH_BATCH {
                                attempts_for_worker.fetch_add(local_attempts, Ordering::Relaxed);
                                local_attempts = 0;
                            }
                        }
                        Err(err) => {
                            local_attempts += 1;
                            attempts_for_worker.fetch_add(local_attempts, Ordering::Relaxed);
                            local_attempts = 0;
                            if !found.swap(true, Ordering::Relaxed) {
                                let mut slot = result_slot.lock().unwrap();
                                *slot = Some(Err(VanitySearchError::KeyGeneration(err)));
                            }
                            break;
                        }
                    }
                }
                if local_attempts > 0 {
                    attempts_for_worker.fetch_add(local_attempts, Ordering::Relaxed);
                }
            });
        }
    });

    done.store(true, Ordering::Relaxed);
    if progress_handle.join().is_err() {
        return Err(VanitySearchError::ProgressThreadPanicked);
    }
    drop(progress_guard);
    drop(progress_span);

    let attempts_total = attempts.load(Ordering::Relaxed);
    let elapsed = start.elapsed();

    let outcome = Arc::try_unwrap(result_slot)
        .expect("all worker references dropped")
        .into_inner()
        .unwrap();

    match outcome {
        Some(Ok((peer, peer_id))) => Ok(VanityResult {
            peer,
            peer_id,
            attempts: attempts_total,
            elapsed,
        }),
        Some(Err(err)) => Err(err),
        None => Err(VanitySearchError::NoResult),
    }
}

fn rate(attempts: u64, elapsed: Duration) -> f64 {
    if elapsed.as_secs_f64() == 0.0 {
        0.0
    } else {
        attempts as f64 / elapsed.as_secs_f64()
    }
}

fn expectation_summary(prefix_bits: usize, total_rate: f64) -> Option<String> {
    if prefix_bits == 0 || total_rate <= 0.0 {
        return None;
    }
    let expected_attempts = 2f64.powi(prefix_bits as i32);
    if !expected_attempts.is_finite() {
        return None;
    }
    let expected_seconds = expected_attempts / total_rate;
    if !expected_seconds.is_finite() || expected_seconds <= 0.0 {
        return None;
    }
    if expected_seconds >= Duration::MAX.as_secs_f64() {
        return None;
    }
    let expected_duration = Duration::from_secs_f64(expected_seconds);
    let success_prob = 1.0 / expected_attempts;
    let denom = (1.0 - success_prob).ln();
    let p95 = if denom.is_sign_negative() {
        let attempts_p95 = (0.05_f64.ln() / denom).ceil();
        let seconds_p95 = attempts_p95 / total_rate;
        if seconds_p95.is_finite() && seconds_p95 > 0.0 && seconds_p95 < Duration::MAX.as_secs_f64()
        {
            Some(Duration::from_secs_f64(seconds_p95))
        } else {
            None
        }
    } else {
        None
    };
    let expected_str = HumanDuration(expected_duration).to_string();
    if let Some(p95_duration) = p95 {
        Some(format!(
            "E[t] ~{}, P95 ~{}",
            expected_str,
            HumanDuration(p95_duration)
        ))
    } else {
        Some(format!("E[t] ~{}", expected_str))
    }
}

fn default_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn hex_char_to_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn peer_id_matches(peer_id: &htr_core::peer::PeerId, prefix: &[u8]) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let bytes = peer_id.as_ref().as_ref();
    for (index, expected_nibble) in prefix.iter().enumerate() {
        let byte = bytes[index / 2];
        let nibble = if index % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0F
        };
        if nibble != *expected_nibble {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use htr_core::common::Hash32;
    use htr_core::peer::PeerId;

    #[test]
    fn hex_parser_accepts_valid_prefix() {
        let opts = VanityOptions::new("caffe", Some(1)).expect("valid prefix");
        assert_eq!(opts.prefix_str, "caffe");
        assert_eq!(opts.prefix_nibbles.len(), 5);
    }

    #[test]
    fn hex_parser_rejects_invalid_char() {
        let err = VanityOptions::new("caffg", Some(1)).unwrap_err();
        let VanitySearchError::InvalidPrefix { .. } = err else {
            panic!("unexpected error: {err:?}");
        };
    }

    #[test]
    fn peer_id_matching_checks_nibbles() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xca;
        bytes[1] = 0xff;
        bytes[2] = 0xe0;
        let peer_id = PeerId::from(Hash32(bytes));
        let prefix = VanityOptions::new("caffe", Some(1))
            .expect("valid")
            .prefix_nibbles;
        assert!(peer_id_matches(&peer_id, prefix.as_ref()));
        assert!(!peer_id_matches(&peer_id, &[0xc, 0xa, 0xf, 0xf, 0xf]));
    }
}
