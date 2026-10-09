// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(feature = "tokio-console", tokio_unstable))]
use console_subscriber::ConsoleLayer;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tracing::Subscriber;
use tracing_error::ErrorLayer;
use tracing_indicatif::{
    IndicatifLayer,
    filter::{IndicatifFilter, hide_indicatif_span_fields},
};
use tracing_subscriber::fmt::{self, MakeWriter};
#[cfg(all(feature = "tokio-console", tokio_unstable))]
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{
    filter::{Directive, EnvFilter, LevelFilter},
    prelude::*,
};

static LOG_HANDLE: OnceLock<LogHandle> = OnceLock::new();

#[derive(Clone, Default)]
pub struct LogHandle {
    state: Option<Arc<ReopenState>>,
}

impl LogHandle {
    fn new(state: Option<Arc<ReopenState>>) -> Self {
        Self { state }
    }

    pub fn reload_log_file(&self) -> io::Result<()> {
        if let Some(state) = &self.state {
            state.reopen()
        } else {
            Ok(())
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn has_reopen_state(&self) -> bool {
        self.state.is_some()
    }
}

pub fn current_log_handle() -> Option<LogHandle> {
    LOG_HANDLE.get().cloned()
}

struct ReopenState {
    path: PathBuf,
    file: Mutex<File>,
}

impl ReopenState {
    fn new(path: PathBuf) -> io::Result<Self> {
        let file = Self::open_file(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    fn open_file(path: &Path) -> io::Result<File> {
        OpenOptions::new().create(true).append(true).open(path)
    }

    fn reopen(&self) -> io::Result<()> {
        let mut file = self.lock_file();
        *file = Self::open_file(&self.path)?;
        Ok(())
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut file = self.lock_file();
        file.write(buf)
    }

    fn flush(&self) -> io::Result<()> {
        let mut file = self.lock_file();
        file.flush()
    }

    fn lock_file(&self) -> std::sync::MutexGuard<'_, File> {
        self.file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Clone)]
struct ReopeningWriter {
    state: Arc<ReopenState>,
}

impl ReopeningWriter {
    fn new(state: Arc<ReopenState>) -> Self {
        Self { state }
    }
}

struct ReopenGuard {
    state: Arc<ReopenState>,
}

impl<'a> MakeWriter<'a> for ReopeningWriter {
    type Writer = ReopenGuard;

    fn make_writer(&'a self) -> Self::Writer {
        ReopenGuard {
            state: self.state.clone(),
        }
    }
}

impl Write for ReopenGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.state.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state.flush()
    }
}

pub fn setup_logging_with_level(
    log_dir: impl AsRef<Path>,
    fallback_level: LevelFilter,
) -> Result<LogHandle, Box<dyn Error>> {
    setup_logging_with_level_and_filters(log_dir, fallback_level, &[])
}

pub fn setup_logging_with_level_and_filters(
    log_dir: impl AsRef<Path>,
    fallback_level: LevelFilter,
    filters: &[String],
) -> Result<LogHandle, Box<dyn Error>> {
    let log_dir = log_dir.as_ref();

    // Preflight: ensure directory exists and we can create/append a file.
    let mut file_logging_ok = true;
    if let Err(e) = std::fs::create_dir_all(log_dir) {
        eprintln!(
            "logging: could not create log dir '{}': {}; falling back to stdout",
            log_dir.display(),
            e
        );
        file_logging_ok = false;
    }

    // see: https://jsonlines.org/
    let log_file_path = log_dir.join("logs.jsonl");
    let file_state = if file_logging_ok {
        match ReopenState::new(log_file_path.clone()) {
            Ok(state) => Some(Arc::new(state)),
            Err(e) => {
                eprintln!(
                    "logging: cannot create log file '{}': {}; falling back to stdout",
                    log_file_path.display(),
                    e
                );
                None
            }
        }
    } else {
        None
    };

    let env_filter_builder = EnvFilter::builder()
        .with_env_var("HATHOR_LOG")
        .with_default_directive(fallback_level.into());

    let enable_console = std::env::var("HATHOR_ENABLE_CONSOLE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if let Some(state) = file_state.clone() {
        let env_filter_stdout = env_filter_builder.clone().from_env_lossy();
        let env_filter_file = env_filter_builder.clone().from_env_lossy();
        let env_filter_stdout = apply_directives(env_filter_stdout, filters);
        let env_filter_file = apply_directives(env_filter_file, filters);

        let indicatif_layer = IndicatifLayer::new().with_span_field_formatter(
            hide_indicatif_span_fields(fmt::format::DefaultFields::new()),
        );
        let stdout_writer = indicatif_layer.get_stdout_writer();
        let indicatif_layer = indicatif_layer.with_filter(IndicatifFilter::new(false));

        let json_format = fmt::format()
            .json()
            .flatten_event(true)
            .with_file(false)
            .with_line_number(false)
            .with_target(true);

        let stdout_layer = fmt::layer()
            .compact()
            .with_writer(stdout_writer)
            .with_filter(env_filter_stdout)
            .boxed();
        let file_layer = fmt::layer()
            .json()
            .event_format(json_format)
            .with_writer(ReopeningWriter::new(state.clone()))
            .with_filter(env_filter_file)
            .boxed();

        let subscriber = tracing_subscriber::registry()
            .with(ErrorLayer::default())
            .with(indicatif_layer)
            .with(file_layer)
            .with(stdout_layer);

        init_subscriber(subscriber, enable_console);

        let handle = LogHandle::new(Some(state));
        let _ = LOG_HANDLE.set(handle.clone());
        return Ok(handle);
    }

    let env_filter_stdout = env_filter_builder.clone().from_env_lossy();
    let env_filter_stdout = apply_directives(env_filter_stdout, filters);
    let indicatif_layer = IndicatifLayer::new()
        .with_span_field_formatter(hide_indicatif_span_fields(fmt::format::DefaultFields::new()));
    let stdout_writer = indicatif_layer.get_stdout_writer();
    let indicatif_layer = indicatif_layer.with_filter(IndicatifFilter::new(false));
    let stdout_layer = fmt::layer()
        .compact()
        .with_writer(stdout_writer)
        .with_filter(env_filter_stdout)
        .boxed();

    let subscriber = tracing_subscriber::registry()
        .with(ErrorLayer::default())
        .with(indicatif_layer)
        .with(stdout_layer);

    init_subscriber(subscriber, enable_console);

    let handle = LogHandle::default();
    let _ = LOG_HANDLE.set(handle.clone());
    Ok(handle)
}

fn apply_directives(mut filter: EnvFilter, directives: &[String]) -> EnvFilter {
    for directive in directives {
        match directive.parse::<Directive>() {
            Ok(d) => filter = filter.add_directive(d),
            Err(err) => eprintln!("logging: ignoring invalid filter '{}': {}", directive, err),
        }
    }
    filter
}

pub fn setup_logging(log_dir: impl AsRef<Path>) -> Result<LogHandle, Box<dyn Error>> {
    setup_logging_with_level(log_dir, LevelFilter::INFO)
}

#[cfg(unix)]
pub async fn watch_for_log_reopen_signals(handle: LogHandle) {
    use tokio::signal::unix::{SignalKind, signal};

    if !handle.has_reopen_state() {
        return;
    }

    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(%err, "logging: failed to register SIGHUP handler for log reload");
            return;
        }
    };
    let mut sigusr1 = match signal(SignalKind::user_defined1()) {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(%err, "logging: failed to register SIGUSR1 handler for log reload");
            return;
        }
    };

    loop {
        tokio::select! {
            recv = sighup.recv() => {
                match recv {
                    Some(_) => {
                        if let Err(err) = handle.reload_log_file() {
                            tracing::warn!(%err, "logging: failed to reopen log file after SIGHUP");
                        }
                    }
                    None => {
                        tracing::warn!("logging: SIGHUP signal stream closed; stopping log reload watcher");
                        break;
                    }
                }
            }
            recv = sigusr1.recv() => {
                match recv {
                    Some(_) => {
                        if let Err(err) = handle.reload_log_file() {
                            tracing::warn!(%err, "logging: failed to reopen log file after SIGUSR1");
                        }
                    }
                    None => {
                        tracing::warn!("logging: SIGUSR1 signal stream closed; stopping log reload watcher");
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(all(feature = "tokio-console", tokio_unstable))]
fn init_subscriber<S>(subscriber: S, enable_console: bool)
where
    S: Subscriber + Send + Sync + 'static + for<'span> LookupSpan<'span>,
{
    if enable_console {
        subscriber.with(ConsoleLayer::builder().spawn()).init();
    } else {
        subscriber.init();
    }
}

// The `tokio-console` feature is enabled but the binary was built without `--cfg tokio_unstable`,
// so the console layer would receive no task data. Skip it and warn at runtime rather than failing
// the build — this keeps the crate compiling under the workspace's `--all-features` checks.
#[cfg(all(feature = "tokio-console", not(tokio_unstable)))]
fn init_subscriber<S>(subscriber: S, enable_console: bool)
where
    S: Subscriber + Send + Sync + 'static,
{
    if enable_console {
        eprintln!(
            "HATHOR_ENABLE_CONSOLE set and 'tokio-console' feature enabled, but the binary was \
             built without --cfg tokio_unstable; the console would receive no data, ignoring"
        );
    }
    subscriber.init();
}

#[cfg(not(feature = "tokio-console"))]
fn init_subscriber<S>(subscriber: S, enable_console: bool)
where
    S: Subscriber + Send + Sync + 'static,
{
    if enable_console {
        eprintln!(
            "HATHOR_ENABLE_CONSOLE set, but binary built without 'tokio-console' feature; ignoring"
        );
    }
    subscriber.init();
}
