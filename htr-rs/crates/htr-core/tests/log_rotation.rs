// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use htr_core::logging;
use std::fs;
use std::thread;
use std::time::{Duration, Instant};
use tokio::runtime::Builder;
use tokio::sync::oneshot;
use tracing::info;
use tracing_subscriber::filter::LevelFilter;

#[test]
fn log_file_reloads_on_sigusr1() {
    let tmp = TestDir::new();
    let log_dir = tmp.path();

    let handle =
        logging::setup_logging_with_level(log_dir, LevelFilter::INFO).expect("setup logging");

    info!("initial log line");
    wait_for(
        || log_dir.join("logs.jsonl").exists(),
        Duration::from_secs(2),
    );

    let log_path = log_dir.join("logs.jsonl");
    let rotated_path = log_dir.join("logs.jsonl.rotated");
    fs::rename(&log_path, &rotated_path).expect("rename log file");
    assert!(!log_path.exists(), "log path should be absent after rename");

    let pre_signal_marker = "still-using-rotated-file";
    info!("{pre_signal_marker}");
    wait_for(
        || file_contains(&rotated_path, pre_signal_marker),
        Duration::from_secs(2),
    );
    assert!(
        !log_path.exists(),
        "log path should remain absent before signal"
    );

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let watcher_handle = handle.clone();
    let watcher = thread::spawn(move || {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create runtime");
        runtime.block_on(async move {
            tokio::select! {
                _ = logging::watch_for_log_reopen_signals(watcher_handle) => {},
                _ = shutdown_rx => {},
            }
        });
    });

    thread::sleep(Duration::from_millis(100));

    unsafe {
        libc::raise(libc::SIGUSR1);
    }

    wait_for(|| log_path.exists(), Duration::from_secs(2));
    let post_signal_marker = "after-signal-new-file";
    info!("{post_signal_marker}");
    wait_for(
        || file_contains(&log_path, post_signal_marker),
        Duration::from_secs(2),
    );

    shutdown_tx.send(()).ok();
    watcher.join().expect("watcher thread join");

    let rotated_contents = fs::read_to_string(&rotated_path).expect("read rotated log contents");
    assert!(
        rotated_contents.contains(pre_signal_marker),
        "rotated file should contain pre-signal entries"
    );
    assert!(
        !rotated_contents.contains(post_signal_marker),
        "rotated file should not contain post-signal entries"
    );

    let new_contents = fs::read_to_string(&log_path).expect("read new log contents");
    assert!(
        new_contents.contains(post_signal_marker),
        "new log file should contain post-signal entries"
    );
    assert!(
        !new_contents.contains(pre_signal_marker),
        "new log file should not contain pre-signal entries"
    );
}

fn wait_for(mut condition: impl FnMut() -> bool, timeout: Duration) {
    let start = Instant::now();
    while !condition() {
        if start.elapsed() > timeout {
            panic!("condition not satisfied within {:?}", timeout);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn file_contains(path: &std::path::Path, needle: &str) -> bool {
    match fs::read_to_string(path) {
        Ok(contents) => contents.contains(needle),
        Err(_) => false,
    }
}

struct TestDir {
    path: std::path::PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        for attempt in 0..1000 {
            let candidate = base.join(format!("hathor-logtest-{pid}-{now}-{attempt}"));
            match std::fs::create_dir(&candidate) {
                Ok(()) => return Self { path: candidate },
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("failed to create temp dir {candidate:?}: {err}"),
            }
        }
        panic!("could not create temporary directory");
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
