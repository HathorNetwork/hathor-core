// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn peergen_ed25519_matches_python_loader() {
    let peergen_path = env!("CARGO_BIN_EXE_peergen");
    let output = Command::new(peergen_path)
        .arg("--algo")
        .arg("ed25519")
        .output()
        .expect("failed to run peergen");
    assert!(
        output.status.success(),
        "peergen exited with {:?}",
        output.status.code()
    );

    let peer_value: Value =
        serde_json::from_slice(&output.stdout).expect("peergen must emit valid JSON");
    let priv_key_b64 = peer_value
        .get("privKey")
        .and_then(Value::as_str)
        .expect("privKey field");

    let pkcs8_bytes = BASE64_STANDARD
        .decode(priv_key_b64)
        .expect("privKey should be valid base64");
    assert!(
        has_nested_ed25519_private_key(&pkcs8_bytes),
        "Ed25519 PKCS#8 should use nested OCTET STRING as per RFC 8410"
    );

    let python = match find_python() {
        Some(python) => python,
        None => {
            eprintln!("skipping python compatibility check: no python interpreter found");
            return;
        }
    };

    if !has_cryptography_module(&python) {
        eprintln!(
            "skipping python compatibility check: '{}' lacks 'cryptography' module",
            python
        );
        return;
    }

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/check_peer_json.py");
    let mut child = Command::new(&python)
        .arg(script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run python script");
    child
        .stdin
        .as_mut()
        .expect("script stdin available")
        .write_all(&output.stdout)
        .expect("failed to write JSON to script");
    let script_output = child
        .wait_with_output()
        .expect("python script execution failed");

    assert!(
        script_output.status.success(),
        "python script failed: {}\nstdout: {}\nstderr: {}",
        script_output.status,
        String::from_utf8_lossy(&script_output.stdout),
        String::from_utf8_lossy(&script_output.stderr)
    );
}

fn has_nested_ed25519_private_key(pkcs8: &[u8]) -> bool {
    const NEEDLE: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    pkcs8
        .windows(NEEDLE.len())
        .position(|window| window == NEEDLE)
        .map(|idx| {
            let start = idx + NEEDLE.len();
            pkcs8.len() >= start + 32
        })
        .unwrap_or(false)
}

fn find_python() -> Option<String> {
    for candidate in ["python3", "python", "py"] {
        let status = Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(status) if status.success() => return Some(candidate.to_string()),
            Ok(_) | Err(_) => continue,
        }
    }
    None
}

fn has_cryptography_module(python: &str) -> bool {
    Command::new(python)
        .args(["-c", "import cryptography"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
