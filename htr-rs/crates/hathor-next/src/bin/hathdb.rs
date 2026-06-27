// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use bytes::{Buf, BufMut, BytesMut};
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use hathor_next::vertex::DagData;
use hathor_next::vertex::{AnyVertexData, decode_any_vertex_data, encode_any_vertex_data};
use thiserror::Error;
use tracing::*;
use tracing_subscriber::filter::LevelFilter;

#[derive(Debug, Parser)]
#[command(
    name = "hathdb-roundtrip",
    version,
    about = "Decode and re-encode HathDB dumps for perf testing"
)]
struct Cli {
    /// Input HathDB file
    #[arg(value_name = "INPUT")]
    input: PathBuf,
    /// Output file (default: INPUT with ".roundtrip" suffix)
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
}

#[derive(Debug, Error)]
enum RtError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parsing error: {0}")]
    Buf(#[from] bytes::TryGetError),
    #[error("format error: {0}")]
    Format(&'static str),
    #[error("decode error: {0}")]
    Decode(String),
}

const MAGIC: &[u8; 6] = b"HathDB";

struct ParsedDump {
    tx_count: u32,
    block_count: u32,
    vertices: Vec<AnyVertexData>,
    genesis_hack: bool,
}

impl ParsedDump {
    fn get_tx_count(&self) -> u32 {
        if self.genesis_hack {
            self.tx_count + 2
        } else {
            self.tx_count
        }
    }
    fn get_block_count(&self) -> u32 {
        if self.genesis_hack {
            self.block_count + 1
        } else {
            self.block_count
        }
    }
}

fn try_parse_dump(mut buf: &[u8]) -> Result<ParsedDump, RtError> {
    if buf.len() < MAGIC.len() + 8 {
        return Err(RtError::Format("file too small"));
    }
    if &buf[..MAGIC.len()] != MAGIC {
        return Err(RtError::Format("invalid header magic"));
    }
    // advance past magic using slice; then rely solely on Buf methods
    buf = &buf[MAGIC.len()..];
    let orig_tx_count = buf.try_get_u32()?; // big-endian
    let orig_block_count = buf.try_get_u32()?; // big-endian
    let total_count = (orig_tx_count as usize).saturating_add(orig_block_count as usize);

    let mut vertices: Vec<AnyVertexData> = Vec::with_capacity(total_count);
    let mut tx_count = 0u32;
    let mut block_count = 0u32;
    let mut genesis_hack = false;

    while buf.remaining() > 0 {
        let len = buf.try_get_u32()? as usize;
        if buf.remaining() < len {
            return Err(RtError::Format("truncated vertex payload"));
        }
        let payload = buf.copy_to_bytes(len);
        let vertex =
            decode_any_vertex_data(payload).map_err(|e| RtError::Decode(format!("{e}")))?;
        if vertex.kind().is_block() {
            block_count = block_count
                .checked_add(1)
                .ok_or(RtError::Format("count overflow"))?
        } else {
            tx_count = tx_count
                .checked_add(1)
                .ok_or(RtError::Format("count overflow"))?
        }
        vertices.push(vertex);
    }

    // Buf is fully consumed
    debug_assert_eq!(buf.remaining(), 0);
    if tx_count != orig_tx_count || block_count != orig_block_count {
        // XXX: compensate for a bug where the exporter could have written a wrong count because of
        // the genesis not being added to the export but being added to the counts
        let orig_tx_count = orig_tx_count - 2;
        let orig_block_count = orig_block_count - 1;
        if tx_count == orig_tx_count && block_count == orig_block_count {
            genesis_hack = true;
        } else {
            return Err(RtError::Format("header counts do not match parsed items"));
        }
    }

    Ok(ParsedDump {
        tx_count,
        block_count,
        vertices,
        genesis_hack,
    })
}

fn write_dump(out_path: &PathBuf, dump: &ParsedDump) -> Result<(), RtError> {
    let mut file = File::create(out_path)?;

    let mut header = Vec::with_capacity(6 + 8);
    header.extend_from_slice(MAGIC);
    header.put_u32(dump.get_tx_count());
    header.put_u32(dump.get_block_count());
    file.write_all(&header)?;

    let mut buf = BytesMut::with_capacity(1024);
    for v in &dump.vertices {
        buf.clear();
        encode_any_vertex_data(&mut buf, v).map_err(|_| RtError::Format("encode failed"))?;
        let bytes = buf.as_ref();
        let mut len_prefix = Vec::with_capacity(4);
        len_prefix.put_u32(bytes.len() as u32);
        file.write_all(&len_prefix)?;
        file.write_all(bytes)?;
    }
    Ok(())
}

fn main() -> Result<(), RtError> {
    let cli = Cli::parse();

    let max_level = cli.verbosity.tracing_level().unwrap_or(Level::INFO);
    let fallback_level = match max_level {
        Level::ERROR => LevelFilter::ERROR,
        Level::WARN => LevelFilter::WARN,
        Level::INFO => LevelFilter::INFO,
        Level::DEBUG => LevelFilter::DEBUG,
        Level::TRACE => LevelFilter::TRACE,
    };

    // Prepare logs directory and initialize logging via helper
    let logs_dir = hathor_next::utils::project_dir()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"))
        .join("logs");
    std::fs::create_dir_all(&logs_dir)?;
    let _guard = hathor_next::logging::setup_logging_with_level(&logs_dir, fallback_level)
        .expect("failed to setup logging");

    // Read full file into memory
    let mut f = File::open(&cli.input)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    let parsed = try_parse_dump(&data)?;
    info!(
        tx = parsed.tx_count,
        blocks = parsed.block_count,
        total = parsed.vertices.len(),
        "parsed HathDB dump"
    );

    let out_path = cli.output.unwrap_or_else(|| {
        let mut p = cli.input.clone();
        let suffix = match p.file_name().and_then(|n| n.to_str()) {
            Some(name) => format!("{name}.roundtrip"),
            None => String::from("roundtrip.hdb"),
        };
        p.set_file_name(suffix);
        p
    });

    write_dump(&out_path, &parsed)?;
    info!(path = %out_path.display(), "wrote roundtrip dump");

    Ok(())
}
