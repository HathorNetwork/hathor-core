//! Bytes-only RocksDB storage layer.
//!
//! Owns the primary RocksDB handle and exposes the operation surface hathor-core uses
//! through python-rocksdb (see `plans/rust-rocksdb-storage.md` for the inventory): point
//! reads/writes, atomic write batches, seekable iterators, `key_may_exist`, properties and
//! column-family management. Values are raw bytes; no parsing or serialization happens here.
//!
//! This crate is pure Rust — no Python types. The PyO3 bindings in `htr-lib-py` wrap these
//! types, release the GIL around each call, and translate [`StorageError`] into Python
//! exceptions. Rust consumers (the batch-verification pipeline) share the same primary handle
//! via [`RocksDb::native`].

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use rocksdb::{DBWithThreadMode, MultiThreaded, Options, WriteBatch as RawWriteBatch};

/// Multi-threaded mode: `create_cf`/`drop_cf` take `&self`, and column-family handles are
/// resolved by name per call, so callers never hold raw CF pointers across an FFI boundary.
pub type Db = DBWithThreadMode<MultiThreaded>;

/// Result alias for the storage layer.
pub type StorageResult<T> = Result<T, StorageError>;

/// A storage-layer failure.
///
/// The PyO3 wrapper maps [`StorageError::Io`] to `IOError` and every other variant to
/// `ValueError`, preserving the exception types hathor-core relied on under python-rocksdb.
#[derive(Debug)]
pub enum StorageError {
    /// An operation was attempted after [`RocksDb::close`].
    Closed,
    /// No live column family has this name.
    UnknownColumnFamily(String),
    /// A write batch was reused after it had already been applied (batches are single-use).
    BatchConsumed,
    /// An iterator was opened with an invalid mode/key combination, or asked for a zero-sized
    /// chunk. Carries the full human-readable message.
    InvalidArgument(String),
    /// An underlying RocksDB failure.
    Io(rocksdb::Error),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Closed => f.write_str("database is closed"),
            StorageError::UnknownColumnFamily(name) => {
                write!(f, "unknown column family: '{name}'")
            }
            StorageError::BatchConsumed => f.write_str("write batch already consumed"),
            StorageError::InvalidArgument(message) => f.write_str(message),
            StorageError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rocksdb::Error> for StorageError {
    fn from(error: rocksdb::Error) -> Self {
        StorageError::Io(error)
    }
}

/// Mirror of the options set by `hathor/storage/rocksdb_storage.py`. Keep the two in sync:
/// they affect performance and disk behavior (not correctness), and silent divergence would
/// be hard to notice.
fn build_options(cache_capacity: Option<usize>) -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(rocksdb::DBCompressionType::None);
    opts.set_allow_mmap_writes(true);
    opts.set_allow_mmap_reads(true);
    opts.set_write_buffer_size(83_886_080); // 80MB (default is 4MB)
    // Limits the total size of WAL files; when reached RocksDB flushes to free disk space.
    opts.set_max_total_wal_size(3 * 1024 * 1024 * 1024); // 3GB
    let mut table_opts = rocksdb::BlockBasedOptions::default();
    if let Some(capacity) = cache_capacity {
        let cache = rocksdb::Cache::new_lru_cache(capacity);
        table_opts.set_block_cache(&cache);
    }
    // SST files use the bundled librocksdb's current default format, which the older
    // librocksdb behind python-rocksdb cannot read ("Unknown Footer version"). That is
    // accepted: switching backends means starting from a fresh database and re-syncing
    // (decision recorded in plans/rust-rocksdb-storage.md), so no cross-binding file
    // compatibility is maintained in either direction.
    opts.set_block_based_table_factory(&table_opts);
    opts
}

/// Shared state behind the handle: the DB plus the live column-family name set (RocksDB has
/// no "list live CFs on an open DB" call, so the set is maintained here: initialized from
/// `list_cf` at open, updated by `create_cf`/`drop_cf`).
struct DbState {
    db: Arc<Db>,
    cf_names: BTreeSet<String>,
}

/// Bytes-only handle over the primary RocksDB database.
///
/// Column families are addressed by name; an unknown name yields
/// [`StorageError::UnknownColumnFamily`], and any use after [`close`](RocksDb::close) yields
/// [`StorageError::Closed`].
pub struct RocksDb {
    /// `None` after `close()`. Iterators hold their own `Arc<Db>`, so the underlying DB
    /// closes when the last holder drops.
    state: Mutex<Option<DbState>>,
}

impl RocksDb {
    /// Open (or create) the database at `path`, mirroring `hathor/storage/rocksdb_storage.py`:
    /// list the existing column families and open them all; when the DB does not exist yet,
    /// python-rocksdb creates it via `repair_db`, replicated here (with `create_if_missing`
    /// as a strictly-more-robust fallback if repair itself fails on the empty directory).
    pub fn open(path: &str, cache_capacity: Option<usize>) -> StorageResult<Self> {
        let opts = build_options(cache_capacity);
        let cf_names = match Db::list_cf(&opts, path) {
            Ok(names) => names,
            Err(_) => {
                // The DB does not exist: a repair creates an empty one.
                let _ = Db::repair(&opts, path);
                Db::list_cf(&opts, path).unwrap_or_default()
            }
        };
        let mut open_opts = opts.clone();
        open_opts.create_if_missing(true);
        let descriptors = cf_names
            .iter()
            .map(|name| rocksdb::ColumnFamilyDescriptor::new(name, Options::default()));
        let db = Db::open_cf_descriptors(&open_opts, path, descriptors)?;
        let mut names: BTreeSet<String> = cf_names.into_iter().collect();
        names.insert("default".to_string());
        Ok(Self {
            state: Mutex::new(Some(DbState {
                db: Arc::new(db),
                cf_names: names,
            })),
        })
    }

    /// Clone the handle out of the mutex (so RocksDB calls run without holding it).
    fn db(&self) -> StorageResult<Arc<Db>> {
        let guard = self.state.lock().expect("RocksDb mutex poisoned");
        match guard.as_ref() {
            Some(state) => Ok(Arc::clone(&state.db)),
            None => Err(StorageError::Closed),
        }
    }

    /// Access the shared handle from Rust code. `None` after `close()`.
    pub fn native(&self) -> Option<Arc<Db>> {
        let guard = self.state.lock().expect("RocksDb mutex poisoned");
        guard.as_ref().map(|state| Arc::clone(&state.db))
    }

    /// Point read; `None` when the key is absent.
    pub fn get(&self, cf: &str, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let db = self.db()?;
        let handle = cf_handle(&db, cf)?;
        Ok(db.get_cf(&handle, key)?)
    }

    /// Batched point reads, in input order; `None` per absent key.
    pub fn multi_get(&self, cf: &str, keys: &[Vec<u8>]) -> StorageResult<Vec<Option<Vec<u8>>>> {
        let db = self.db()?;
        let handle = cf_handle(&db, cf)?;
        let results = db.multi_get_cf(keys.iter().map(|key| (&handle, key)));
        results
            .into_iter()
            .map(|result| result.map_err(StorageError::Io))
            .collect()
    }

    pub fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> StorageResult<()> {
        let db = self.db()?;
        let handle = cf_handle(&db, cf)?;
        Ok(db.put_cf(&handle, key, value)?)
    }

    pub fn delete(&self, cf: &str, key: &[u8]) -> StorageResult<()> {
        let db = self.db()?;
        let handle = cf_handle(&db, cf)?;
        Ok(db.delete_cf(&handle, key)?)
    }

    /// Apply a write batch atomically (all column families, all ops, one WAL write). The batch
    /// is consumed: a second `write` of the same batch yields [`StorageError::BatchConsumed`].
    pub fn write(&self, batch: &WriteBatch) -> StorageResult<()> {
        let db = self.db()?;
        let ops = batch.take_ops()?;
        let mut wb = RawWriteBatch::default();
        for op in &ops {
            match op {
                BatchOp::Put { cf, key, value } => {
                    let handle = cf_handle(&db, cf)?;
                    wb.put_cf(&handle, key, value);
                }
                BatchOp::Delete { cf, key } => {
                    let handle = cf_handle(&db, cf)?;
                    wb.delete_cf(&handle, key);
                }
            }
        }
        Ok(db.write(wb)?)
    }

    /// Open a chunked iterator over `cf`. `mode` is one of `"first"`, `"last"`, `"seek"`,
    /// `"seek_for_prev"` (the latter two require `key`); `reverse` sets the scan direction
    /// after the initial position.
    pub fn iterator(
        &self,
        cf: &str,
        mode: &str,
        key: Option<Vec<u8>>,
        reverse: bool,
    ) -> StorageResult<DbIterator> {
        let db = self.db()?;
        // Fail fast on a bad CF name so the error surfaces at open, like python-rocksdb.
        cf_handle(&db, cf)?;
        let start = match (mode, key) {
            ("first", None) => IterStart::First,
            ("last", None) => IterStart::Last,
            ("seek", Some(key)) => IterStart::Seek(key),
            ("seek_for_prev", Some(key)) => IterStart::SeekForPrev(key),
            ("seek" | "seek_for_prev", None) => {
                return Err(StorageError::InvalidArgument(format!(
                    "mode '{mode}' requires a key"
                )));
            }
            ("first" | "last", Some(_)) => {
                return Err(StorageError::InvalidArgument(format!(
                    "mode '{mode}' does not take a key"
                )));
            }
            (other, _) => {
                return Err(StorageError::InvalidArgument(format!(
                    "unknown iterator mode: '{other}'"
                )));
            }
        };
        Ok(DbIterator {
            state: Mutex::new(IterState {
                db,
                cf: cf.to_string(),
                start,
                reverse,
                resume_after: None,
                exhausted: false,
            }),
        })
    }

    /// Bloom-filter/memtable probe: `false` means definitely absent, `true` means *maybe* present.
    pub fn key_may_exist(&self, cf: &str, key: &[u8]) -> StorageResult<bool> {
        let db = self.db()?;
        let handle = cf_handle(&db, cf)?;
        Ok(db.key_may_exist_cf(&handle, key))
    }

    /// A RocksDB property value (e.g. `"rocksdb.estimate-num-keys"`), or `None` if unknown.
    pub fn get_property(&self, cf: &str, name: &str) -> StorageResult<Option<String>> {
        let db = self.db()?;
        let handle = cf_handle(&db, cf)?;
        Ok(db.property_value_cf(&handle, name)?)
    }

    /// Names of the live column families (always includes `"default"`).
    pub fn list_cfs(&self) -> StorageResult<Vec<String>> {
        let guard = self.state.lock().expect("RocksDb mutex poisoned");
        match guard.as_ref() {
            Some(state) => Ok(state.cf_names.iter().cloned().collect()),
            None => Err(StorageError::Closed),
        }
    }

    /// Create a column family. Errors if it already exists.
    pub fn create_cf(&self, name: &str) -> StorageResult<()> {
        let mut guard = self.state.lock().expect("RocksDb mutex poisoned");
        let state = guard.as_mut().ok_or(StorageError::Closed)?;
        state.db.create_cf(name, &Options::default())?;
        state.cf_names.insert(name.to_string());
        Ok(())
    }

    /// Drop a column family and all of its data.
    pub fn drop_cf(&self, name: &str) -> StorageResult<()> {
        let mut guard = self.state.lock().expect("RocksDb mutex poisoned");
        let state = guard.as_mut().ok_or(StorageError::Closed)?;
        state.db.drop_cf(name)?;
        state.cf_names.remove(name);
        Ok(())
    }

    /// Flush all column families' memtables to SST files (frees WAL disk space).
    pub fn flush(&self) -> StorageResult<()> {
        let (db, names) = {
            let guard = self.state.lock().expect("RocksDb mutex poisoned");
            let state = guard.as_ref().ok_or(StorageError::Closed)?;
            let names: Vec<String> = state.cf_names.iter().cloned().collect();
            (Arc::clone(&state.db), names)
        };
        for name in &names {
            let handle = cf_handle(&db, name)?;
            db.flush_cf(&handle)?;
        }
        Ok(())
    }

    /// Release this handle. The DB actually closes when the last holder (e.g. a live
    /// iterator) drops. Subsequent calls on this object yield [`StorageError::Closed`];
    /// `close` itself is idempotent.
    pub fn close(&self) {
        let mut guard = self.state.lock().expect("RocksDb mutex poisoned");
        *guard = None;
    }
}

fn cf_handle<'db>(db: &'db Db, name: &str) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'db>>> {
    db.cf_handle(name)
        .ok_or_else(|| StorageError::UnknownColumnFamily(name.to_string()))
}

enum BatchOp {
    Put {
        cf: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        cf: String,
        key: Vec<u8>,
    },
}

/// Records a sequence of put/delete ops to apply atomically via [`RocksDb::write`].
///
/// Ops are materialized into a real `rocksdb::WriteBatch` inside `write`, keeping this object
/// independent of any DB handle/lifetime. Single-use: applying it consumes the recorded ops.
pub struct WriteBatch {
    ops: Mutex<Option<Vec<BatchOp>>>,
}

impl WriteBatch {
    pub fn new() -> Self {
        Self {
            ops: Mutex::new(Some(Vec::new())),
        }
    }

    pub fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> StorageResult<()> {
        let mut guard = self.ops.lock().expect("WriteBatch mutex poisoned");
        let ops = guard.as_mut().ok_or(StorageError::BatchConsumed)?;
        ops.push(BatchOp::Put {
            cf: cf.to_string(),
            key: key.to_vec(),
            value: value.to_vec(),
        });
        Ok(())
    }

    pub fn delete(&self, cf: &str, key: &[u8]) -> StorageResult<()> {
        let mut guard = self.ops.lock().expect("WriteBatch mutex poisoned");
        let ops = guard.as_mut().ok_or(StorageError::BatchConsumed)?;
        ops.push(BatchOp::Delete {
            cf: cf.to_string(),
            key: key.to_vec(),
        });
        Ok(())
    }

    pub fn len(&self) -> StorageResult<usize> {
        let guard = self.ops.lock().expect("WriteBatch mutex poisoned");
        match guard.as_ref() {
            Some(ops) => Ok(ops.len()),
            None => Err(StorageError::BatchConsumed),
        }
    }

    pub fn is_empty(&self) -> StorageResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Consume the recorded ops (a batch is single-use, like python-rocksdb's).
    fn take_ops(&self) -> StorageResult<Vec<BatchOp>> {
        let mut guard = self.ops.lock().expect("WriteBatch mutex poisoned");
        guard.take().ok_or(StorageError::BatchConsumed)
    }
}

impl Default for WriteBatch {
    fn default() -> Self {
        Self::new()
    }
}

enum IterStart {
    First,
    Last,
    Seek(Vec<u8>),
    SeekForPrev(Vec<u8>),
}

struct IterState {
    db: Arc<Db>,
    cf: String,
    start: IterStart,
    reverse: bool,
    /// The last key returned by the previous chunk; the next chunk resumes strictly after
    /// it (in scan direction).
    resume_after: Option<Vec<u8>>,
    exhausted: bool,
}

/// Chunked iterator: each `next_chunk(n)` call returns up to `n` `(key, value)` pairs, so an
/// index scan crossing the FFI boundary pays one round trip per chunk rather than per item.
///
/// Each chunk opens a fresh RocksDB iterator and re-seeks to the resume position (an
/// O(log n) seek per chunk, trivially amortized by the chunk size). Consequence: a chunk
/// observes writes that happened after the previous chunk — same contract as hathor-core's
/// usage, where scans run on the reactor thread between writes.
pub struct DbIterator {
    state: Mutex<IterState>,
}

impl DbIterator {
    /// Return up to `n` `(key, value)` pairs; an empty list means the scan is finished
    /// (exhaustion is sticky). `n` must be positive.
    pub fn next_chunk(&self, n: usize) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        if n == 0 {
            return Err(StorageError::InvalidArgument(
                "chunk size must be positive".to_string(),
            ));
        }
        let mut state = self.state.lock().expect("DbIterator mutex poisoned");
        if state.exhausted {
            return Ok(Vec::new());
        }
        // Scope the RocksDB iterator (which borrows `state.db`) so it drops before the
        // resume-position bookkeeping below mutates `state`.
        let items = {
            let handle = cf_handle(&state.db, &state.cf)?;
            let mut it = state.db.raw_iterator_cf(&handle);
            match (&state.resume_after, &state.start) {
                (Some(key), _) => {
                    // Resume strictly after the last returned key, in scan direction.
                    if state.reverse {
                        it.seek_for_prev(key);
                        if it.valid() && it.key() == Some(key.as_slice()) {
                            it.prev();
                        }
                    } else {
                        it.seek(key);
                        if it.valid() && it.key() == Some(key.as_slice()) {
                            it.next();
                        }
                    }
                }
                (None, IterStart::First) => it.seek_to_first(),
                (None, IterStart::Last) => it.seek_to_last(),
                (None, IterStart::Seek(key)) => it.seek(key),
                (None, IterStart::SeekForPrev(key)) => it.seek_for_prev(key),
            }
            let mut items = Vec::with_capacity(n);
            while items.len() < n && it.valid() {
                let key = it.key().expect("valid iterator must expose a key").to_vec();
                let value = it
                    .value()
                    .expect("valid iterator must expose a value")
                    .to_vec();
                items.push((key, value));
                if state.reverse {
                    it.prev();
                } else {
                    it.next();
                }
            }
            it.status()?;
            items
        };
        match items.last() {
            Some((key, _)) if items.len() == n => {
                state.resume_after = Some(key.clone());
            }
            _ => {
                state.exhausted = true;
            }
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests;
