//! Bytes-only RocksDB storage layer shared by Python and Rust consumers.
//!
//! Python sees three pyclasses — [`RocksDb`], [`RocksDbWriteBatch`] and [`RocksDbIterator`] —
//! that mirror the operation surface hathor-core uses through python-rocksdb (see
//! `plans/rust-rocksdb-storage.md` for the inventory): point reads/writes, atomic write
//! batches, seekable iterators, `key_may_exist`, properties and column-family management.
//! Values cross the FFI as raw bytes; no parsing or serialization happens here.
//!
//! Rust consumers (the batch-verification pipeline) share the same primary handle via
//! [`RocksDb::native`], reading vertex bytes without the GIL.
//!
//! The GIL is released around every RocksDB call (`Python::detach`), so reads and writes
//! issued from Python worker threads overlap with reactor work.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use rocksdb::{DBWithThreadMode, MultiThreaded, Options, WriteBatch};

/// Multi-threaded mode: `create_cf`/`drop_cf` take `&self`, and column-family handles are
/// resolved by name per call, so Python never holds raw CF pointers across the FFI.
pub type Db = DBWithThreadMode<MultiThreaded>;

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

fn io_err(error: rocksdb::Error) -> PyErr {
    PyIOError::new_err(error.to_string())
}

/// Shared state behind the pyclass: the DB handle plus the live column-family name set
/// (RocksDB has no "list live CFs on an open DB" call, so the set is maintained here:
/// initialized from `list_cf` at open, updated by `create_cf`/`drop_cf`).
struct DbState {
    db: Arc<Db>,
    cf_names: BTreeSet<String>,
}

#[pyclass(frozen)]
pub struct RocksDb {
    /// `None` after `close()`. Iterators hold their own `Arc<Db>`, so the underlying DB
    /// closes when the last holder drops.
    state: Mutex<Option<DbState>>,
}

impl RocksDb {
    /// Clone the handle out of the mutex (so RocksDB calls run without holding it).
    fn db(&self) -> PyResult<Arc<Db>> {
        let guard = self.state.lock().expect("RocksDb mutex poisoned");
        match guard.as_ref() {
            Some(state) => Ok(Arc::clone(&state.db)),
            None => Err(PyValueError::new_err("database is closed")),
        }
    }

    /// Access the shared handle from Rust code (no GIL involved).
    pub fn native(&self) -> Option<Arc<Db>> {
        let guard = self.state.lock().expect("RocksDb mutex poisoned");
        guard.as_ref().map(|state| Arc::clone(&state.db))
    }
}

#[pymethods]
impl RocksDb {
    /// Open (or create) the database at `path`, mirroring `hathor/storage/rocksdb_storage.py`:
    /// list the existing column families and open them all; when the DB does not exist yet,
    /// python-rocksdb creates it via `repair_db`, replicated here (with `create_if_missing`
    /// as a strictly-more-robust fallback if repair itself fails on the empty directory).
    #[new]
    #[pyo3(signature = (path, cache_capacity=None))]
    pub(crate) fn new(
        py: Python<'_>,
        path: String,
        cache_capacity: Option<usize>,
    ) -> PyResult<Self> {
        let state = py.detach(|| -> Result<DbState, rocksdb::Error> {
            let opts = build_options(cache_capacity);
            let cf_names = match Db::list_cf(&opts, &path) {
                Ok(names) => names,
                Err(_) => {
                    // The DB does not exist: a repair creates an empty one.
                    let _ = Db::repair(&opts, &path);
                    Db::list_cf(&opts, &path).unwrap_or_default()
                }
            };
            let mut open_opts = opts.clone();
            open_opts.create_if_missing(true);
            let descriptors = cf_names
                .iter()
                .map(|name| rocksdb::ColumnFamilyDescriptor::new(name, Options::default()));
            let db = Db::open_cf_descriptors(&open_opts, &path, descriptors)?;
            let mut names: BTreeSet<String> = cf_names.into_iter().collect();
            names.insert("default".to_string());
            Ok(DbState {
                db: Arc::new(db),
                cf_names: names,
            })
        });
        let state = state.map_err(io_err)?;
        Ok(Self {
            state: Mutex::new(Some(state)),
        })
    }

    /// Point read; `None` when the key is absent.
    fn get(&self, py: Python<'_>, cf: &str, key: Vec<u8>) -> PyResult<Option<Vec<u8>>> {
        let db = self.db()?;
        py.detach(|| {
            let handle = cf_handle(&db, cf)?;
            db.get_cf(&handle, key).map_err(io_err)
        })
    }

    /// Batched point reads, in input order; `None` per absent key.
    fn multi_get(
        &self,
        py: Python<'_>,
        cf: &str,
        keys: Vec<Vec<u8>>,
    ) -> PyResult<Vec<Option<Vec<u8>>>> {
        let db = self.db()?;
        py.detach(|| {
            let handle = cf_handle(&db, cf)?;
            let results = db.multi_get_cf(keys.iter().map(|key| (&handle, key)));
            results
                .into_iter()
                .map(|result| result.map_err(io_err))
                .collect()
        })
    }

    fn put(&self, py: Python<'_>, cf: &str, key: Vec<u8>, value: Vec<u8>) -> PyResult<()> {
        let db = self.db()?;
        py.detach(|| {
            let handle = cf_handle(&db, cf)?;
            db.put_cf(&handle, key, value).map_err(io_err)
        })
    }

    fn delete(&self, py: Python<'_>, cf: &str, key: Vec<u8>) -> PyResult<()> {
        let db = self.db()?;
        py.detach(|| {
            let handle = cf_handle(&db, cf)?;
            db.delete_cf(&handle, key).map_err(io_err)
        })
    }

    /// Apply a write batch atomically (all column families, all ops, one WAL write).
    pub(crate) fn write(&self, py: Python<'_>, batch: &RocksDbWriteBatch) -> PyResult<()> {
        let db = self.db()?;
        let ops = batch.take_ops()?;
        py.detach(|| {
            let mut wb = WriteBatch::default();
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
            db.write(wb).map_err(io_err)
        })
    }

    /// Open a chunked iterator over `cf`. `mode` is one of `'first'`, `'last'`, `'seek'`,
    /// `'seek_for_prev'` (the latter two require `key`); `reverse` sets the scan direction
    /// after the initial position.
    #[pyo3(signature = (cf, *, mode, key=None, reverse=false))]
    fn iterator(
        &self,
        cf: &str,
        mode: &str,
        key: Option<Vec<u8>>,
        reverse: bool,
    ) -> PyResult<RocksDbIterator> {
        let db = self.db()?;
        // Fail fast on a bad CF name so the error surfaces at open, like python-rocksdb.
        cf_handle(&db, cf)?;
        let start = match (mode, key) {
            ("first", None) => IterStart::First,
            ("last", None) => IterStart::Last,
            ("seek", Some(key)) => IterStart::Seek(key),
            ("seek_for_prev", Some(key)) => IterStart::SeekForPrev(key),
            ("seek" | "seek_for_prev", None) => {
                return Err(PyValueError::new_err(format!(
                    "mode '{mode}' requires a key"
                )));
            }
            ("first" | "last", Some(_)) => {
                return Err(PyValueError::new_err(format!(
                    "mode '{mode}' does not take a key"
                )));
            }
            (other, _) => {
                return Err(PyValueError::new_err(format!(
                    "unknown iterator mode: '{other}'"
                )));
            }
        };
        Ok(RocksDbIterator {
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
    fn key_may_exist(&self, py: Python<'_>, cf: &str, key: Vec<u8>) -> PyResult<bool> {
        let db = self.db()?;
        py.detach(|| {
            let handle = cf_handle(&db, cf)?;
            Ok(db.key_may_exist_cf(&handle, key))
        })
    }

    /// A RocksDB property value (e.g. `'rocksdb.estimate-num-keys'`), or `None` if unknown.
    fn get_property(&self, py: Python<'_>, cf: &str, name: &str) -> PyResult<Option<String>> {
        let db = self.db()?;
        py.detach(|| {
            let handle = cf_handle(&db, cf)?;
            db.property_value_cf(&handle, name).map_err(io_err)
        })
    }

    /// Names of the live column families (always includes `'default'`).
    fn list_cfs(&self) -> PyResult<Vec<String>> {
        let guard = self.state.lock().expect("RocksDb mutex poisoned");
        match guard.as_ref() {
            Some(state) => Ok(state.cf_names.iter().cloned().collect()),
            None => Err(PyValueError::new_err("database is closed")),
        }
    }

    /// Create a column family. Errors if it already exists.
    pub(crate) fn create_cf(&self, py: Python<'_>, name: &str) -> PyResult<()> {
        let mut guard = self.state.lock().expect("RocksDb mutex poisoned");
        let state = guard
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("database is closed"))?;
        let db = Arc::clone(&state.db);
        py.detach(|| db.create_cf(name, &Options::default()).map_err(io_err))?;
        state.cf_names.insert(name.to_string());
        Ok(())
    }

    /// Drop a column family and all of its data.
    fn drop_cf(&self, py: Python<'_>, name: &str) -> PyResult<()> {
        let mut guard = self.state.lock().expect("RocksDb mutex poisoned");
        let state = guard
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("database is closed"))?;
        let db = Arc::clone(&state.db);
        py.detach(|| db.drop_cf(name).map_err(io_err))?;
        state.cf_names.remove(name);
        Ok(())
    }

    /// Flush all column families' memtables to SST files (frees WAL disk space).
    fn flush(&self, py: Python<'_>) -> PyResult<()> {
        let guard = self.state.lock().expect("RocksDb mutex poisoned");
        let state = guard
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("database is closed"))?;
        let db = Arc::clone(&state.db);
        let names: Vec<String> = state.cf_names.iter().cloned().collect();
        drop(guard);
        py.detach(|| {
            for name in &names {
                let handle = cf_handle(&db, name)?;
                db.flush_cf(&handle).map_err(io_err)?;
            }
            Ok(())
        })
    }

    /// Release this handle. The DB actually closes when the last holder (e.g. a live
    /// iterator) drops. Subsequent calls on this object raise ValueError.
    fn close(&self) {
        let mut guard = self.state.lock().expect("RocksDb mutex poisoned");
        *guard = None;
    }
}

fn cf_handle<'db>(db: &'db Db, name: &str) -> PyResult<Arc<rocksdb::BoundColumnFamily<'db>>> {
    db.cf_handle(name)
        .ok_or_else(|| PyValueError::new_err(format!("unknown column family: '{name}'")))
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

/// Ops are recorded here and materialized into a real `rocksdb::WriteBatch` inside
/// `RocksDb.write`, keeping this object independent of any DB handle/lifetime.
#[pyclass(frozen)]
pub struct RocksDbWriteBatch {
    ops: Mutex<Option<Vec<BatchOp>>>,
}

impl RocksDbWriteBatch {
    /// Consume the recorded ops (a batch is single-use, like python-rocksdb's).
    fn take_ops(&self) -> PyResult<Vec<BatchOp>> {
        let mut guard = self.ops.lock().expect("RocksDbWriteBatch mutex poisoned");
        guard
            .take()
            .ok_or_else(|| PyValueError::new_err("write batch already consumed"))
    }
}

#[pymethods]
impl RocksDbWriteBatch {
    #[new]
    pub(crate) fn new() -> Self {
        Self {
            ops: Mutex::new(Some(Vec::new())),
        }
    }

    pub(crate) fn put(&self, cf: &str, key: Vec<u8>, value: Vec<u8>) -> PyResult<()> {
        let mut guard = self.ops.lock().expect("RocksDbWriteBatch mutex poisoned");
        let ops = guard
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("write batch already consumed"))?;
        ops.push(BatchOp::Put {
            cf: cf.to_string(),
            key,
            value,
        });
        Ok(())
    }

    fn delete(&self, cf: &str, key: Vec<u8>) -> PyResult<()> {
        let mut guard = self.ops.lock().expect("RocksDbWriteBatch mutex poisoned");
        let ops = guard
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("write batch already consumed"))?;
        ops.push(BatchOp::Delete {
            cf: cf.to_string(),
            key,
        });
        Ok(())
    }

    fn len(&self) -> PyResult<usize> {
        let guard = self.ops.lock().expect("RocksDbWriteBatch mutex poisoned");
        match guard.as_ref() {
            Some(ops) => Ok(ops.len()),
            None => Err(PyValueError::new_err("write batch already consumed")),
        }
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

/// Chunked iterator: each `next_chunk(n)` call is one FFI crossing returning up to `n`
/// `(key, value)` pairs, so index scans don't pay a Python round trip per item.
///
/// Each chunk opens a fresh RocksDB iterator and re-seeks to the resume position
/// (an O(log n) seek per chunk, trivially amortized by the chunk size). Consequence: a
/// chunk observes writes that happened after the previous chunk — same contract as
/// hathor-core's usage, where scans run on the reactor thread between writes.
#[pyclass(frozen)]
pub struct RocksDbIterator {
    state: Mutex<IterState>,
}

#[pymethods]
impl RocksDbIterator {
    /// Return up to `n` `(key, value)` pairs; an empty list means the scan is finished.
    fn next_chunk(&self, py: Python<'_>, n: usize) -> PyResult<Vec<(Vec<u8>, Vec<u8>)>> {
        if n == 0 {
            return Err(PyValueError::new_err("chunk size must be positive"));
        }
        let mut state = self.state.lock().expect("RocksDbIterator mutex poisoned");
        if state.exhausted {
            return Ok(Vec::new());
        }
        let items = py.detach(|| -> PyResult<Vec<(Vec<u8>, Vec<u8>)>> {
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
            it.status().map_err(io_err)?;
            Ok(items)
        })?;
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
