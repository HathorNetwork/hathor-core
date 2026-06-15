//! PyO3 wrappers over the pure-Rust storage layer in `htr-lib`.
//!
//! Python sees three pyclasses — [`PyRocksDb`], [`PyRocksDbWriteBatch`] and
//! [`PyRocksDbIterator`] (exported as `RocksDb`, `RocksDbWriteBatch`, `RocksDbIterator`) —
//! that mirror the operation surface hathor-core uses through python-rocksdb. Each wrapper is
//! thin: it releases the GIL around the underlying call (`Python::detach`) so reads and writes
//! issued from Python worker threads overlap with reactor work, and translates
//! [`StorageError`] into the Python exception type the caller expects (I/O failures raise
//! `IOError`; everything else raises `ValueError`). Values cross the FFI as raw bytes.

use htr_lib::storage::{DbIterator, RocksDb, StorageError, WriteBatch};
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;

/// Map a storage error onto the Python exception type hathor-core relied on under
/// python-rocksdb: I/O failures become `IOError`, every other failure becomes `ValueError`.
fn to_pyerr(error: StorageError) -> PyErr {
    let message = error.to_string();
    match error {
        StorageError::Io(_) => PyIOError::new_err(message),
        _ => PyValueError::new_err(message),
    }
}

/// Bytes-only handle over the primary RocksDB database (see `plans/rust-rocksdb-storage.md`).
///
/// All methods release the GIL around the underlying RocksDB call. Column families are
/// addressed by name; unknown names raise ValueError, I/O failures raise IOError, and any
/// use after `close()` raises ValueError.
#[pyclass(name = "RocksDb", frozen)]
pub struct PyRocksDb(RocksDb);

#[pymethods]
impl PyRocksDb {
    #[new]
    #[pyo3(signature = (path, cache_capacity=None))]
    fn new(py: Python<'_>, path: String, cache_capacity: Option<usize>) -> PyResult<Self> {
        let db = py.detach(|| RocksDb::open(&path, cache_capacity).map_err(to_pyerr))?;
        Ok(Self(db))
    }

    /// Point read; `None` when the key is absent.
    fn get(&self, py: Python<'_>, cf: &str, key: Vec<u8>) -> PyResult<Option<Vec<u8>>> {
        py.detach(|| self.0.get(cf, &key).map_err(to_pyerr))
    }

    /// Batched point reads, in input order; `None` per absent key.
    fn multi_get(
        &self,
        py: Python<'_>,
        cf: &str,
        keys: Vec<Vec<u8>>,
    ) -> PyResult<Vec<Option<Vec<u8>>>> {
        py.detach(|| self.0.multi_get(cf, &keys).map_err(to_pyerr))
    }

    fn put(&self, py: Python<'_>, cf: &str, key: Vec<u8>, value: Vec<u8>) -> PyResult<()> {
        py.detach(|| self.0.put(cf, &key, &value).map_err(to_pyerr))
    }

    fn delete(&self, py: Python<'_>, cf: &str, key: Vec<u8>) -> PyResult<()> {
        py.detach(|| self.0.delete(cf, &key).map_err(to_pyerr))
    }

    /// Apply a write batch atomically (all column families, all ops, one WAL write).
    fn write(&self, py: Python<'_>, batch: &PyRocksDbWriteBatch) -> PyResult<()> {
        let inner = &batch.0;
        py.detach(|| self.0.write(inner).map_err(to_pyerr))
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
    ) -> PyResult<PyRocksDbIterator> {
        let iterator = self.0.iterator(cf, mode, key, reverse).map_err(to_pyerr)?;
        Ok(PyRocksDbIterator(iterator))
    }

    /// Bloom-filter/memtable probe: `false` means definitely absent, `true` means *maybe* present.
    fn key_may_exist(&self, py: Python<'_>, cf: &str, key: Vec<u8>) -> PyResult<bool> {
        py.detach(|| self.0.key_may_exist(cf, &key).map_err(to_pyerr))
    }

    /// A RocksDB property value (e.g. `'rocksdb.estimate-num-keys'`), or `None` if unknown.
    fn get_property(&self, py: Python<'_>, cf: &str, name: &str) -> PyResult<Option<String>> {
        py.detach(|| self.0.get_property(cf, name).map_err(to_pyerr))
    }

    /// Names of the live column families (always includes `'default'`).
    fn list_cfs(&self) -> PyResult<Vec<String>> {
        self.0.list_cfs().map_err(to_pyerr)
    }

    /// Create a column family. Errors if it already exists.
    fn create_cf(&self, py: Python<'_>, name: &str) -> PyResult<()> {
        py.detach(|| self.0.create_cf(name).map_err(to_pyerr))
    }

    /// Drop a column family and all of its data.
    fn drop_cf(&self, py: Python<'_>, name: &str) -> PyResult<()> {
        py.detach(|| self.0.drop_cf(name).map_err(to_pyerr))
    }

    /// Flush all column families' memtables to SST files (frees WAL disk space).
    fn flush(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.0.flush().map_err(to_pyerr))
    }

    /// Release this handle. The DB actually closes when the last holder (e.g. a live
    /// iterator) drops. Subsequent calls on this object raise ValueError.
    fn close(&self) {
        self.0.close();
    }
}

/// Atomic write batch for `RocksDb.write`. Single-use: consumed by `write`.
#[pyclass(name = "RocksDbWriteBatch", frozen)]
pub struct PyRocksDbWriteBatch(WriteBatch);

#[pymethods]
impl PyRocksDbWriteBatch {
    #[new]
    fn new() -> Self {
        Self(WriteBatch::new())
    }

    fn put(&self, cf: &str, key: Vec<u8>, value: Vec<u8>) -> PyResult<()> {
        self.0.put(cf, &key, &value).map_err(to_pyerr)
    }

    fn delete(&self, cf: &str, key: Vec<u8>) -> PyResult<()> {
        self.0.delete(cf, &key).map_err(to_pyerr)
    }

    fn len(&self) -> PyResult<usize> {
        self.0.len().map_err(to_pyerr)
    }
}

/// Chunked column-family scan: one FFI call per chunk, not per item.
#[pyclass(name = "RocksDbIterator", frozen)]
pub struct PyRocksDbIterator(DbIterator);

#[pymethods]
impl PyRocksDbIterator {
    /// Return up to `n` `(key, value)` pairs; an empty list means exhausted (sticky).
    fn next_chunk(&self, py: Python<'_>, n: usize) -> PyResult<Vec<(Vec<u8>, Vec<u8>)>> {
        py.detach(|| self.0.next_chunk(n).map_err(to_pyerr))
    }
}

#[cfg(test)]
mod tests;
