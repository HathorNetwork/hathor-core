//! Wrapper-level tests: the pure storage behavior is covered in `htr-lib`, so these only
//! pin the binding glue — that calls route through the pyclasses under a GIL token, and that
//! a [`StorageError`](htr_lib::storage::StorageError) surfaces as the right Python exception
//! type and message.

use pyo3::prelude::*;

use super::*;

fn with_db<F: FnOnce(Python<'_>, &PyRocksDb)>(f: F) {
    Python::initialize();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db").to_str().unwrap().to_string();
    Python::attach(|py| {
        let db = PyRocksDb::new(py, path, None).unwrap();
        f(py, &db);
    });
}

#[test]
fn test_roundtrip_through_pyclass() {
    with_db(|py, db| {
        assert_eq!(db.get(py, "default", b"k".to_vec()).unwrap(), None);
        db.put(py, "default", b"k".to_vec(), b"v".to_vec()).unwrap();
        assert_eq!(
            db.get(py, "default", b"k".to_vec()).unwrap(),
            Some(b"v".to_vec())
        );
    });
}

#[test]
fn test_write_batch_and_iterator_through_pyclass() {
    with_db(|py, db| {
        let batch = PyRocksDbWriteBatch::new();
        batch.put("default", b"a".to_vec(), b"1".to_vec()).unwrap();
        batch.put("default", b"b".to_vec(), b"2".to_vec()).unwrap();
        assert_eq!(batch.len().unwrap(), 2);
        db.write(py, &batch).unwrap();

        let it = db.iterator("default", "first", None, false).unwrap();
        let items = it.next_chunk(py, 8).unwrap();
        assert_eq!(
            items,
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"2".to_vec()),
            ]
        );
        // Exhaustion is sticky.
        assert_eq!(it.next_chunk(py, 8).unwrap(), Vec::new());
    });
}

#[test]
fn test_unknown_cf_raises_value_error() {
    with_db(|py, db| {
        let err = db.get(py, "nope", b"k".to_vec()).unwrap_err();
        assert_eq!(err.to_string(), "ValueError: unknown column family: 'nope'");
    });
}

#[test]
fn test_consumed_batch_raises_value_error() {
    with_db(|py, db| {
        let batch = PyRocksDbWriteBatch::new();
        batch.put("default", b"a".to_vec(), b"1".to_vec()).unwrap();
        db.write(py, &batch).unwrap();
        let err = db.write(py, &batch).unwrap_err();
        assert_eq!(err.to_string(), "ValueError: write batch already consumed");
    });
}

#[test]
fn test_closed_db_raises_value_error() {
    with_db(|py, db| {
        db.close();
        let err = db.get(py, "default", b"k".to_vec()).unwrap_err();
        assert_eq!(err.to_string(), "ValueError: database is closed");
        let err = db.list_cfs().unwrap_err();
        assert_eq!(err.to_string(), "ValueError: database is closed");
    });
}

#[test]
fn test_invalid_iterator_mode_raises_value_error() {
    with_db(|py, db| {
        let _ = py;
        let err = db
            .iterator("default", "seek", None, false)
            .err()
            .expect("must fail");
        assert_eq!(err.to_string(), "ValueError: mode 'seek' requires a key");
    });
}
