//! Tests drive the pyclasses through their Rust methods (Python::attach supplies the token),
//! covering the full op surface inventoried in `plans/rust-rocksdb-storage.md`.

use pyo3::prelude::*;

use super::*;

fn with_db<F: FnOnce(Python<'_>, &RocksDb)>(f: F) {
    Python::initialize();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db").to_str().unwrap().to_string();
    Python::attach(|py| {
        let db = RocksDb::new(py, path, None).unwrap();
        f(py, &db);
    });
}

fn keys_of(items: &[(Vec<u8>, Vec<u8>)]) -> Vec<&[u8]> {
    items.iter().map(|(key, _)| key.as_slice()).collect()
}

/// Drain an iterator with the given chunk size, asserting chunk-size invariants.
fn drain(py: Python<'_>, it: &RocksDbIterator, chunk: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut all = Vec::new();
    loop {
        let items = it.next_chunk(py, chunk).unwrap();
        if items.is_empty() {
            // Exhaustion is sticky.
            assert_eq!(it.next_chunk(py, chunk).unwrap(), Vec::new());
            return all;
        }
        assert!(items.len() <= chunk);
        all.extend(items);
    }
}

#[test]
fn test_open_creates_missing_db() {
    with_db(|_py, db| {
        assert_eq!(db.list_cfs().unwrap(), vec!["default".to_string()]);
    });
}

#[test]
fn test_put_get_delete_roundtrip() {
    with_db(|py, db| {
        assert_eq!(db.get(py, "default", b"k".to_vec()).unwrap(), None);
        db.put(py, "default", b"k".to_vec(), b"v".to_vec()).unwrap();
        assert_eq!(
            db.get(py, "default", b"k".to_vec()).unwrap(),
            Some(b"v".to_vec())
        );
        db.delete(py, "default", b"k".to_vec()).unwrap();
        assert_eq!(db.get(py, "default", b"k".to_vec()).unwrap(), None);
    });
}

#[test]
fn test_multi_get_preserves_order_and_misses() {
    with_db(|py, db| {
        db.put(py, "default", b"a".to_vec(), b"1".to_vec()).unwrap();
        db.put(py, "default", b"c".to_vec(), b"3".to_vec()).unwrap();
        let results = db
            .multi_get(
                py,
                "default",
                vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            )
            .unwrap();
        assert_eq!(
            results,
            vec![Some(b"1".to_vec()), None, Some(b"3".to_vec())]
        );
    });
}

#[test]
fn test_column_family_lifecycle() {
    with_db(|py, db| {
        db.create_cf(py, "tx").unwrap();
        db.create_cf(py, "meta").unwrap();
        assert_eq!(
            db.list_cfs().unwrap(),
            vec!["default".to_string(), "meta".to_string(), "tx".to_string()]
        );
        // Same key, different CFs, independent values.
        db.put(py, "tx", b"k".to_vec(), b"tx-v".to_vec()).unwrap();
        db.put(py, "meta", b"k".to_vec(), b"meta-v".to_vec())
            .unwrap();
        assert_eq!(
            db.get(py, "tx", b"k".to_vec()).unwrap(),
            Some(b"tx-v".to_vec())
        );
        assert_eq!(
            db.get(py, "meta", b"k".to_vec()).unwrap(),
            Some(b"meta-v".to_vec())
        );

        db.drop_cf(py, "meta").unwrap();
        assert_eq!(
            db.list_cfs().unwrap(),
            vec!["default".to_string(), "tx".to_string()]
        );
        let err = db.get(py, "meta", b"k".to_vec()).unwrap_err();
        assert_eq!(err.to_string(), "ValueError: unknown column family: 'meta'");
    });
}

#[test]
fn test_unknown_cf_errors() {
    with_db(|py, db| {
        let err = db.get(py, "nope", b"k".to_vec()).unwrap_err();
        assert_eq!(err.to_string(), "ValueError: unknown column family: 'nope'");
    });
}

#[test]
fn test_write_batch_atomic_multi_cf() {
    with_db(|py, db| {
        db.create_cf(py, "tx").unwrap();
        db.put(py, "default", b"stale".to_vec(), b"x".to_vec())
            .unwrap();

        let batch = RocksDbWriteBatch::new();
        batch.put("default", b"a".to_vec(), b"1".to_vec()).unwrap();
        batch.put("tx", b"b".to_vec(), b"2".to_vec()).unwrap();
        batch.delete("default", b"stale".to_vec()).unwrap();
        assert_eq!(batch.len().unwrap(), 3);
        db.write(py, &batch).unwrap();

        assert_eq!(
            db.get(py, "default", b"a".to_vec()).unwrap(),
            Some(b"1".to_vec())
        );
        assert_eq!(
            db.get(py, "tx", b"b".to_vec()).unwrap(),
            Some(b"2".to_vec())
        );
        assert_eq!(db.get(py, "default", b"stale".to_vec()).unwrap(), None);

        // A batch is single-use.
        let err = db.write(py, &batch).unwrap_err();
        assert_eq!(err.to_string(), "ValueError: write batch already consumed");
    });
}

#[test]
fn test_write_batch_unknown_cf_applies_nothing() {
    with_db(|py, db| {
        let batch = RocksDbWriteBatch::new();
        batch.put("default", b"a".to_vec(), b"1".to_vec()).unwrap();
        batch.put("nope", b"b".to_vec(), b"2".to_vec()).unwrap();
        let err = db.write(py, &batch).unwrap_err();
        assert_eq!(err.to_string(), "ValueError: unknown column family: 'nope'");
        // Atomicity: the valid op must not have been applied.
        assert_eq!(db.get(py, "default", b"a".to_vec()).unwrap(), None);
    });
}

fn populate(py: Python<'_>, db: &RocksDb) {
    for i in 0..10u8 {
        let key = vec![i];
        let value = vec![i, i];
        db.put(py, "default", key, value).unwrap();
    }
}

#[test]
fn test_iterator_forward_chunked() {
    with_db(|py, db| {
        populate(py, db);
        // Chunk size smaller than, equal to, and larger than the total.
        for chunk in [3, 10, 64] {
            let it = db.iterator("default", "first", None, false).unwrap();
            let items = drain(py, &it, chunk);
            let keys: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i]).collect();
            assert_eq!(
                keys_of(&items),
                keys.iter().map(|k| k.as_slice()).collect::<Vec<_>>()
            );
            assert_eq!(items[4].1, vec![4, 4]);
        }
    });
}

#[test]
fn test_iterator_reverse_chunked() {
    with_db(|py, db| {
        populate(py, db);
        let it = db.iterator("default", "last", None, true).unwrap();
        let items = drain(py, &it, 4);
        let keys: Vec<Vec<u8>> = (0..10u8).rev().map(|i| vec![i]).collect();
        assert_eq!(
            keys_of(&items),
            keys.iter().map(|k| k.as_slice()).collect::<Vec<_>>()
        );
    });
}

#[test]
fn test_iterator_seek_forward() {
    with_db(|py, db| {
        populate(py, db);
        let it = db
            .iterator("default", "seek", Some(vec![7]), false)
            .unwrap();
        let items = drain(py, &it, 2);
        assert_eq!(keys_of(&items), vec![&[7][..], &[8][..], &[9][..]]);
    });
}

#[test]
fn test_iterator_seek_lands_on_next_key_when_absent() {
    with_db(|py, db| {
        populate(py, db);
        db.delete(py, "default", vec![7]).unwrap();
        let it = db
            .iterator("default", "seek", Some(vec![7]), false)
            .unwrap();
        let items = drain(py, &it, 64);
        assert_eq!(keys_of(&items), vec![&[8][..], &[9][..]]);
    });
}

#[test]
fn test_iterator_seek_for_prev_reverse() {
    with_db(|py, db| {
        populate(py, db);
        // seek_for_prev on an absent key positions at the greatest key <= target.
        let it = db
            .iterator("default", "seek_for_prev", Some(vec![6, 0]), true)
            .unwrap();
        let items = drain(py, &it, 3);
        let keys: Vec<Vec<u8>> = (0..=6u8).rev().map(|i| vec![i]).collect();
        assert_eq!(
            keys_of(&items),
            keys.iter().map(|k| k.as_slice()).collect::<Vec<_>>()
        );
    });
}

#[test]
fn test_iterator_empty_cf() {
    with_db(|py, db| {
        db.create_cf(py, "empty").unwrap();
        let it = db.iterator("empty", "first", None, false).unwrap();
        assert_eq!(it.next_chunk(py, 8).unwrap(), Vec::new());
    });
}

#[test]
fn test_iterator_mode_validation() {
    with_db(|py, db| {
        let _ = py;
        let err = db
            .iterator("default", "seek", None, false)
            .err()
            .expect("must fail");
        assert_eq!(err.to_string(), "ValueError: mode 'seek' requires a key");
        let err = db
            .iterator("default", "first", Some(vec![1]), false)
            .err()
            .expect("must fail");
        assert_eq!(
            err.to_string(),
            "ValueError: mode 'first' does not take a key"
        );
        let err = db
            .iterator("default", "bogus", None, false)
            .err()
            .expect("must fail");
        assert_eq!(
            err.to_string(),
            "ValueError: unknown iterator mode: 'bogus'"
        );
        let err = db
            .iterator("nope", "first", None, false)
            .err()
            .expect("must fail");
        assert_eq!(err.to_string(), "ValueError: unknown column family: 'nope'");
    });
}

#[test]
fn test_key_may_exist() {
    with_db(|py, db| {
        db.put(py, "default", b"present".to_vec(), b"v".to_vec())
            .unwrap();
        // True for a present key; false negatives are impossible by contract.
        assert!(
            db.key_may_exist(py, "default", b"present".to_vec())
                .unwrap()
        );
    });
}

#[test]
fn test_get_property() {
    with_db(|py, db| {
        let value = db
            .get_property(py, "default", "rocksdb.estimate-num-keys")
            .unwrap();
        assert_eq!(value, Some("0".to_string()));
        let missing = db
            .get_property(py, "default", "rocksdb.not-a-property")
            .unwrap();
        assert_eq!(missing, None);
    });
}

#[test]
fn test_flush() {
    with_db(|py, db| {
        db.create_cf(py, "tx").unwrap();
        db.put(py, "tx", b"k".to_vec(), b"v".to_vec()).unwrap();
        db.flush(py).unwrap();
        assert_eq!(
            db.get(py, "tx", b"k".to_vec()).unwrap(),
            Some(b"v".to_vec())
        );
    });
}

#[test]
fn test_close_then_use_errors() {
    with_db(|py, db| {
        db.close();
        let err = db.get(py, "default", b"k".to_vec()).unwrap_err();
        assert_eq!(err.to_string(), "ValueError: database is closed");
        let err = db.list_cfs().unwrap_err();
        assert_eq!(err.to_string(), "ValueError: database is closed");
        // close() is idempotent.
        db.close();
    });
}

#[test]
fn test_reopen_persists_data_and_cfs() {
    Python::initialize();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db").to_str().unwrap().to_string();
    Python::attach(|py| {
        let db = RocksDb::new(py, path.clone(), None).unwrap();
        db.create_cf(py, "tx").unwrap();
        db.put(py, "tx", b"k".to_vec(), b"v".to_vec()).unwrap();
        db.put(py, "default", b"d".to_vec(), b"w".to_vec()).unwrap();
        db.close();

        let db = RocksDb::new(py, path.clone(), Some(1 << 20)).unwrap();
        assert_eq!(
            db.list_cfs().unwrap(),
            vec!["default".to_string(), "tx".to_string()]
        );
        assert_eq!(
            db.get(py, "tx", b"k".to_vec()).unwrap(),
            Some(b"v".to_vec())
        );
        assert_eq!(
            db.get(py, "default", b"d".to_vec()).unwrap(),
            Some(b"w".to_vec())
        );
    });
}

#[test]
fn test_native_handle_shares_writes() {
    with_db(|py, db| {
        db.put(py, "default", b"k".to_vec(), b"v".to_vec()).unwrap();
        // The Rust-native path sees Python-side writes through the same primary handle.
        let native = db.native().expect("db is open");
        let handle = native
            .cf_handle("default")
            .expect("default CF always exists");
        let value = native.get_cf(&handle, b"k").unwrap();
        assert_eq!(value, Some(b"v".to_vec()));
        db.close();
        assert!(db.native().is_none());
    });
}
