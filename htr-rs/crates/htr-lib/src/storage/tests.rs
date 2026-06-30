//! Exercises the pure storage API, covering the full op surface inventoried in
//! `plans/rust-rocksdb-storage.md`. The PyO3 wrapper is tested separately in `htr-lib-py`.

use super::*;

fn with_db<F: FnOnce(&RocksDb)>(f: F) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db").to_str().unwrap().to_string();
    let db = RocksDb::open(&path, None).unwrap();
    f(&db);
}

fn keys_of(items: &[(Vec<u8>, Vec<u8>)]) -> Vec<&[u8]> {
    items.iter().map(|(key, _)| key.as_slice()).collect()
}

/// Drain an iterator with the given chunk size, asserting chunk-size invariants.
fn drain(it: &DbIterator, chunk: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut all = Vec::new();
    loop {
        let items = it.next_chunk(chunk).unwrap();
        if items.is_empty() {
            // Exhaustion is sticky.
            assert_eq!(it.next_chunk(chunk).unwrap(), Vec::new());
            return all;
        }
        assert!(items.len() <= chunk);
        all.extend(items);
    }
}

#[test]
fn test_open_creates_missing_db() {
    with_db(|db| {
        assert_eq!(db.list_cfs().unwrap(), vec!["default".to_string()]);
    });
}

#[test]
fn test_put_get_delete_roundtrip() {
    with_db(|db| {
        assert_eq!(db.get("default", b"k").unwrap(), None);
        db.put("default", b"k", b"v").unwrap();
        assert_eq!(db.get("default", b"k").unwrap(), Some(b"v".to_vec()));
        db.delete("default", b"k").unwrap();
        assert_eq!(db.get("default", b"k").unwrap(), None);
    });
}

#[test]
fn test_multi_get_preserves_order_and_misses() {
    with_db(|db| {
        db.put("default", b"a", b"1").unwrap();
        db.put("default", b"c", b"3").unwrap();
        let keys = [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let results = db.multi_get("default", &keys).unwrap();
        assert_eq!(
            results,
            vec![Some(b"1".to_vec()), None, Some(b"3".to_vec())]
        );
    });
}

#[test]
fn test_column_family_lifecycle() {
    with_db(|db| {
        db.create_cf("tx").unwrap();
        db.create_cf("meta").unwrap();
        assert_eq!(
            db.list_cfs().unwrap(),
            vec!["default".to_string(), "meta".to_string(), "tx".to_string()]
        );
        // Same key, different CFs, independent values.
        db.put("tx", b"k", b"tx-v").unwrap();
        db.put("meta", b"k", b"meta-v").unwrap();
        assert_eq!(db.get("tx", b"k").unwrap(), Some(b"tx-v".to_vec()));
        assert_eq!(db.get("meta", b"k").unwrap(), Some(b"meta-v".to_vec()));

        db.drop_cf("meta").unwrap();
        assert_eq!(
            db.list_cfs().unwrap(),
            vec!["default".to_string(), "tx".to_string()]
        );
        let err = db.get("meta", b"k").unwrap_err();
        assert_eq!(err.to_string(), "unknown column family: 'meta'");
    });
}

#[test]
fn test_unknown_cf_errors() {
    with_db(|db| {
        let err = db.get("nope", b"k").unwrap_err();
        assert_eq!(err.to_string(), "unknown column family: 'nope'");
    });
}

#[test]
fn test_write_batch_atomic_multi_cf() {
    with_db(|db| {
        db.create_cf("tx").unwrap();
        db.put("default", b"stale", b"x").unwrap();

        let batch = WriteBatch::new();
        batch.put("default", b"a", b"1").unwrap();
        batch.put("tx", b"b", b"2").unwrap();
        batch.delete("default", b"stale").unwrap();
        assert_eq!(batch.len().unwrap(), 3);
        db.write(&batch).unwrap();

        assert_eq!(db.get("default", b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(db.get("tx", b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(db.get("default", b"stale").unwrap(), None);

        // A batch is single-use.
        let err = db.write(&batch).unwrap_err();
        assert_eq!(err.to_string(), "write batch already consumed");
    });
}

#[test]
fn test_write_batch_unknown_cf_applies_nothing() {
    with_db(|db| {
        let batch = WriteBatch::new();
        batch.put("default", b"a", b"1").unwrap();
        batch.put("nope", b"b", b"2").unwrap();
        let err = db.write(&batch).unwrap_err();
        assert_eq!(err.to_string(), "unknown column family: 'nope'");
        // Atomicity: the valid op must not have been applied.
        assert_eq!(db.get("default", b"a").unwrap(), None);
    });
}

fn populate(db: &RocksDb) {
    for i in 0..10u8 {
        db.put("default", &[i], &[i, i]).unwrap();
    }
}

#[test]
fn test_iterator_forward_chunked() {
    with_db(|db| {
        populate(db);
        // Chunk size smaller than, equal to, and larger than the total.
        for chunk in [3, 10, 64] {
            let it = db.iterator("default", "first", None, false).unwrap();
            let items = drain(&it, chunk);
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
    with_db(|db| {
        populate(db);
        let it = db.iterator("default", "last", None, true).unwrap();
        let items = drain(&it, 4);
        let keys: Vec<Vec<u8>> = (0..10u8).rev().map(|i| vec![i]).collect();
        assert_eq!(
            keys_of(&items),
            keys.iter().map(|k| k.as_slice()).collect::<Vec<_>>()
        );
    });
}

#[test]
fn test_iterator_seek_forward() {
    with_db(|db| {
        populate(db);
        let it = db
            .iterator("default", "seek", Some(vec![7]), false)
            .unwrap();
        let items = drain(&it, 2);
        assert_eq!(keys_of(&items), vec![&[7][..], &[8][..], &[9][..]]);
    });
}

#[test]
fn test_iterator_seek_lands_on_next_key_when_absent() {
    with_db(|db| {
        populate(db);
        db.delete("default", &[7]).unwrap();
        let it = db
            .iterator("default", "seek", Some(vec![7]), false)
            .unwrap();
        let items = drain(&it, 64);
        assert_eq!(keys_of(&items), vec![&[8][..], &[9][..]]);
    });
}

#[test]
fn test_iterator_seek_for_prev_reverse() {
    with_db(|db| {
        populate(db);
        // seek_for_prev on an absent key positions at the greatest key <= target.
        let it = db
            .iterator("default", "seek_for_prev", Some(vec![6, 0]), true)
            .unwrap();
        let items = drain(&it, 3);
        let keys: Vec<Vec<u8>> = (0..=6u8).rev().map(|i| vec![i]).collect();
        assert_eq!(
            keys_of(&items),
            keys.iter().map(|k| k.as_slice()).collect::<Vec<_>>()
        );
    });
}

#[test]
fn test_iterator_empty_cf() {
    with_db(|db| {
        db.create_cf("empty").unwrap();
        let it = db.iterator("empty", "first", None, false).unwrap();
        assert_eq!(it.next_chunk(8).unwrap(), Vec::new());
    });
}

#[test]
fn test_iterator_mode_validation() {
    with_db(|db| {
        let err = db
            .iterator("default", "seek", None, false)
            .err()
            .expect("must fail");
        assert_eq!(err.to_string(), "mode 'seek' requires a key");
        let err = db
            .iterator("default", "first", Some(vec![1]), false)
            .err()
            .expect("must fail");
        assert_eq!(err.to_string(), "mode 'first' does not take a key");
        let err = db
            .iterator("default", "bogus", None, false)
            .err()
            .expect("must fail");
        assert_eq!(err.to_string(), "unknown iterator mode: 'bogus'");
        let err = db
            .iterator("nope", "first", None, false)
            .err()
            .expect("must fail");
        assert_eq!(err.to_string(), "unknown column family: 'nope'");
    });
}

#[test]
fn test_next_chunk_zero_errors() {
    with_db(|db| {
        let it = db.iterator("default", "first", None, false).unwrap();
        let err = it.next_chunk(0).unwrap_err();
        assert_eq!(err.to_string(), "chunk size must be positive");
    });
}

#[test]
fn test_key_may_exist() {
    with_db(|db| {
        db.put("default", b"present", b"v").unwrap();
        // True for a present key; false negatives are impossible by contract.
        assert!(db.key_may_exist("default", b"present").unwrap());
    });
}

#[test]
fn test_get_property() {
    with_db(|db| {
        let value = db
            .get_property("default", "rocksdb.estimate-num-keys")
            .unwrap();
        assert_eq!(value, Some("0".to_string()));
        let missing = db
            .get_property("default", "rocksdb.not-a-property")
            .unwrap();
        assert_eq!(missing, None);
    });
}

#[test]
fn test_flush() {
    with_db(|db| {
        db.create_cf("tx").unwrap();
        db.put("tx", b"k", b"v").unwrap();
        db.flush().unwrap();
        assert_eq!(db.get("tx", b"k").unwrap(), Some(b"v".to_vec()));
    });
}

#[test]
fn test_close_then_use_errors() {
    with_db(|db| {
        db.close();
        let err = db.get("default", b"k").unwrap_err();
        assert_eq!(err.to_string(), "database is closed");
        let err = db.list_cfs().unwrap_err();
        assert_eq!(err.to_string(), "database is closed");
        // close() is idempotent.
        db.close();
    });
}

#[test]
fn test_reopen_persists_data_and_cfs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db").to_str().unwrap().to_string();

    let db = RocksDb::open(&path, None).unwrap();
    db.create_cf("tx").unwrap();
    db.put("tx", b"k", b"v").unwrap();
    db.put("default", b"d", b"w").unwrap();
    db.close();

    let db = RocksDb::open(&path, Some(1 << 20)).unwrap();
    assert_eq!(
        db.list_cfs().unwrap(),
        vec!["default".to_string(), "tx".to_string()]
    );
    assert_eq!(db.get("tx", b"k").unwrap(), Some(b"v".to_vec()));
    assert_eq!(db.get("default", b"d").unwrap(), Some(b"w".to_vec()));
}

#[test]
fn test_native_handle_shares_writes() {
    with_db(|db| {
        db.put("default", b"k", b"v").unwrap();
        // The Rust-native path sees writes through the same primary handle.
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
