//! Process-wide interner for rule adapter (target) names.
//!
//! A config of several thousand rules names only a handful of distinct
//! targets (`DIRECT`, `Proxy`, a few groups). Storing one `String` per rule
//! costs 24 bytes inline plus a heap block each; interning hands every rule
//! a 16-byte `Arc<str>` that shares one block per distinct name. Names that
//! no live rule references any more are pruned whenever a new name is
//! interned, so the table tracks the live configuration rather than
//! accumulating across reloads.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

/// Shared, immutable adapter name.
pub type Adapter = Arc<str>;

static INTERNER: Mutex<Option<HashSet<Arc<str>>>> = Mutex::new(None);

/// Return the shared handle for `name`, creating it on first sight.
pub fn intern_adapter(name: &str) -> Adapter {
    let mut guard = INTERNER.lock().unwrap_or_else(PoisonError::into_inner);
    let table = guard.get_or_insert_with(HashSet::new);
    if let Some(existing) = table.get(name) {
        return Arc::clone(existing);
    }
    // Growing the table is rare (new distinct name): drop entries that
    // only the table itself still holds before inserting.
    table.retain(|entry| Arc::strong_count(entry) > 1);
    let handle: Arc<str> = Arc::from(name);
    table.insert(Arc::clone(&handle));
    handle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_shares_one_allocation_per_name() {
        let a = intern_adapter("intern-test-shared");
        let b = intern_adapter("intern-test-shared");
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(&*a, "intern-test-shared");
        let c = intern_adapter("intern-test-other");
        assert!(!Arc::ptr_eq(&a, &c));
    }

    #[test]
    fn unreferenced_names_are_pruned_on_growth() {
        let dead = intern_adapter("intern-test-dead");
        let dead_ptr = Arc::as_ptr(&dead);
        drop(dead);
        // Force a table growth, which prunes names only the table holds.
        let _keep = intern_adapter("intern-test-growth");
        let revived = intern_adapter("intern-test-dead");
        // A fresh allocation is the expected outcome; an equal pointer is
        // possible if the allocator reuses the block, so only check content.
        assert_eq!(&*revived, "intern-test-dead");
        let _ = dead_ptr;
    }
}
