//! redb helpers shared by the shield store and the address index.
use redb::{Database, WriteTransaction};

/// A write transaction that saves the allocator state with its commit
/// (redb's quick-repair). After a crash or a kill the database then opens
/// at once; without it redb walks the whole file to rebuild that state,
/// which takes long for a large address index.
pub fn begin_write(db: &Database) -> Result<WriteTransaction, String> {
    let mut w = db.begin_write().map_err(|e| e.to_string())?;
    w.set_quick_repair(true);
    Ok(w)
}
