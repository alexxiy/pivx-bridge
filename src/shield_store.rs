//! Shield stream storage.
//!
//! `shield.bin` holds the PIVX-compat stream (append-only, served by byte
//! range straight from disk). A small redb database next to it holds:
//!   - BLOCKS  height → start offset of the block in the pivx, compact and
//!     compact+ streams (the compact streams are derived on the fly, their
//!     offsets are kept so lengths are known without converting)
//!   - HASHES  height → block hash for the last `HASH_WINDOW` scanned
//!     blocks, so reorgs are found exactly, also across restarts
//!   - META    committed stream lengths and the scan cursor
//!
//! Commit order: new bytes are appended to shield.bin and fsynced, then one
//! redb transaction records the blocks, the lengths and the cursor. On
//! startup shield.bin is cut back to the committed length, so a crash
//! between the two steps only loses the unrecorded tail.
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::api::StreamFormat;
use crate::scanner::ShieldBlock;
use crate::stream;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const BLOCKS: TableDefinition<u32, (u64, u64, u64)> = TableDefinition::new("blocks");
const HASHES: TableDefinition<u32, &[u8]> = TableDefinition::new("hashes");

/// Bump to refuse databases written by an incompatible version.
const SCHEMA_VERSION: u32 = 1;

/// Scanned block hashes kept for reorg detection.
pub const HASH_WINDOW: u32 = 1_000;

/// Lengths of the three stream formats (bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lengths {
    pub pivx: u64,
    pub compact: u64,
    pub compact_plus: u64,
}

impl Lengths {
    fn from_tuple((pivx, compact, compact_plus): (u64, u64, u64)) -> Self {
        Self { pivx, compact, compact_plus }
    }

    pub fn of(&self, format: StreamFormat) -> u64 {
        match format {
            StreamFormat::PivxCompat => self.pivx,
            StreamFormat::Compact => self.compact,
            StreamFormat::CompactPlus => self.compact_plus,
        }
    }

    fn encode(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&self.pivx.to_le_bytes());
        b[8..16].copy_from_slice(&self.compact.to_le_bytes());
        b[16..].copy_from_slice(&self.compact_plus.to_le_bytes());
        b
    }

    fn decode(b: &[u8]) -> Self {
        let get = |i: usize| b.get(i..i + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())).unwrap_or(0);
        Self { pivx: get(0), compact: get(8), compact_plus: get(16) }
    }
}

/// Last scanned block (scanned = looked at, with or without shield txs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub height: u32,
    /// Display-order hex; empty before the first block is scanned.
    pub hash: String,
}

impl Cursor {
    fn encode(&self) -> Vec<u8> {
        let mut b = self.height.to_le_bytes().to_vec();
        b.extend_from_slice(self.hash.as_bytes());
        b
    }

    fn decode(b: &[u8]) -> Self {
        let height = b.get(..4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).unwrap_or(0);
        let hash = b.get(4..).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default();
        Self { height, hash }
    }
}

/// A consistent view of the stored stream for one request.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub lengths: Lengths,
    pub generation: u64,
}

pub struct ShieldStore {
    label: &'static str,
    db: Database,
    bin_path: PathBuf,
    /// Writer handle of shield.bin; also serialises writers.
    file: Mutex<File>,
    lengths: RwLock<Lengths>,
    cursor: RwLock<Cursor>,
    /// Bumped before shield.bin is cut back (reorg). A reader that sees it
    /// change while streaming stops, as the bytes may no longer match.
    generation: AtomicU64,
}

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

impl ShieldStore {
    /// Open (or create) the store. `start_height` is where a fresh store
    /// starts scanning (Sapling activation).
    pub fn open(label: &'static str, db_path: &str, bin_path: &str, start_height: u32) -> Result<Self, String> {
        let db = Database::create(db_path)
            .map_err(|err| format!("{db_path}: {err} (delete it and shield.bin to rebuild)"))?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(bin_path)
            .map_err(|err| format!("{bin_path}: {err}"))?;

        let schema = {
            let r = db.begin_read().map_err(e)?;
            match r.open_table(META) {
                Ok(t) => t.get("schema").map_err(e)?.map(|v| v.value().to_vec()),
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(err) => return Err(err.to_string()),
            }
        };
        match schema {
            Some(v) if v.as_slice() != SCHEMA_VERSION.to_le_bytes() => {
                return Err(format!("{db_path} was written by another bridge version — delete it to rebuild"));
            }
            Some(_) => {}
            None => Self::initialise(label, &db, &mut file, bin_path, start_height)?,
        }

        let (lengths, cursor) = {
            let r = db.begin_read().map_err(e)?;
            let meta = r.open_table(META).map_err(e)?;
            let lengths = meta.get("lengths").map_err(e)?.map(|v| Lengths::decode(v.value())).unwrap_or_default();
            let cursor = meta.get("cursor").map_err(e)?.map(|v| Cursor::decode(v.value())).unwrap_or_default();
            (lengths, cursor)
        };
        let store = Self {
            label,
            db,
            bin_path: PathBuf::from(bin_path),
            file: Mutex::new(file),
            lengths: RwLock::new(lengths),
            cursor: RwLock::new(cursor),
            generation: AtomicU64::new(0),
        };
        store.check_file_length()?;
        Ok(store)
    }

    /// First start: an empty store. A shield.bin without its database
    /// (another version, PivxNodeController) is not trusted: scan anew.
    fn initialise(label: &str, db: &Database, file: &mut File, bin_path: &str, start_height: u32) -> Result<(), String> {
        if file.metadata().map_err(e)?.len() > 0 {
            log::info!("[{label}] {bin_path} has no index: rebuilding it from block {start_height}");
            file.set_len(0).map_err(e)?;
            file.sync_data().map_err(e)?;
        }
        let cursor = Cursor { height: start_height.saturating_sub(1), hash: String::new() };
        let w = crate::db::begin_write(db)?;
        {
            w.open_table(BLOCKS).map_err(e)?;
            w.open_table(HASHES).map_err(e)?;
            let mut meta = w.open_table(META).map_err(e)?;
            meta.insert("schema", &SCHEMA_VERSION.to_le_bytes()[..]).map_err(e)?;
            meta.insert("lengths", &Lengths::default().encode()[..]).map_err(e)?;
            meta.insert("cursor", &cursor.encode()[..]).map_err(e)?;
        }
        w.commit().map_err(e)
    }

    /// shield.bin must hold exactly the committed bytes: cut a longer file
    /// back (crash after writing, before committing); roll the index back
    /// to what a shorter file still holds (should never happen).
    fn check_file_length(&self) -> Result<(), String> {
        let file = self.file.lock().unwrap();
        let actual = file.metadata().map_err(e)?.len();
        let committed = self.lengths.read().unwrap().pivx;
        if actual > committed {
            log::info!(
                "[{}] Cutting {} uncommitted bytes from the end of {}",
                self.label,
                actual - committed,
                self.bin_path.display()
            );
            file.set_len(committed).map_err(e)?;
            file.sync_data().map_err(e)?;
        } else if actual < committed {
            // Find the first block that isn't fully on disk and roll back
            // from there.
            let r = self.db.begin_read().map_err(e)?;
            let table = r.open_table(BLOCKS).map_err(e)?;
            // A block ends where the next one starts (the last one at
            // `committed`), so the first incomplete block is the one before
            // the first start past the end of the file, or the last one.
            let mut last_started = None;
            let mut first_incomplete = None;
            for item in table.iter().map_err(e)? {
                let (k, v) = item.map_err(e)?;
                if v.value().0 > actual {
                    first_incomplete = last_started;
                    break;
                }
                last_started = Some(k.value());
            }
            drop(table);
            drop(r);
            drop(file);
            let fork = first_incomplete.or(last_started).unwrap_or(0);
            log::warn!(
                "[{}] {} is shorter than its index ({actual} < {committed}); rescanning from {fork}",
                self.label,
                self.bin_path.display()
            );
            self.rollback_to(fork)?;
        }
        Ok(())
    }

    pub fn cursor(&self) -> Cursor {
        self.cursor.read().unwrap().clone()
    }

    pub fn snapshot(&self) -> Snapshot {
        // Read the generation first: a rollback that lands after this is
        // seen by the reader's per-chunk check.
        let generation = self.generation.load(Ordering::SeqCst);
        Snapshot { lengths: *self.lengths.read().unwrap(), generation }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Stored hash of a scanned block, if still in the window.
    pub fn hash_at(&self, height: u32) -> Result<Option<String>, String> {
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(HASHES).map_err(e)?;
        Ok(t.get(height).map_err(e)?.map(|v| String::from_utf8_lossy(v.value()).into_owned()))
    }

    /// Stream offsets where the first block at or above `height` starts,
    /// or `None` when there is none.
    pub fn offsets_from(&self, height: u32) -> Result<Option<Lengths>, String> {
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(BLOCKS).map_err(e)?;
        let first = t.range(height..).map_err(e)?.next();
        match first {
            Some(item) => Ok(Some(Lengths::from_tuple(item.map_err(e)?.1.value()))),
            None => Ok(None),
        }
    }

    /// Stream offsets just past the last block at or below `height`,
    /// limited to `snapshot`.
    pub fn offsets_after(&self, height: u32, snapshot: &Snapshot) -> Result<Lengths, String> {
        Ok(match height.checked_add(1) {
            Some(next) => self.offsets_from(next)?.unwrap_or(snapshot.lengths),
            None => snapshot.lengths,
        })
    }

    /// Heights of all shield blocks, ascending.
    pub fn heights(&self) -> Result<Vec<u32>, String> {
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(BLOCKS).map_err(e)?;
        let mut out = Vec::with_capacity(t.len().map_err(e)? as usize);
        for item in t.iter().map_err(e)? {
            out.push(item.map_err(e)?.0.value());
        }
        Ok(out)
    }

    pub fn block_count(&self) -> Result<u64, String> {
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(BLOCKS).map_err(e)?;
        t.len().map_err(e)
    }

    /// A read handle on shield.bin for serving.
    pub fn open_reader(&self) -> std::io::Result<File> {
        File::open(&self.bin_path)
    }

    /// Append `blocks` (shield blocks, ascending) and move the cursor to
    /// the last of `scanned` (every block looked at, with its hash).
    pub fn append(&self, blocks: &[ShieldBlock], scanned: &[(u32, String)]) -> Result<(), String> {
        let Some(last) = scanned.last() else { return Ok(()) };
        let mut file = self.file.lock().unwrap();
        let before = *self.lengths.read().unwrap();

        let mut lengths = before;
        let mut rows = Vec::with_capacity(blocks.len());
        let mut bytes = Vec::new();
        for b in blocks {
            let encoded = stream::encode_shield_stream(std::slice::from_ref(b), StreamFormat::PivxCompat);
            rows.push((b.height, (lengths.pivx, lengths.compact, lengths.compact_plus)));
            lengths.pivx += encoded.len() as u64;
            lengths.compact += stream::pivxcompat_to_compact(&encoded, StreamFormat::Compact).len() as u64;
            lengths.compact_plus += stream::pivxcompat_to_compact(&encoded, StreamFormat::CompactPlus).len() as u64;
            bytes.extend_from_slice(&encoded);
        }
        if !bytes.is_empty() {
            // Drop whatever a failed earlier write may have left.
            file.set_len(before.pivx).map_err(e)?;
            file.seek(SeekFrom::Start(before.pivx)).map_err(e)?;
            file.write_all(&bytes).map_err(e)?;
            file.sync_data().map_err(e)?;
        }

        let cursor = Cursor { height: last.0, hash: last.1.clone() };
        let w = crate::db::begin_write(&self.db)?;
        {
            let mut table = w.open_table(BLOCKS).map_err(e)?;
            for (h, offsets) in &rows {
                table.insert(*h, *offsets).map_err(e)?;
            }
            let mut hashes = w.open_table(HASHES).map_err(e)?;
            let keep_from = cursor.height.saturating_sub(HASH_WINDOW);
            for (h, hash) in scanned.iter().filter(|(h, _)| *h >= keep_from) {
                hashes.insert(*h, hash.as_bytes()).map_err(e)?;
            }
            hashes.retain_in(..keep_from, |_, _| false).map_err(e)?;
            let mut meta = w.open_table(META).map_err(e)?;
            meta.insert("lengths", &lengths.encode()[..]).map_err(e)?;
            meta.insert("cursor", &cursor.encode()[..]).map_err(e)?;
        }
        w.commit().map_err(e)?;
        *self.lengths.write().unwrap() = lengths;
        *self.cursor.write().unwrap() = cursor;
        Ok(())
    }

    /// Forget every block at or above `fork` (a reorg): the cursor moves
    /// to `fork - 1` and shield.bin is cut back.
    pub fn rollback_to(&self, fork: u32) -> Result<(), String> {
        let file = self.file.lock().unwrap();
        let current = *self.lengths.read().unwrap();
        let w = crate::db::begin_write(&self.db)?;
        let lengths;
        let cursor;
        {
            let mut table = w.open_table(BLOCKS).map_err(e)?;
            let first = table.range(fork..).map_err(e)?.next().map(|i| i.map(|(_, v)| v.value())).transpose().map_err(e)?;
            lengths = first.map(Lengths::from_tuple).unwrap_or(current);
            table.retain_in(fork.., |_, _| false).map_err(e)?;
            let mut hashes = w.open_table(HASHES).map_err(e)?;
            hashes.retain_in(fork.., |_, _| false).map_err(e)?;
            let height = fork.saturating_sub(1);
            let hash = hashes.get(height).map_err(e)?.map(|v| String::from_utf8_lossy(v.value()).into_owned()).unwrap_or_default();
            cursor = Cursor { height, hash };
            let mut meta = w.open_table(META).map_err(e)?;
            meta.insert("lengths", &lengths.encode()[..]).map_err(e)?;
            meta.insert("cursor", &cursor.encode()[..]).map_err(e)?;
        }
        w.commit().map_err(e)?;
        self.generation.fetch_add(1, Ordering::SeqCst);
        *self.lengths.write().unwrap() = lengths;
        *self.cursor.write().unwrap() = cursor;
        file.set_len(lengths.pivx).map_err(e)?;
        file.sync_data().map_err(e)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ShieldTx;

    fn block(height: u32, time: u32) -> ShieldBlock {
        ShieldBlock { height, time, txs: vec![ShieldTx { raw: vec![0x03, 0x00, 0x00, 0x00, 0xAB], compact: None }] }
    }

    fn temp(name: &str) -> (String, String) {
        let dir = std::env::temp_dir().join(format!("pivx-bridge-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = |f: &str| dir.join(f).to_string_lossy().into_owned();
        (p("shield.redb"), p("shield.bin"))
    }

    fn open(paths: &(String, String)) -> ShieldStore {
        ShieldStore::open("test", &paths.0, &paths.1, 100).unwrap()
    }

    #[test]
    fn append_query_and_reopen() {
        let paths = temp("append");
        let store = open(&paths);
        assert_eq!(store.cursor().height, 99);
        store
            .append(&[block(100, 1), block(105, 2)], &[(100, "a".into()), (104, "b".into()), (105, "c".into())])
            .unwrap();
        assert_eq!(store.heights().unwrap(), vec![100, 105]);
        assert_eq!(store.cursor(), Cursor { height: 105, hash: "c".into() });
        let snap = store.snapshot();
        let one = stream::encode_shield_stream(&[block(100, 1)], StreamFormat::PivxCompat).len() as u64;
        assert_eq!(snap.lengths.pivx, 2 * one);
        assert_eq!(store.offsets_from(101).unwrap().unwrap().pivx, one);
        assert_eq!(store.offsets_from(106).unwrap(), None);
        assert_eq!(store.offsets_after(100, &snap).unwrap().pivx, one);
        assert_eq!(store.hash_at(104).unwrap().as_deref(), Some("b"));
        drop(store);

        // Uncommitted tail is cut on open.
        let mut f = OpenOptions::new().append(true).open(&paths.1).unwrap();
        f.write_all(&[1, 2, 3]).unwrap();
        drop(f);
        let store = open(&paths);
        assert_eq!(std::fs::metadata(&paths.1).unwrap().len(), 2 * one);
        assert_eq!(store.heights().unwrap(), vec![100, 105]);
    }

    #[test]
    fn rollback_cuts_file_and_cursor() {
        let paths = temp("rollback");
        let store = open(&paths);
        store
            .append(&[block(100, 1), block(105, 2)], &[(100, "a".into()), (104, "b".into()), (105, "c".into())])
            .unwrap();
        let generation = store.generation();
        store.rollback_to(105).unwrap();
        assert!(store.generation() > generation);
        assert_eq!(store.heights().unwrap(), vec![100]);
        assert_eq!(store.cursor(), Cursor { height: 104, hash: "b".into() });
        let one = stream::encode_shield_stream(&[block(100, 1)], StreamFormat::PivxCompat).len() as u64;
        assert_eq!(std::fs::metadata(&paths.1).unwrap().len(), one);
        // Re-append on the new chain lands right after block 100.
        store.append(&[block(105, 9)], &[(105, "c2".into())]).unwrap();
        assert_eq!(store.offsets_from(105).unwrap().unwrap().pivx, one);
    }

    #[test]
    fn stream_without_index_is_rebuilt() {
        let paths = temp("orphan");
        std::fs::write(&paths.1, stream::encode_shield_stream(&[block(100, 1)], StreamFormat::PivxCompat)).unwrap();
        let store = open(&paths);
        assert_eq!(store.heights().unwrap(), Vec::<u32>::new());
        assert_eq!(store.cursor().height, 99);
        assert_eq!(std::fs::metadata(&paths.1).unwrap().len(), 0);
    }
}
