//! Block fetching for the indexers' catch-up. Worker threads ask the node
//! for blocks, turn each into what the indexer stores (so that work is
//! spread over the workers too, and blocks waiting for their turn are
//! small), and the indexer takes them in height order.
//!
//! One call per block: pivxd answers `getblockhash`/`getblock` batches
//! about twice as slowly as the same calls one by one (measured on 5.6.1).
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::rpc::RpcClient;
use crate::shield_sync::RpcConfig;
use crate::shutdown;

/// How far the workers may get ahead of the block the indexer takes.
/// Fetched blocks wait in memory for the ones before them: without a
/// limit, one slow fetch would let the others fill memory with blocks.
const LOOKAHEAD: u32 = 1_000;

/// Blocks `from..=to` in height order, fetched by `workers` threads.
/// `read` fetches and reads one height; a failure is tried 3 times.
pub struct Fetcher<T> {
    rx: mpsc::Receiver<(u32, Result<T, String>)>,
    waiting: BTreeMap<u32, Result<T, String>>,
    next: u32,
    to: u32,
    /// The next height the indexer takes; workers stay within LOOKAHEAD.
    taken: Arc<AtomicU32>,
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

impl<T: Send + 'static> Fetcher<T> {
    pub fn start<F>(rpc: &RpcConfig, from: u32, to: u32, workers: usize, read: F) -> Self
    where
        F: Fn(&RpcClient, u32) -> Result<T, String> + Send + Sync + 'static,
    {
        let read = Arc::new(read);
        let next = Arc::new(AtomicU32::new(from));
        let taken = Arc::new(AtomicU32::new(from));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel::<(u32, Result<T, String>)>(256);
        let handles = (0..workers)
            .map(|_| {
                let (read, next, taken, stop, tx, rpc) =
                    (read.clone(), next.clone(), taken.clone(), stop.clone(), tx.clone(), rpc.client());
                std::thread::spawn(move || {
                    let stopped = || stop.load(Ordering::SeqCst) || shutdown::stopping();
                    while !stopped() {
                        let h = next.fetch_add(1, Ordering::SeqCst);
                        if h > to {
                            break;
                        }
                        while h > taken.load(Ordering::SeqCst) + LOOKAHEAD && !stopped() {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        let mut result = Err(String::new());
                        for attempt in 0..3 {
                            result = read(&rpc, h);
                            match &result {
                                Err(e) if !stopped() => log::debug!("Fetching block {h} failed ({e}), retrying"),
                                _ => break,
                            }
                            std::thread::sleep(Duration::from_millis(500 * (attempt + 1)));
                        }
                        if tx.send((h, result)).is_err() {
                            return;
                        }
                    }
                })
            })
            .collect();
        Self { rx, waiting: BTreeMap::new(), next: from, to, taken, stop, handles }
    }

    /// The next block in height order; `None` after the last one, or once
    /// the bridge is stopping.
    pub fn next(&mut self) -> Option<(u32, Result<T, String>)> {
        if self.next > self.to {
            return None;
        }
        loop {
            if shutdown::stopping() {
                return None;
            }
            if let Some(r) = self.waiting.remove(&self.next) {
                let h = self.next;
                self.next += 1;
                self.taken.store(self.next, Ordering::SeqCst);
                return Some((h, r));
            }
            match self.rx.recv_timeout(Duration::from_millis(200)) {
                Ok((h, r)) => {
                    self.waiting.insert(h, r);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Some((self.next, Err("fetch workers stopped".into())));
                }
            }
        }
    }

    /// Stops the workers. When the bridge is stopping, a worker may still
    /// wait on the node: it isn't waited for.
    pub fn finish(self) {
        self.stop.store(true, Ordering::SeqCst);
        drop(self.rx);
        if !shutdown::stopping() {
            for h in self.handles {
                let _ = h.join();
            }
        }
    }
}
