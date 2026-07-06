//! Secondary-mode reader for the EN's block-replay WAL.
//!
//! Mirrors `tools/zisk-batch-test/src/replay_reader.rs` but uses RocksDB's
//! secondary instance mode so we can read while the EN continues to write.
//! The two readers diverge only in how the DB is opened; the record layout
//! is identical because the WAL format is owned by `zksync-os-server`.

use std::path::Path;

use zksync_os_interface::types::BlockContext;
use zksync_os_types::ZkTransaction;

const CF_CONTEXT: &str = "Context";
const CF_TXS: &str = "Txs";
const CF_LATEST: &str = "Latest";

const CF_NAMES: &[&str] = &[
    CF_CONTEXT, CF_TXS, CF_LATEST,
    "ProtocolVersion", "BlockOutputHash", "ForcePreimages",
    "StartingL1SerialId", "StartingInteropEventIndex",
    "StartingMigrationNumber", "StartingInteropFeeNumber",
    "CanonicalHash", "NodeVersion",
];

pub struct ReplayData {
    pub block_context: BlockContext,
    pub transactions: Vec<ZkTransaction>,
}

pub struct SecondaryReplayReader {
    db: rocksdb::DB,
}

impl SecondaryReplayReader {
    /// Open the EN's `block_replay_wal/` in secondary mode so the EN can keep
    /// writing while we read.
    pub fn open(primary_path: &Path, secondary_path: &Path) -> anyhow::Result<Self> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        std::fs::create_dir_all(secondary_path)?;
        let db = rocksdb::DB::open_cf_as_secondary(
            &opts,
            primary_path,
            secondary_path,
            CF_NAMES,
        )?;
        Ok(Self { db })
    }

    /// Catch up to the latest snapshot of the primary.
    pub fn refresh(&self) -> anyhow::Result<()> {
        self.db.try_catch_up_with_primary()?;
        Ok(())
    }

    pub fn latest_block(&self) -> u64 {
        let cf = self.db.cf_handle(CF_LATEST).expect("missing Latest CF");
        match self.db.get_cf(&cf, b"latest_block").ok().flatten() {
            Some(bytes) if bytes.len() == 8 => u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            _ => 0,
        }
    }

    pub fn read_record(&self, block_number: u64) -> anyhow::Result<ReplayData> {
        let key = block_number.to_be_bytes();
        let ctx_cf = self.db.cf_handle(CF_CONTEXT).expect("missing Context CF");
        let ctx_bytes = self.db.get_cf(&ctx_cf, &key)?
            .ok_or_else(|| anyhow::anyhow!("no context for block {block_number}"))?;
        let (block_context, _): (BlockContext, _) =
            bincode::serde::decode_from_slice(&ctx_bytes, bincode::config::standard())?;

        let txs_cf = self.db.cf_handle(CF_TXS).expect("missing Txs CF");
        let txs_bytes = self.db.get_cf(&txs_cf, &key)?
            .ok_or_else(|| anyhow::anyhow!("no txs for block {block_number}"))?;
        let (transactions, _): (Vec<ZkTransaction>, _) =
            bincode::decode_from_slice(&txs_bytes, bincode::config::standard())?;

        Ok(ReplayData { block_context, transactions })
    }
}
