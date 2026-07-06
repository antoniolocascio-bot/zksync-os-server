//! Minimal reader for the block replay WAL RocksDB.
//! Reads block context + transactions directly without needing Genesis or full server setup.

use zksync_os_interface::types::BlockContext;
use zksync_os_types::ZkTransaction;

/// Minimal block data extracted from the replay WAL.
pub struct ReplayData {
    pub block_context: BlockContext,
    pub transactions: Vec<ZkTransaction>,
}

/// Reads from the server's block_replay_wal RocksDB.
pub struct ReplayReader {
    db: rocksdb::DB,
}

const CF_CONTEXT: &str = "Context";
const CF_TXS: &str = "Txs";
const CF_LATEST: &str = "Latest";

impl ReplayReader {
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        // Open with all known column families (RocksDB requires listing them all)
        let cf_names = [
            CF_CONTEXT, CF_TXS, CF_LATEST,
            "ProtocolVersion", "BlockOutputHash", "ForcePreimages",
            "StartingL1SerialId", "StartingInteropEventIndex",
            "StartingMigrationNumber", "StartingInteropFeeNumber",
            "CanonicalHash", "NodeVersion",
        ];

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(true);

        let db = rocksdb::DB::open_cf(&opts, path, cf_names)?;
        Ok(Self { db })
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

        // Read BlockContext (bincode serde encoded)
        let ctx_cf = self.db.cf_handle(CF_CONTEXT).expect("missing Context CF");
        let ctx_bytes = self.db.get_cf(&ctx_cf, &key)?
            .ok_or_else(|| anyhow::anyhow!("no context for block {block_number}"))?;
        let (block_context, _): (BlockContext, _) =
            bincode::serde::decode_from_slice(&ctx_bytes, bincode::config::standard())?;

        // Read transactions (bincode Encode/Decode)
        let txs_cf = self.db.cf_handle(CF_TXS).expect("missing Txs CF");
        let txs_bytes = self.db.get_cf(&txs_cf, &key)?
            .ok_or_else(|| anyhow::anyhow!("no txs for block {block_number}"))?;
        let (transactions, _): (Vec<ZkTransaction>, _) =
            bincode::decode_from_slice(&txs_bytes, bincode::config::standard())?;

        Ok(ReplayData {
            block_context,
            transactions,
        })
    }
}
