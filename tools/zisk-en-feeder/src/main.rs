//! zisk-en-feeder
//!
//! Reads the EN's RocksDB in secondary mode, walks blocks in order, builds
//! ZiSK `BatchInput` bincode (+ Airbender witness, once wired), and pushes
//! each batch to the sidecar at `$SIDECAR_URL/feed/batch`.
//!
//! Lives inside the `zksync-os-server` workspace so it can reuse the existing
//! `zisk_input_builder` helpers. Runs as its own Docker container alongside
//! the EN, with the EN's data dir mounted read-only.

mod input_builder;
mod replay_reader;

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use serde::Serialize;
use tracing_subscriber::EnvFilter;

use crate::replay_reader::SecondaryReplayReader;

#[derive(Parser, Debug)]
#[command(name = "zisk-en-feeder")]
struct Args {
    /// Path to the EN's RocksDB root (writer / primary). Must be readable.
    #[arg(long, env = "EN_ROCKS_DB_PATH")]
    en_rocks_db_path: PathBuf,

    /// Scratch dir for the secondary-mode replica state.
    #[arg(long, env = "FEEDER_SECONDARY_PATH", default_value = "/tmp/zisk_feeder_secondary")]
    secondary_path: PathBuf,

    /// Sidecar base URL to push produced inputs to.
    #[arg(long, env = "SIDECAR_URL", default_value = "http://sidecar:3124")]
    sidecar_url: String,

    /// How often to re-check the EN for new blocks.
    #[arg(long, env = "FEEDER_POLL_INTERVAL_SECS", default_value_t = 5)]
    poll_interval_secs: u64,

    /// How many contiguous blocks form one shadow batch.
    #[arg(long, env = "FEEDER_BATCH_SIZE", default_value_t = 8)]
    batch_size: u64,

    /// Optional starting block. Defaults to EN tip at startup, so we don't try
    /// to backfill an empty secondary instance.
    #[arg(long, env = "FEEDER_START_BLOCK")]
    start_block: Option<u64>,
}

#[derive(Serialize)]
struct FeedBatchReq {
    batch_number: u64,
    block_range: (u64, u64),
    #[serde(skip_serializing_if = "Option::is_none")]
    zisk_input_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    airbender_witness_hex: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,zisk_en_feeder=debug"))
        )
        .init();
    let args = Args::parse();
    tracing::info!(?args, "zisk-en-feeder starting");

    let replay_primary = args.en_rocks_db_path.join("block_replay_wal");
    let reader = SecondaryReplayReader::open(&replay_primary, &args.secondary_path)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    reader.refresh().ok();
    let mut next_lo = args.start_block.unwrap_or_else(|| {
        let tip = reader.latest_block();
        tip.saturating_sub(args.batch_size) + 1
    });
    tracing::info!(next_lo, "starting feed loop");

    let interval = Duration::from_secs(args.poll_interval_secs);
    loop {
        if let Err(e) = reader.refresh() {
            tracing::warn!(?e, "refresh secondary failed");
            tokio::time::sleep(interval).await;
            continue;
        }
        let tip = reader.latest_block();

        while tip + 1 >= next_lo + args.batch_size {
            let lo = next_lo;
            let hi = next_lo + args.batch_size - 1;
            match build_and_push(&reader, &client, &args.sidecar_url, lo, hi).await {
                Ok(()) => next_lo = hi + 1,
                Err(e) => {
                    tracing::warn!(?e, batch_range = ?(lo, hi), "feed attempt failed, retrying later");
                    break;
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

async fn build_and_push(
    reader: &SecondaryReplayReader,
    client: &reqwest::Client,
    sidecar_url: &str,
    lo: u64,
    hi: u64,
) -> anyhow::Result<()> {
    let batch_number = hi;
    let mut combined_zisk: Vec<u8> = Vec::new();
    let mut combined_airbender: Vec<u8> = Vec::new();
    let mut have_any = false;

    for n in lo..=hi {
        let replay = reader.read_record(n)?;
        if let Some(inputs) = input_builder::build_inputs_for_block(&replay) {
            combined_zisk.extend(inputs.zisk_bincode);
            combined_airbender.extend(inputs.airbender_witness_bytes);
            have_any = true;
        }
    }

    let body = FeedBatchReq {
        batch_number,
        block_range: (lo, hi),
        zisk_input_hex: have_any.then(|| format!("0x{}", hex::encode(&combined_zisk))),
        airbender_witness_hex: have_any.then(|| format!("0x{}", hex::encode(&combined_airbender))),
    };
    if !have_any {
        tracing::info!(batch_number, lo, hi, "input builder is still a stub — skipping push");
        return Ok(());
    }

    let url = format!("{}/feed/batch", sidecar_url.trim_end_matches('/'));
    let resp = client.post(&url).json(&body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("sidecar POST {} failed: {}", url, resp.status());
    }
    tracing::info!(batch_number, lo, hi, "posted batch to sidecar");
    Ok(())
}
