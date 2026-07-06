# zisk-en-feeder

Shadow-mode capture tool: reads an External Node's block-replay storage and
turns real chain traffic into ZiSK `BatchInput`s for offline proving and
replay-based equivalence testing.

## How it fits together

```
testnet main node ──replay──► EN (en_dump_only mode)
                               │  recreates only L1-committed batches;
                               │  ZISK_DUMP_DIR writes BatchInput bincode
                               │
                               └── EN RocksDB ◄─(read-only, secondary mode)── zisk-en-feeder
                                                              │
                                                              ▼
                                                    sidecar / prover box
                                            (ZiSK executor for PI comparison,
                                             cargo-zisk for full proving runs)
```

Two capture paths exist; pick per use case:

- **`en_dump_only` on the EN** (config: `batcher.en_dump_only: true`): the EN
  itself runs ProverInputGenerator + Batcher, recreates each batch after it is
  committed on L1, and writes `batch_<N>_zisk.bin` (ZiSK stdin framing:
  `[len u64 LE][bincode][pad to 8]`) into `ZISK_DUMP_DIR`. Use for bulk
  capture straight to disk.
- **This feeder**: walks the EN's replay WAL directly (RocksDB secondary
  instance — the EN keeps writing while the feeder reads) and pushes built
  batches to a sidecar over HTTP. Use when the consumer is a live service
  rather than a directory of dumps.

## Running

```bash
cargo run --release -p zksync_os_zisk_en_feeder -- \
  --en-rocks-db-path /db/en/rocksdb   # or EN_ROCKS_DB_PATH; mount read-only
# optional:
#   --feeder-secondary-path /tmp/zisk_feeder_secondary   (RocksDB secondary dir)
#   --sidecar-url http://sidecar:3124                    (POST target, /feed/batch)
#   --feeder-poll-interval-secs 5
#   --feeder-batch-size 8
#   --feeder-start-block <N>
```

Every flag is also settable via the environment variable named next to it
above — convenient when running as a container beside the EN with the data
dir mounted read-only.

## Consuming the output

- PI comparison without proving: feed the bincode to the ZiSK executor via
  the zisk lib's `test_proven` reader helpers
  (`executor::execute_and_commit_from_bincode`) and compare the returned
  commitment with the batch public input.
- Full proving: the framed file is exactly `cargo-zisk prove -i` input; see
  the `zksync-os-zisk-prover` README for the v0.18.0 invocation.
