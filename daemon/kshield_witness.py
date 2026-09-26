#!/usr/bin/env python3
"""
kshield_witness.py — Universal Kernel Defense Framework (UKDF Phase 5)
Cross-Node Cryptographic Dual-Witness Notary Daemon
Project Aegis-Kernel | Enterprise Systems Architecture

Runs as an independent witness daemon on a secondary node:
1. Subscribes to NATS block stream broadcast by primary vault.
2. Independently validates:
   - Strict monotonic sequence counter (index == last_index + 1)
   - Dynamic reorder window for packet jitter (up to 200 blocks)
   - Unbroken SHA-256 hash chaining (prev_hash == last_hash)
   - Cryptographic payload integrity (recomputed SHA-256 == hash)
3. Synchronously commits verified blocks to local storage.
4. Enforces 60-second Dead-Man Switch on heartbeat topic (alerts on primary silence).
5. Exposes status telemetry in witness_status.json.
6. Rate-limited, isolated alerts on witness alert topic (preventing feedback loops).
"""

import os
import sys
import time
import json
import asyncio
import hashlib
import logging
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [WITNESS-NOTARY] %(message)s")
logger = logging.getLogger("KShieldWitness")

NATS_URL = os.getenv("NATS_URL", "nats://127.0.0.1:4222")
WITNESS_DIR = os.getenv("KSHIELD_WITNESS_DIR", "/var/log/kshield/witness")
WITNESS_FILE = os.path.join(WITNESS_DIR, "audit_chain_witness.jsonl")
STATUS_FILE = os.path.join(WITNESS_DIR, "witness_status.json")
WITNESS_BLOCK_TOPIC = os.getenv("KSHIELD_WITNESS_BLOCK_TOPIC", "kshield.security.witness.block")
HEARTBEAT_TOPIC = os.getenv("KSHIELD_HEARTBEAT_TOPIC", "kshield.security.heartbeat")
WITNESS_ALERT_TOPIC = os.getenv("KSHIELD_WITNESS_ALERT_TOPIC", "kshield.security.witness.alert")
DEAD_MAN_TIMEOUT_SEC = float(os.getenv("KSHIELD_DEAD_MAN_TIMEOUT_SEC", "60.0"))
ALERT_COOLDOWN_SEC = float(os.getenv("KSHIELD_ALERT_COOLDOWN_SEC", "60.0"))
REORDER_WINDOW_MAX = int(os.getenv("KSHIELD_REORDER_WINDOW_MAX", "200"))
NODE_ID = os.getenv("KSHIELD_NODE_ID", "witness-notary-01")

GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class KShieldWitness:
    def __init__(self, ledger_path: str = WITNESS_FILE):
        self.ledger_path = ledger_path
        self.last_index = 0
        self.last_hash = GENESIS_PREV_HASH
        self.total_verified = 0
        self.last_heartbeat_time = time.time()
        self.dead_man_tripped = False
        self.desynchronized = False
        self.reorder_buffer: Dict[int, Dict[str, Any]] = {}
        self.last_alert_times: Dict[str, float] = {}
        self.nc = None
        self._init_ledger()

    def _init_ledger(self):
        os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)
        if os.path.exists(self.ledger_path):
            logger.info(f"Reading existing ledger baseline: {self.ledger_path}...")
            count = 0
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip(" \t\r\n\x00")
                    if line:
                        try:
                            rec = json.loads(line)
                            self.last_index = rec.get("index", 0)
                            self.last_hash = rec.get("hash", GENESIS_PREV_HASH)
                            count += 1
                        except Exception:
                            pass
            logger.info(f"[OK] Baseline loaded: {count:,} records. Head Index: {self.last_index}, Head Hash: {self.last_hash[:16]}...")
        else:
            logger.warning(f"Ledger file not found at {self.ledger_path}. Awaiting first block or baseline sync.")

        self._write_status("INITIALIZED")

    def _write_status(self, state: str):
        status = {
            "status": state,
            "witness_node": NODE_ID,
            "ledger_path": self.ledger_path,
            "head_index": self.last_index,
            "head_hash": self.last_hash,
            "reorder_buffer_size": len(self.reorder_buffer),
            "desynchronized": self.desynchronized,
            "total_verified_in_session": self.total_verified,
            "last_heartbeat_timestamp": self.last_heartbeat_time,
            "dead_man_active": not self.dead_man_tripped,
            "updated_at": time.time()
        }
        try:
            with open(STATUS_FILE, "w", encoding="utf-8") as f:
                json.dump(status, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not write status file: {e}")

    @staticmethod
    def compute_hash(index: int, timestamp: Any, topic: str, data: Any, prev_hash: str) -> str:
        data_str = json.dumps(data)
        raw = f"{index}|{timestamp}|{topic}|{data_str}|{prev_hash}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    async def _emit_alert(self, severity: str, event_type: str, message: str):
        now = time.time()
        if now - self.last_alert_times.get(event_type, 0) < ALERT_COOLDOWN_SEC:
            return  # Rate-limited
        self.last_alert_times[event_type] = now

        payload = {
            "source": f"KShieldWitness_{NODE_ID}",
            "severity": severity,
            "event_type": event_type,
            "message": message,
            "node": NODE_ID,
            "last_verified_index": self.last_index,
            "timestamp": now
        }
        if self.nc:
            try:
                await self.nc.publish(WITNESS_ALERT_TOPIC, json.dumps(payload).encode("utf-8"))
            except Exception as e:
                logger.error(f"Failed to publish witness alert: {e}")

    def _commit_block_to_disk(self, block: Dict[str, Any]):
        record_json = json.dumps(block)
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(record_json + "\n")
            f.flush()
            os.fsync(f.fileno())

    async def process_block(self, block: Dict[str, Any]) -> bool:
        idx = block.get("index", 0)
        ts = block.get("timestamp")
        topic = block.get("topic", "")
        data = block.get("data")
        prev_hash = block.get("prev_hash")
        received_hash = block.get("hash")

        expected_index = self.last_index + 1

        # Case 1: Already processed / stale block
        if idx <= self.last_index:
            return True

        # Case 2: Out of order block within reorder window
        if idx > expected_index:
            if idx <= expected_index + REORDER_WINDOW_MAX:
                self.reorder_buffer[idx] = block
                if not self.desynchronized:
                    logger.debug(f"Buffering out-of-order block #{idx} (expected #{expected_index}). Buffer size: {len(self.reorder_buffer)}")
                return False
            else:
                # Sequence gap exceeds buffer window
                if not self.desynchronized:
                    self.desynchronized = True
                    err_msg = f"[ALERT] SEQUENCE GAP: Expected index {expected_index}, received {idx} (> window {REORDER_WINDOW_MAX})! Awaiting baseline sync."
                    logger.error(err_msg)
                    await self._emit_alert("CRITICAL", "SEQUENCE_GAP", err_msg)
                    self._write_status("DESYNCHRONIZED")
                return False

        # Case 3: Exactly the expected next block (idx == expected_index)
        # Verify Hash Chain Continuity
        if prev_hash != self.last_hash:
            err_msg = f"[ALERT] HASH CHAIN BROKEN: Block #{idx} prev_hash ({prev_hash[:16]}...) != expected ({self.last_hash[:16]}...)!"
            logger.error(err_msg)
            await self._emit_alert("CRITICAL", "HASH_CHAIN_DIVERGENCE", err_msg)
            return False

        # Verify Payload Integrity
        computed = self.compute_hash(idx, ts, topic, data, prev_hash)
        if computed != received_hash:
            err_msg = f"[ALERT] CRYPTOGRAPHIC MISMATCH: Block #{idx} stored hash ({received_hash[:16]}...) != computed ({computed[:16]}...)!"
            logger.error(err_msg)
            await self._emit_alert("CRITICAL", "PAYLOAD_TAMPERING", err_msg)
            return False

        # Synchronous Commit to Disk (NVMe WORM)
        self._commit_block_to_disk(block)

        self.last_index = idx
        self.last_hash = received_hash
        self.total_verified += 1
        self.last_heartbeat_time = time.time()
        self.dead_man_tripped = False
        if self.desynchronized:
            logger.info("[OK] Witness resynchronization achieved! Resuming live validation.")
            self.desynchronized = False

        self._write_status("HEALTHY")
        if self.total_verified % 50 == 0 or idx % 25 == 0:
            logger.info(f"[NOTARY] Witnessed & Attested Block #{idx} [{topic}] Hash: {received_hash[:16]}... (Zero Divergence)")

        # Drain buffered blocks if consecutive blocks are waiting
        while (self.last_index + 1) in self.reorder_buffer:
            next_idx = self.last_index + 1
            next_block = self.reorder_buffer.pop(next_idx)
            logger.info(f"Processing buffered block #{next_idx}...")
            await self.process_block(next_block)

        return True

    async def run_dead_man_monitor(self):
        while True:
            await asyncio.sleep(10)
            elapsed = time.time() - self.last_heartbeat_time
            if elapsed > DEAD_MAN_TIMEOUT_SEC:
                if not self.dead_man_tripped:
                    self.dead_man_tripped = True
                    msg = f"DEAD-MAN TRIGGER: Zero heartbeat or audit blocks received for {elapsed:.1f}s (Threshold: {DEAD_MAN_TIMEOUT_SEC}s)!"
                    logger.critical(f"[ALERT] {msg}")
                    await self._emit_alert("CRITICAL", "WORM_LOGGER_SILENT", msg)
                    self._write_status("DEAD_MAN_ALARM")
            else:
                if self.dead_man_tripped:
                    logger.info("[OK] Logger heartbeat restored. Dead-man alarm cleared.")
                    self.dead_man_tripped = False
                    self._write_status("HEALTHY")


async def main():
    witness = KShieldWitness()

    from nats.aio.client import Client as NATS
    nc = NATS()
    logger.info(f"Connecting to NATS cluster at {NATS_URL}...")
    await nc.connect(NATS_URL)
    witness.nc = nc
    logger.info("Connected to NATS cluster fabric.")

    async def block_callback(msg):
        try:
            payload = json.loads(msg.data.decode("utf-8"))
            await witness.process_block(payload)
        except Exception as e:
            logger.error(f"Error processing witness block: {e}")

    await nc.subscribe(WITNESS_BLOCK_TOPIC, cb=block_callback)
    logger.info(f"Subscribed to '{WITNESS_BLOCK_TOPIC}' (Synchronous Block Ingestion).")

    async def heartbeat_callback(msg):
        witness.last_heartbeat_time = time.time()
        if witness.dead_man_tripped:
            logger.info("Heartbeat received from primary vault. Clearing dead-man alarm.")
            witness.dead_man_tripped = False
            witness._write_status("HEALTHY")

    await nc.subscribe(HEARTBEAT_TOPIC, cb=heartbeat_callback)
    logger.info(f"Subscribed to '{HEARTBEAT_TOPIC}' (Dead-Man Switch).")

    asyncio.create_task(witness.run_dead_man_monitor())

    logger.info("Dual-Witness Notary Daemon Active and Guarding Ledger.")
    witness._write_status("HEALTHY")

    while True:
        await asyncio.sleep(30)
        witness._write_status("HEALTHY" if not witness.desynchronized else "DESYNCHRONIZED")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Witness daemon shutting down gracefully.")
