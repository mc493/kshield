#!/usr/bin/env python3
"""
kshield_publisher.py — Universal Kernel Defense Framework (UKDF Phase 5)
Cross-Node Cryptographic Dual-Witness Primary Publisher Daemon
Project Aegis-Kernel | Enterprise Systems Architecture

Runs as an independent publisher daemon on the primary host:
1. Tails the local WORM vault ledger (/var/log/kshield/audit_chain.jsonl).
2. Broadcasts newly committed blocks to NATS topic (kshield.security.witness.block).
3. Emits periodic 30-second heartbeats to (kshield.security.heartbeat) to maintain
   the remote witness notary Dead-Man switch in healthy status.
4. Resilient to network partitions (offset backpressure), NATS restarts, and log rotation.
5. Bounded O(1) tail seek initialization for instant startup across arbitrarily large ledgers.
"""

import os
import sys
import time
import json
import asyncio
import signal
import logging
from typing import Dict, Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [VAULT-PUBLISHER] %(message)s"
)
logger = logging.getLogger("KShieldPublisher")

NATS_URL = os.getenv("NATS_URL", "nats://127.0.0.1:4222")
VAULT_PATH = os.getenv("KSHIELD_VAULT_PATH", "/var/log/kshield/audit_chain.jsonl")
WITNESS_BLOCK_TOPIC = os.getenv("KSHIELD_WITNESS_BLOCK_TOPIC", "kshield.security.witness.block")
HEARTBEAT_TOPIC = os.getenv("KSHIELD_HEARTBEAT_TOPIC", "kshield.security.heartbeat")
HEARTBEAT_INTERVAL_SEC = float(os.getenv("KSHIELD_HEARTBEAT_INTERVAL_SEC", "30.0"))
NODE_ID = os.getenv("KSHIELD_NODE_ID", "primary-vault-01")


class KShieldPublisher:
    """Tails the local audit ledger and streams attested blocks to the remote witness notary."""

    def __init__(self, vault_path: str = VAULT_PATH, nats_url: str = NATS_URL):
        self.vault_path = vault_path
        self.nats_url = nats_url
        self.nc = None
        self.running = False
        self.last_index = 0
        self.last_hash = "0" * 64
        self.total_published = 0
        self.file_pos = 0

    async def connect_nats(self):
        """Establishes resilient connection to the NATS message plane."""
        try:
            import nats
        except ImportError:
            logger.error("nats-py package not installed. Install requirements via daemon/requirements.txt.")
            sys.exit(1)

        while self.running:
            try:
                logger.info(f"Connecting to NATS at {self.nats_url}...")
                self.nc = await nats.connect(
                    servers=[self.nats_url],
                    connect_timeout=5,
                    reconnect_time_wait=2,
                    max_reconnect_attempts=-1
                )
                logger.info(f"Connected to NATS ({self.nats_url}) successfully.")
                break
            except Exception as e:
                logger.warning(f"NATS connection failed: {e}. Retrying in 5 seconds...")
                await asyncio.sleep(5)

    def _sync_tail_position(self):
        """Initializes read pointer to current end-of-file, caching current head index and hash in O(1) time."""
        if not os.path.exists(self.vault_path):
            logger.warning(f"Ledger file not found at {self.vault_path}. Publisher will await file creation.")
            self.file_pos = 0
            return

        try:
            file_size = os.path.getsize(self.vault_path)
            self.file_pos = file_size
            if file_size == 0:
                self.last_index = 0
                self.last_hash = "0" * 64
                logger.info("Baseline synchronized: Ledger is empty. Offset: 0 bytes.")
                return

            with open(self.vault_path, "rb") as f:
                try:
                    if file_size > 65536:
                        f.seek(-65536, os.SEEK_END)
                        f.readline()  # discard potential partial line
                    else:
                        f.seek(0)
                except OSError:
                    f.seek(0)
                lines = f.read().decode("utf-8", errors="ignore").strip().splitlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        try:
                            rec = json.loads(last_line)
                            self.last_index = rec.get("index", 0)
                            self.last_hash = rec.get("hash", "0" * 64)
                        except Exception as e:
                            logger.warning(f"Failed to parse last ledger record: {e}")
            logger.info(f"Baseline synchronized: Head index #{self.last_index}, offset: {self.file_pos} bytes.")
        except Exception as e:
            logger.error(f"Error reading initial tail position: {e}")
            self.file_pos = 0


    async def heartbeat_loop(self):
        """Emits periodic heartbeats to maintain remote witness dead-man switch."""
        while self.running:
            try:
                if self.nc and self.nc.is_connected:
                    payload = {
                        "source": NODE_ID,
                        "timestamp": time.time(),
                        "head_index": self.last_index,
                        "head_hash": self.last_hash,
                        "total_published": self.total_published
                    }
                    await self.nc.publish(HEARTBEAT_TOPIC, json.dumps(payload).encode("utf-8"))
                    logger.debug(f"Heartbeat emitted: Head #{self.last_index}")
            except Exception as e:
                logger.debug(f"Heartbeat publish error: {e}")

            await asyncio.sleep(HEARTBEAT_INTERVAL_SEC)

    async def tail_ledger_loop(self):
        """Monitors local vault file for new records and publishes them across the network with offset backpressure."""
        while self.running:
            if not os.path.exists(self.vault_path):
                await asyncio.sleep(2)
                continue

            try:
                file_size = os.path.getsize(self.vault_path)
                # Handle log rotation or file truncation
                if file_size < self.file_pos:
                    logger.warning("Vault file truncation detected. Resetting offset to 0.")
                    self.file_pos = 0

                if file_size > self.file_pos:
                    # Enforce backpressure: hold read offset until NATS transport is connected
                    if not (self.nc and self.nc.is_connected):
                        await asyncio.sleep(0.5)
                        continue

                    with open(self.vault_path, "r", encoding="utf-8") as f:
                        f.seek(self.file_pos)
                        while self.running:
                            line_start_pos = f.tell()
                            line = f.readline()
                            if not line:
                                break

                            clean_line = line.strip()
                            if not clean_line:
                                self.file_pos = f.tell()
                                continue

                            # Check connection before attempting publish
                            if not (self.nc and self.nc.is_connected):
                                logger.warning("NATS transport disconnected mid-batch. Holding offset for retry.")
                                break

                            try:
                                block = json.loads(clean_line)
                            except json.JSONDecodeError as json_err:
                                logger.error(f"Corrupted record at offset {line_start_pos}: {json_err}. Advancing offset past malformed line.")
                                self.file_pos = f.tell()
                                continue

                            try:
                                await self.nc.publish(
                                    WITNESS_BLOCK_TOPIC,
                                    clean_line.encode("utf-8")
                                )
                                self.last_index = block.get("index", self.last_index)
                                self.last_hash = block.get("hash", self.last_hash)
                                self.total_published += 1
                                self.file_pos = f.tell()
                                logger.info(f"Broadcast block #{self.last_index} ({block.get('topic')})")
                            except Exception as pub_err:
                                logger.error(f"Failed to publish block #{block.get('index')}: {pub_err}. Holding offset for retry.")
                                # Do NOT advance self.file_pos; break out to retry this block on next loop iteration
                                break
            except Exception as e:
                logger.error(f"Error reading ledger file: {e}")

            await asyncio.sleep(0.5)

    async def start(self):
        """Launches publisher lifecycle."""
        self.running = True
        self._sync_tail_position()
        await self.connect_nats()

        heartbeat_task = asyncio.create_task(self.heartbeat_loop())
        tail_task = asyncio.create_task(self.tail_ledger_loop())

        try:
            await asyncio.gather(heartbeat_task, tail_task)
        except asyncio.CancelledError:
            pass

    async def stop(self):
        """Gracefully disconnects and terminates publisher."""
        logger.info("Stopping publisher daemon...")
        self.running = False
        if self.nc and self.nc.is_connected:
            await self.nc.drain()
            await self.nc.close()
        logger.info("Publisher stopped cleanly.")


def main():
    publisher = KShieldPublisher()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _sig_handler():
        logger.info("Received termination signal.")
        loop.create_task(publisher.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _sig_handler)
        except NotImplementedError:
            pass

    try:
        loop.run_until_complete(publisher.start())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    main()
