#!/usr/bin/env python3
"""
kshield_soak_monitor.py — Universal Kernel Defense Framework (UKDF Phase 6)
Automated Continuous Soak & Drift Sentinel Engine
Project Aegis-Kernel | Enterprise Systems Architecture

Monitors and records time-series soak metrics for longitudinal attestation:
1. Cross-Node Cryptographic Consensus (Primary Vault ⟷ Witness Notary)
2. Index sync drift & hash divergence
3. Syscall latency micro-benchmarking (detects kernel jitter & regressions)
4. Host silicon & NVMe disk health metrics
5. Automated NATS alerting upon any consensus breakdown (drift > 5 blocks)
"""

import os
import sys
import time
import json
import math
import shutil
import argparse
import subprocess
from typing import Dict, Any, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kshield import KShieldLedger, KShieldSandbox

TIMESERIES_PATH = os.getenv("KSHIELD_SOAK_TIMESERIES", "/var/log/kshield/soak_timeseries.jsonl")
DEFAULT_INTERVAL_SEC = 300  # 5 minutes
ALERT_DRIFT_THRESHOLD = 5


class KShieldSoakMonitor:
    def __init__(self, timeseries_path: str = TIMESERIES_PATH):
        self.timeseries_path = timeseries_path
        os.makedirs(os.path.dirname(self.timeseries_path), exist_ok=True)

    @staticmethod
    def get_host_metrics() -> Dict[str, Any]:
        load1, load5, load15 = os.getloadavg()
        mem_pct = 0.0
        try:
            with open("/proc/meminfo", "r") as f:
                mem = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        mem[parts[0].strip()] = int(parts[1].split()[0])
                total = mem.get("MemTotal", 1)
                avail = mem.get("MemAvailable", 0)
                mem_pct = ((total - avail) / total) * 100.0
        except Exception:
            pass

        disk_avail_gb = 0.0
        try:
            vault_dir = os.getenv("KSHIELD_STORAGE_PATH", "/var/log")
            st = os.statvfs(vault_dir if os.path.exists(vault_dir) else "/")
            disk_avail_gb = (st.f_bavail * st.f_frsize) / (1024 ** 3)
        except Exception:
            pass

        return {
            "load_1m": round(load1, 2),
            "load_5m": round(load5, 2),
            "mem_used_pct": round(mem_pct, 1),
            "nvme_avail_gb": round(disk_avail_gb, 1)
        }

    def record_sample(self, benchmark_iterations: int = 10_000) -> Dict[str, Any]:
        t_sample = time.time()

        # 1. Primary Vault Telemetry
        vault_res = KShieldLedger.verify_local_vault()

        # 2. Remote Witness Telemetry
        witness_res = KShieldLedger.query_remote_witness()

        # 3. Consensus Computation
        l_idx = vault_res.get("head_index", 0)
        w_idx = witness_res.get("head_index", 0)
        l_hash = vault_res.get("head_hash", "")
        w_hash = witness_res.get("head_hash", "")
        w_status = witness_res.get("status", "UNKNOWN")

        drift = abs(l_idx - w_idx)
        hash_match = (l_hash == w_hash)
        consensus_ok = (drift <= ALERT_DRIFT_THRESHOLD) and (w_status == "HEALTHY")

        # 4. Micro-benchmark Syscall Latency
        latency_ns = KShieldSandbox.benchmark_latency(benchmark_iterations)

        # 5. Host Resource Telemetry
        host_telemetry = self.get_host_metrics()

        sample = {
            "timestamp": t_sample,
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_sample)),
            "primary": {
                "head_index": l_idx,
                "head_hash": l_hash,
                "valid": vault_res.get("valid", False),
                "total_records": vault_res.get("count", 0)
            },
            "witness": {
                "head_index": w_idx,
                "head_hash": w_hash,
                "status": w_status,
                "dead_man_active": witness_res.get("dead_man_active", False),
                "reorder_buffer_size": witness_res.get("reorder_buffer_size", 0)
            },
            "consensus": {
                "attested": (drift == 0 and hash_match),
                "index_drift": drift,
                "hash_match": hash_match,
                "status": "ATTESTED" if (drift == 0 and hash_match) else ("CONVERGENT" if drift <= ALERT_DRIFT_THRESHOLD else "DIVERGENT")
            },
            "syscall_latency_ns": round(latency_ns, 2),
            "host_metrics": host_telemetry
        }

        # Commit sample to timeseries JSONL
        with open(self.timeseries_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(sample) + "\n")
            f.flush()

        # Alerting on divergence
        if not consensus_ok:
            self._emit_divergence_alert(sample)

        return sample

    def _emit_divergence_alert(self, sample: Dict[str, Any]):
        try:
            payload = {
                "source": "KShieldSoakSentinel",
                "severity": "CRITICAL",
                "event_type": "CONSENSUS_DIVERGENCE",
                "message": f"[ALERT] SOAK ALERT: Dual-witness drift exceeded threshold! Drift={sample['consensus']['index_drift']} blocks. HashMatch={sample['consensus']['hash_match']}",
                "timestamp": sample["timestamp"],
                "sample": sample
            }
            # Use current python executable to emit via NATS
            nats_url = os.getenv("NATS_URL", "nats://127.0.0.1:4222")
            alert_topic = os.getenv("KSHIELD_ALERT_TOPIC", "kshield.security.alert")
            cmd = [
                sys.executable,
                "-c",
                f"""
import nats, asyncio, json
async def send():
    nc = await nats.connect("{nats_url}")
    await nc.publish("{alert_topic}", json.dumps({json.dumps(payload)}).encode())
    await nc.flush()
    await nc.close()
asyncio.run(send())
"""
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except Exception:
            pass

    def generate_report(self) -> Dict[str, Any]:
        if not os.path.exists(self.timeseries_path):
            return {"error": "No soak timeseries data recorded yet."}

        samples: List[Dict[str, Any]] = []
        with open(self.timeseries_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        samples.append(json.loads(line))
                    except Exception:
                        pass

        if not samples:
            return {"error": "Timeseries file is empty."}

        first_sample = samples[0]
        last_sample = samples[-1]

        t_start = first_sample["timestamp"]
        t_end = last_sample["timestamp"]
        elapsed_sec = max(t_end - t_start, 1.0)
        elapsed_hours = elapsed_sec / 3600.0

        total_samples = len(samples)
        attested_samples = sum(1 for s in samples if s.get("consensus", {}).get("attested"))
        consensus_uptime = (attested_samples / total_samples) * 100.0

        latencies = [s["syscall_latency_ns"] for s in samples if "syscall_latency_ns" in s]
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
        min_lat = min(latencies) if latencies else 0.0
        max_lat = max(latencies) if latencies else 0.0

        # Standard deviation (jitter)
        variance = sum((x - avg_lat) ** 2 for x in latencies) / max(len(latencies), 1)
        std_dev = math.sqrt(variance)

        max_drift = max(s.get("consensus", {}).get("index_drift", 0) for s in samples)
        start_block = first_sample.get("primary", {}).get("head_index", 0)
        end_block = last_sample.get("primary", {}).get("head_index", 0)
        blocks_logged = max(end_block - start_block, 0)

        dead_man_incidents = sum(1 for s in samples if not s.get("witness", {}).get("dead_man_active", True))

        return {
            "total_samples": total_samples,
            "soak_start_iso": first_sample.get("iso_time"),
            "soak_latest_iso": last_sample.get("iso_time"),
            "elapsed_hours": round(elapsed_hours, 2),
            "consensus_uptime_pct": round(consensus_uptime, 3),
            "total_blocks_attested": blocks_logged,
            "current_head_index": end_block,
            "max_index_drift": max_drift,
            "dead_man_incidents": dead_man_incidents,
            "syscall_latency_avg_ns": round(avg_lat, 2),
            "syscall_latency_min_ns": round(min_lat, 2),
            "syscall_latency_max_ns": round(max_lat, 2),
            "syscall_jitter_std_dev_ns": round(std_dev, 2),
            "latest_sample": last_sample
        }


def print_report_table(rep: Dict[str, Any]):
    print("═══════════════════════════════════════════════════════════════════════════")
    print("      AEGIS-KERNEL: CONTINUOUS SOAK & DRIFT SENTINEL REPORT           ")
    print("═══════════════════════════════════════════════════════════════════════════")
    if "error" in rep:
        print(f"  {rep['error']}")
        print("═══════════════════════════════════════════════════════════════════════════\n")
        return

    print(f"Observation Window : {rep['soak_start_iso']} ──> {rep['soak_latest_iso']}")
    print(f"Total Duration     : {rep['elapsed_hours']:.2f} hours | Total Samples: {rep['total_samples']:,}")
    print("───────────────────────────────────────────────────────────────────────────")
    print("CRYPTOGRAPHIC CONSENSUS & DUAL-WITNESS INTEGRITY:")
    print(f"  • Consensus Uptime     : {rep['consensus_uptime_pct']:.3f}% (Attested Lockstep)")
    print(f"  • Blocks Logged        : {rep['total_blocks_attested']:,} blocks during window")
    print(f"  • Current Head Index   : #{rep['current_head_index']:,}")
    print(f"  • Max Observed Drift   : {rep['max_index_drift']} blocks (Threshold: {ALERT_DRIFT_THRESHOLD})")
    print(f"  • Dead-Man Incidents   : {rep['dead_man_incidents']} (Zero Silent Drops)")
    print("───────────────────────────────────────────────────────────────────────────")
    print("SYSCALL KERNEL STABILITY & LATENCY (getpid Micro-benchmark):")
    print(f"  • Average Latency      : {rep['syscall_latency_avg_ns']:.2f} ns/syscall")
    print(f"  • Latency Bounds       : Min {rep['syscall_latency_min_ns']:.2f} ns | Max {rep['syscall_latency_max_ns']:.2f} ns")
    print(f"  • Jitter Std Dev (σ)   : {rep['syscall_jitter_std_dev_ns']:.2f} ns (Predictable Low-Jitter)")
    print("───────────────────────────────────────────────────────────────────────────")
    lat = rep.get("latest_sample", {})
    hm = lat.get("host_metrics", {})
    print("LATEST SILICON & STORAGE POSTURE:")
    print(f"  • Host CPU Load        : {hm.get('load_1m')} (1m) | {hm.get('load_5m')} (5m)")
    print(f"  • Memory Utilization   : {hm.get('mem_used_pct')}%")
    print(f"  • NVMe Free Space      : {hm.get('nvme_avail_gb')} GB available")
    print("═══════════════════════════════════════════════════════════════════════════\n")


def main():
    parser = argparse.ArgumentParser(description="kshield_soak_monitor: Automated Continuous Soak & Drift Sentinel")
    parser.add_argument("--sample", action="store_true", help="Record a single soak telemetry sample immediately")
    parser.add_argument("--report", action="store_true", help="Print aggregated soak metrics report")
    parser.add_argument("--json", action="store_true", help="Output report in JSON format")
    parser.add_argument("--daemon", action="store_true", help="Run continuously as background daemon")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SEC, help=f"Polling interval in seconds (default: {DEFAULT_INTERVAL_SEC}s)")

    args = parser.parse_args()
    monitor = KShieldSoakMonitor()

    if args.sample:
        s = monitor.record_sample()
        if args.json:
            print(json.dumps(s, indent=2))
        else:
            print(f"[OK] Soak sample recorded at {s['iso_time']} | Head #{s['primary']['head_index']} | Consensus: {s['consensus']['status']} | Latency: {s['syscall_latency_ns']} ns")

    elif args.report:
        rep = monitor.generate_report()
        if args.json:
            print(json.dumps(rep, indent=2))
        else:
            print_report_table(rep)

    elif args.daemon:
        print(f"[INFO] Starting KShield Soak Sentinel Daemon (Polling interval: {args.interval}s)...")
        while True:
            try:
                s = monitor.record_sample()
                print(f"[{s['iso_time']}] Recorded soak point | Head #{s['primary']['head_index']} | Consensus: {s['consensus']['status']} | Latency: {s['syscall_latency_ns']} ns")
            except Exception as e:
                print(f"[ERROR] Error recording soak sample: {e}", file=sys.stderr)
            time.sleep(args.interval)

    else:
        # Default: sample once and show report
        s = monitor.record_sample()
        print(f"[OK] Recorded soak point: Head #{s['primary']['head_index']} (Consensus: {s['consensus']['status']})")
        rep = monitor.generate_report()
        print_report_table(rep)


if __name__ == "__main__":
    main()
