#!/usr/bin/env python3
"""
Unit and integration test suite for kshield (Project Aegis-Kernel).
Evaluates sysctl generation, modprobe disarm syntax, cryptographic ledger
integrity, snapshot attestation, posture scoring, and seccomp profile validity.

Zero external dependencies: relies exclusively on Python standard library unittest.
"""

import os
import sys
import json
import shutil
import tempfile
import hashlib
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec

# Dynamically import bin/kshield CLI core without requiring .py extension
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KSHIELD_PATH = os.path.join(REPO_ROOT, "bin", "kshield")

loader = SourceFileLoader("kshield", KSHIELD_PATH)
spec = spec_from_loader("kshield", loader)
kshield = module_from_spec(spec)
loader.exec_module(kshield)


class TestSysctlConfiguration(unittest.TestCase):
    """Validates sysctl configuration generator across operational profiles."""

    def test_container_host_profile(self):
        """Verifies default container-host profile enforces baseline sysctls without disabling UserNS."""
        cfg = kshield.KShieldDisarm.generate_sysctl_config(profile="container-host")
        self.assertIn("UKDF / Aegis-Kernel: Automated Sysctl Defense Baseline", cfg)
        self.assertIn("kernel.unprivileged_bpf_disabled = 1", cfg)
        self.assertIn("kernel.kptr_restrict = 2", cfg)
        self.assertIn("kernel.dmesg_restrict = 1", cfg)
        self.assertIn("kernel.yama.ptrace_scope = 2", cfg)
        self.assertIn("kernel.kexec_load_disabled = 1", cfg)
        self.assertIn("vm.unprivileged_userfaultfd = 0", cfg)
        self.assertIn("fs.protected_symlinks = 1", cfg)
        self.assertIn("fs.protected_hardlinks = 1", cfg)
        self.assertIn("fs.protected_fifos = 2", cfg)
        self.assertIn("fs.protected_regular = 2", cfg)
        self.assertIn("kernel.perf_event_paranoid = 2", cfg)
        # Verify user.max_user_namespaces is NOT disabled in container-host mode
        self.assertNotIn("user.max_user_namespaces", cfg)

    def test_strict_host_profile(self):
        """Verifies strict-host profile disables unprivileged user namespaces."""
        cfg = kshield.KShieldDisarm.generate_sysctl_config(profile="strict-host")
        self.assertIn("kernel.unprivileged_bpf_disabled = 1", cfg)
        self.assertIn("user.max_user_namespaces = 0", cfg)
        self.assertIn("# Profile: strict-host", cfg)


class TestModprobeConfiguration(unittest.TestCase):
    """Validates modprobe disarm configuration generator."""

    def test_empty_module_list(self):
        """Verifies empty module list outputs header without install directives."""
        cfg = kshield.KShieldDisarm.generate_modprobe_config([])
        self.assertIn("UKDF / Aegis-Kernel: Automated Universal Modprobe Sealing Configuration", cfg)
        self.assertNotIn("install ", cfg)
        self.assertNotIn("blacklist ", cfg)

    def test_module_disarm_rules(self):
        """Verifies both install /bin/true and blacklist directives are generated."""
        modules = ["dccp", "cramfs", "firewire-core"]
        cfg = kshield.KShieldDisarm.generate_modprobe_config(modules)
        for mod in modules:
            self.assertIn(f"install {mod} /bin/true", cfg)
            self.assertIn(f"blacklist {mod}", cfg)


class TestPostureScoring(unittest.TestCase):
    """Validates posture calculation and scoring engine weighting."""

    def test_perfect_score_container_host(self):
        """Verifies container host with all sysctls active and zero unsealed modules receives high score."""
        sysctl_total = sum(v["weight"] for v in kshield.SYSCTL_TARGETS.values())
        sysctl_earned = sysctl_total
        mod_summary = {"active_risk_modules_in_ram": 0, "dormant_reachable_modules": 0}
        boundaries = {
            "container_runtime_present": True,
            "user_namespaces_enabled": True,
            "seccomp_supported": True,
            "active_lsms": ["bpf", "apparmor"],
            "read_only_root": True
        }

        score = kshield.KShieldAudit.compute_posture_score(
            sysctl_earned, sysctl_total, mod_summary, boundaries
        )
        self.assertGreaterEqual(score, 90)
        self.assertLessEqual(score, 100)

    def test_score_bounds_and_clamping(self):
        """Verifies posture score cannot exceed 100 or fall below 0."""
        score_high = kshield.KShieldAudit.compute_posture_score(
            sysctl_earned=1000,
            sysctl_total=10,
            mod_summary={"unsealed": 0, "sealed": 100, "dormant": 0},
            boundaries={"container_runtime": True, "user_namespaces": True, "lsm": ["SELinux"]}
        )
        self.assertEqual(score_high, 100)

        score_low = kshield.KShieldAudit.compute_posture_score(
            sysctl_earned=0,
            sysctl_total=100,
            mod_summary={"unsealed": 50, "sealed": 0, "dormant": 0},
            boundaries={"container_runtime": False, "user_namespaces": False, "lsm": []}
        )
        self.assertGreaterEqual(score_low, 0)


class TestLedgerIntegrity(unittest.TestCase):
    """Validates cryptographic ledger hash chaining and tamper detection."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="kshield_test_ledger_")
        self.vault_file = os.path.join(self.temp_dir, "test_ledger.jsonl")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _generate_valid_ledger(self, record_count=10):
        records = []
        prev_hash = "0" * 64
        for idx in range(record_count):
            timestamp = 1727400000.0 + idx
            topic = "test.security.event"
            data = {"action": "probe", "index": idx, "status": "ok"}
            rec_hash = kshield.KShieldLedger.compute_hash(idx, timestamp, topic, data, prev_hash)
            record = {
                "index": idx,
                "timestamp": timestamp,
                "topic": topic,
                "data": data,
                "prev_hash": prev_hash,
                "hash": rec_hash
            }
            records.append(record)
            prev_hash = rec_hash

        with open(self.vault_file, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

    def test_valid_ledger_full_and_tail_verification(self):
        """Verifies unmodified ledger passes full sequential and fast-tail verification."""
        self._generate_valid_ledger(15)

        # Full sequential scan
        res_full = kshield.KShieldLedger.verify_local_vault(self.vault_file, full_scan=True)
        self.assertTrue(res_full["valid"])
        self.assertEqual(res_full["count"], 15)
        self.assertEqual(res_full["head_index"], 14)

        # Fast tail scan
        res_tail = kshield.KShieldLedger.verify_local_vault(self.vault_file, full_scan=False)
        self.assertTrue(res_tail["valid"])
        self.assertEqual(res_tail["head_index"], 14)

    def test_tampered_ledger_detection(self):
        """Verifies full scan flags corrupted record payloads and broken hash chains."""
        self._generate_valid_ledger(10)

        # Tamper with record #5 payload without updating hash
        with open(self.vault_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        tampered_rec = json.loads(lines[5])
        tampered_rec["data"]["action"] = "malicious_modification"
        lines[5] = json.dumps(tampered_rec) + "\n"

        with open(self.vault_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        res = kshield.KShieldLedger.verify_local_vault(self.vault_file, full_scan=True)
        self.assertFalse(res["valid"])
        self.assertIn("error", res)


class TestSnapshotAttestation(unittest.TestCase):
    """Validates transactional recovery snapshot creation and SHA-256 digest validation."""

    def setUp(self):
        self.temp_root = tempfile.mkdtemp(prefix="kshield_test_snap_")
        self.orig_snapshot_dir = kshield.SNAPSHOT_DIR
        kshield.SNAPSHOT_DIR = os.path.join(self.temp_root, "snapshots")
        os.makedirs(kshield.SNAPSHOT_DIR, exist_ok=True)

    def tearDown(self):
        kshield.SNAPSHOT_DIR = self.orig_snapshot_dir
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def test_snapshot_attestation_metadata(self):
        """Verifies snapshot generation records SHA-256 digests in metadata."""
        snap_id = "test_snap_001"
        target_dir = kshield.KShieldDisarm.create_snapshot(snap_id)

        self.assertTrue(os.path.isdir(target_dir))
        meta_file = os.path.join(target_dir, "metadata.json")
        self.assertTrue(os.path.exists(meta_file))

        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertEqual(meta["snapshot_id"], snap_id)
        self.assertIn("file_digests", meta)
        self.assertIsInstance(meta["file_digests"], dict)

        # Verify recorded hashes match actual files
        for rel_path, expected_hash in meta["file_digests"].items():
            full_path = os.path.join(target_dir, rel_path)
            self.assertTrue(os.path.exists(full_path))
            with open(full_path, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(expected_hash, actual_hash)


class TestSeccompProfileIntegrity(unittest.TestCase):
    """Validates Seccomp profile JSON syntax and security invariants."""

    def setUp(self):
        self.profile_path = os.path.join(REPO_ROOT, "profiles", "seccomp-kshield-default.json")

    def test_profile_exists_and_valid_json(self):
        """Verifies profile file exists and contains valid JSON."""
        self.assertTrue(os.path.isfile(self.profile_path))
        with open(self.profile_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)

    def test_profile_structure(self):
        """Verifies targeted exploit gating structure, default allow, and blocked syscall rules."""
        with open(self.profile_path, "r", encoding="utf-8") as f:
            profile = json.load(f)

        # Verify defaultAction is SCMP_ACT_ALLOW (surgical deny-list architecture)
        self.assertEqual(profile.get("defaultAction"), "SCMP_ACT_ALLOW")

        # Verify multi-architecture support
        archs = profile.get("architectures", [])
        self.assertIn("SCMP_ARCH_X86_64", archs)
        self.assertIn("SCMP_ARCH_AARCH64", archs)

        # Extract blocked syscall names
        blocked_syscalls = set()
        for rule in profile.get("syscalls", []):
            if rule.get("action") == "SCMP_ACT_ERRNO":
                for name in rule.get("names", []):
                    blocked_syscalls.add(name)

        # Verify critical exploit primitives are blocked
        self.assertIn("io_uring_setup", blocked_syscalls)
        self.assertIn("io_uring_enter", blocked_syscalls)
        self.assertIn("io_uring_register", blocked_syscalls)
        self.assertIn("userfaultfd", blocked_syscalls)
        self.assertIn("kexec_load", blocked_syscalls)
        self.assertIn("reboot", blocked_syscalls)


class TestCliParsing(unittest.TestCase):
    """Validates CLI command and argument parsing logic."""

    def setUp(self):
        self.parser = kshield.build_parser()

    def test_status_command(self):
        """Verifies status command parsing."""
        args = self.parser.parse_args(["status"])
        self.assertEqual(args.command, "status")

    def test_disarm_command_defaults(self):
        """Verifies disarm command defaults to container-host profile and active ICMP checks."""
        args = self.parser.parse_args(["disarm"])
        self.assertEqual(args.command, "disarm")
        self.assertEqual(args.profile, "container-host")
        self.assertFalse(args.dry_run)
        self.assertFalse(args.no_icmp)

    def test_disarm_command_custom_flags(self):
        """Verifies disarm command honors strict-host profile, dry-run, and no-icmp flags."""
        args = self.parser.parse_args(["disarm", "--dry-run", "--profile", "strict-host", "--no-icmp"])
        self.assertEqual(args.command, "disarm")
        self.assertEqual(args.profile, "strict-host")
        self.assertTrue(args.dry_run)
        self.assertTrue(args.no_icmp)

    def test_verify_ledger_full_flag(self):
        """Verifies verify-ledger parses --full flag."""
        args = self.parser.parse_args(["verify-ledger", "--full"])
        self.assertEqual(args.command, "verify-ledger")
        self.assertTrue(args.full)

    def test_install_seccomp_source_flag(self):
        """Verifies install-seccomp parses custom --source path."""
        args = self.parser.parse_args(["install-seccomp", "--source", "/tmp/custom-profile.json"])
        self.assertEqual(args.command, "install-seccomp")
        self.assertEqual(args.source, "/tmp/custom-profile.json")


if __name__ == "__main__":
    unittest.main()
