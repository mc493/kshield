# Contributing to Project Aegis-Kernel (`kshield`)

Thank you for your interest in contributing to this defense-in-depth Linux kernel attack surface hardening framework!

---

## Core Engineering Invariants

`kshield` is designed for production bare-metal and Kubernetes environments. All contributions must respect these principles:

1. **Zero-Downtime & Non-Disruptive:**
   - Controls must apply to running systems without requiring host reboots.
   - Mitigations must not disrupt legitimate production workloads (zero POSIX regressions).
   - Module disarmament must be fail-closed (`install <module> /bin/true`).

2. **Zero-Dependency CLI Standard:**
   - The core CLI (`bin/kshield`) must strictly rely on Python 3 standard library and libc `ctypes`.
   - External third-party package dependencies (PyPI packages) in the core CLI are prohibited.

3. **Multi-Architecture Parity:**
   - All syscall filters and probes must explicitly account for architecture ABI differences between `x86_64` and `aarch64` / `arm64`.

4. **Verification Gate:**
   - Any added control or bug fix must pass `kshield verify-sandbox` and `kshield status` with 100% operational integrity.

---

## Development Workflow

1. **Fork and Clone:**
   ```bash
   git clone https://github.com/mc493/kshield.git
   cd kshield
   ```

2. **Create a Feature Branch:**
   ```bash
   git checkout -b feature/new-mitigation
   ```

3. **Test Mitigations Locally:**
   ```bash
   python3 bin/kshield status
   python3 bin/kshield audit
   python3 bin/kshield verify-sandbox
   ```

4. **Submit a Pull Request:**
   - Target the `main` branch.
   - Provide reproduction evidence and testing transcripts.

---

## Commit Conventions

This project follows [Conventional Commits](https://www.conventionalcommits.org/):
* `feat:` A new compensating control, module blocklist, or CLI command.
* `fix:` A bug fix or false-positive remediation.
* `docs:` Documentation improvements or architectural analyses.
* `refactor:` Code restructuring without functional changes.
