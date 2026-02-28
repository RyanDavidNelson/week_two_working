#!/usr/bin/env python3
"""
eCTF 2026 HSM Setup Script - Phase 1 through 3
================================================
Runs through repo validation, Docker build, secret generation,
HSM firmware builds (HSM_A and HSM_B), and flashes both devices.
Leaves two running HSMs ready for manual testing.

Usage:
    python3 setup_phase3.py <repo_directory> [options]

Examples:
    python3 setup_phase3.py /work/2026-ectf-utd
    python3 setup_phase3.py /work/2026-ectf-utd --skip-docker-rebuild
    python3 setup_phase3.py /work/2026-ectf-utd --cflags "-DENABLE_DEBUG_MESSAGES"
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple


# ── Timing ────────────────────────────────────────────────────────────────────
DEVICE_WAKE_S = 1.0   # seconds to wait after firmware start


# ── Console colours ───────────────────────────────────────────────────────────
class Colors:
    HEADER  = '\033[95m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'


def _hdr(text: str):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(70)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}\n")

def _ok(text: str):  print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")
def _err(text: str): print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")
def _warn(text: str):print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")
def _info(text: str):print(f"{Colors.OKCYAN}ℹ {text}{Colors.ENDC}")


# ── Subprocess helper ─────────────────────────────────────────────────────────
def run_cmd(cmd: List[str], timeout: Optional[float] = None,
            cwd: Optional[Path] = None) -> Tuple[bool, str, float]:
    """Run a command; return (success, combined_output, elapsed_seconds)."""
    start = time.time()
    try:
        result = subprocess.run(
            cmd, cwd=cwd,
            capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output, elapsed
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout}s", time.time() - start
    except Exception as exc:
        return False, f"Error: {exc}", time.time() - start


# ── GPIO helpers (optional bridge) ───────────────────────────────────────────
def _bridge_active(bridge_dir: Path) -> bool:
    return bridge_dir.exists() and Path("/tmp/pico_input_in").exists()


def _gpio(bridge_dir: Path, gpio_cmd: str) -> bool:
    ok, _, _ = run_cmd(
        ["uv", "run", "--with", "pyserial", "python", "pico_gpio.py",
         "--batch", gpio_cmd, "--delay-ms", "100", "--no-wait"],
        cwd=bridge_dir, timeout=5
    )
    return ok


def device_enter_update_mode(bridge_dir: Path, is_d1: bool) -> bool:
    if not _bridge_active(bridge_dir):
        return False
    gpio_cmd = ("off 7; off 6; on 6; on 7; input 7; input 6"
                if is_d1 else
                "off 8; off 9; on 9; on 8; input 8; input 9")
    ok = _gpio(bridge_dir, gpio_cmd)
    if ok:
        time.sleep(1.0)
    return ok


def device_reboot(bridge_dir: Path, is_d1: bool) -> bool:
    if not _bridge_active(bridge_dir):
        return False
    gpio_cmd = ("input 7; off 6; on 6; input 6"
                if is_d1 else
                "input 8; off 9; on 9; input 9")
    ok = _gpio(bridge_dir, gpio_cmd)
    if ok:
        time.sleep(1.0)
    return ok


def wait_for_bootloader(port: str, timeout: float = 5.0) -> bool:
    start = time.time()
    max_iters = int(timeout / 0.5) + 1
    for _i in range(max_iters):
        if time.time() - start >= timeout:
            break
        ok, _, _ = run_cmd(["uvx", "ectf", "hw", port, "status"], timeout=2)
        if ok:
            return True
        time.sleep(0.5)
    return False


# ── Build steps ───────────────────────────────────────────────────────────────
def validate_repo(repo: Path) -> bool:
    required = [
        "firmware",
        "firmware/Dockerfile",
        "ectf26_design",
        "ectf26_design/src",
        "ectf26_design/src/gen_secrets.py",
        "ectf26_design/pyproject.toml",
    ]
    missing = [p for p in required if not (repo / p).exists()]
    if missing:
        _err("Missing required paths:\n  " + "\n  ".join(missing))
        return False
    _ok("Repository structure valid")
    return True


def build_docker(repo: Path, skip_if_exists: bool) -> bool:
    # Check existing image
    ok, out, _ = run_cmd(["docker", "images", "-q", "build-hsm"], timeout=10)
    if skip_if_exists and ok and out.strip():
        _ok("Reusing existing Docker image 'build-hsm'")
        return True

    _info("Building Docker image (this may take a few minutes)…")
    ok, out, dur = run_cmd(
        ["docker", "build", "-t", "build-hsm", "."],
        cwd=repo / "firmware", timeout=600
    )
    if ok:
        _ok(f"Docker image built in {dur:.1f}s")
    else:
        _err(f"Docker build failed:\n{out}")
    return ok


def generate_secrets(repo: Path, groups: List[str], secrets_file: Path) -> bool:
    _info(f"Generating secrets for groups: {', '.join(groups)}")

    # Ensure venv exists
    if not (repo / ".venv").exists():
        run_cmd(["uv", "venv"], cwd=repo, timeout=30)

    # Install design package
    ok, out, _ = run_cmd(
        ["uv", "pip", "install", "-e", "./ectf26_design/"],
        cwd=repo, timeout=60
    )
    if not ok:
        _err(f"Failed to install design package:\n{out}")
        return False

    # Generate secrets
    ok, out, dur = run_cmd(
        ["uv", "run", "secrets", str(secrets_file)] + groups,
        cwd=repo, timeout=30
    )
    if ok and secrets_file.exists():
        _ok(f"Secrets generated in {dur:.2f}s → {secrets_file}")
        return True
    _err(f"Secrets generation failed:\n{out}")
    return False


def build_hsm(repo: Path, secrets_file: Path, pin: str, permissions: str,
              output_dir: Path, cflags: Optional[str]) -> bool:
    _info(f"Building HSM  PIN={pin}  PERMS={permissions}")

    cmd = [
        "docker", "run", "--rm",
        "-u", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{repo / 'firmware'}:/hsm",
        "-v", f"{secrets_file}:/secrets/global.secrets:ro",
        "-v", f"{output_dir}:/out",
        "-e", f"HSM_PIN={pin}",
        "-e", f"PERMISSIONS={permissions}",
    ]
    if cflags:
        cmd += ["-e", f"CFLAGS={cflags}"]
    cmd.append("build-hsm")

    ok, out, dur = run_cmd(cmd, timeout=120)
    hsm_bin = output_dir / "hsm.bin"
    if ok and hsm_bin.exists():
        _ok(f"Firmware built in {dur:.1f}s → {hsm_bin}")
        return True
    _err(f"Firmware build failed:\n{out}")
    return False


def flash_hsm(port: str, hsm_bin: Path, name: str,
              bridge_dir: Path, is_d1: bool) -> bool:
    _info(f"Flashing {name} to {port}…")

    if not Path(port).exists():
        _err(f"Device not found at {port}")
        return False

    # Enter update mode
    if _bridge_active(bridge_dir):
        _info("Entering update mode via GPIO…")
        if device_enter_update_mode(bridge_dir, is_d1):
            if not wait_for_bootloader(port):
                _warn("Bootloader not ready; erase may fail")
        else:
            _warn("GPIO failed – manually hold PB21 and tap NRST")
            time.sleep(2)
    else:
        _warn("Bridge not available – manually hold PB21 and tap NRST")
        time.sleep(2)

    # Erase (one retry)
    ok, out, _ = run_cmd(["uvx", "ectf", "hw", port, "erase"], timeout=30)
    if not ok:
        _warn(f"Erase failed: {out.strip()} – retrying…")
        if _bridge_active(bridge_dir):
            device_reboot(bridge_dir, is_d1)
            time.sleep(0.5)
            device_enter_update_mode(bridge_dir, is_d1)
            wait_for_bootloader(port)
        ok, out, _ = run_cmd(["uvx", "ectf", "hw", port, "erase"], timeout=30)
        if not ok:
            _warn(f"Erase still failing: {out.strip()} – continuing anyway")

    # Flash (up to 2 attempts for EBUSY)
    flash_ok = False
    flash_out = ""
    max_flash_attempts = 2
    for attempt_i in range(max_flash_attempts):
        if attempt_i > 0:
            time.sleep(1.0)
        flash_ok, flash_out, _ = run_cmd(
            ["uvx", "ectf", "hw", port, "flash", str(hsm_bin), "-n", name],
            timeout=60
        )
        if flash_ok:
            break
        if "Device or resource busy" not in flash_out and "Errno 16" not in flash_out:
            break  # Non-transient error; stop early

    if not flash_ok:
        _err(f"Flash failed:\n{flash_out}")
        return False

    # Start application
    ok, out, _ = run_cmd(["uvx", "ectf", "hw", port, "start"], timeout=10)
    if not ok:
        _err(f"Failed to start firmware:\n{out}")
        return False

    time.sleep(DEVICE_WAKE_S)
    _ok(f"{name} running on {port}")
    return True


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="eCTF 2026 setup: validate, build, and flash two HSM devices (phases 1-3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("repo_path", help="Path to the HSM design repository")
    parser.add_argument("--dev1", default="/work/d1",
                        help="Device port for HSM_A (default: /work/d1)")
    parser.add_argument("--dev2", default="/work/d2",
                        help="Device port for HSM_B (default: /work/d2)")
    parser.add_argument("--bridge-dir", default="/work/2026-ectf-utd/bridge",
                        help="Path to bridge directory for GPIO control")
    parser.add_argument("--skip-docker-rebuild", action="store_true",
                        help="Reuse existing 'build-hsm' Docker image")
    parser.add_argument("--cflags", default=None,
                        help="Extra CFLAGS for firmware build (e.g. -DENABLE_DEBUG_MESSAGES)")
    parser.add_argument("--pin-a", default="123abc",
                        help="PIN for HSM_A (default: 123abc)")
    parser.add_argument("--pin-b", default="456def",
                        help="PIN for HSM_B (default: 456def)")
    parser.add_argument("--perms-a", default="0x1111=-W-:0x2222=R--",
                        help="Permission string for HSM_A")
    parser.add_argument("--perms-b", default="0x1111=R-C:0x2222=-W-",
                        help="Permission string for HSM_B")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Keep the temp build directory after completion")
    args = parser.parse_args()

    repo       = Path(args.repo_path).resolve()
    bridge_dir = Path(args.bridge_dir)
    groups     = ["0x1111", "0x2222", "0x3333", "0x4444"]

    # ── Phase 1: Validate + Docker + Secrets ──────────────────────────────────
    _hdr("Phase 1: Repository and Build Validation")

    if not validate_repo(repo):
        sys.exit(1)

    if not build_docker(repo, args.skip_docker_rebuild):
        sys.exit(1)

    tmp_dir      = tempfile.mkdtemp(prefix="ectf_setup_")
    secrets_file = Path(tmp_dir) / "global.secrets"

    if not generate_secrets(repo, groups, secrets_file):
        sys.exit(1)

    # ── Phase 2: Build firmware images ────────────────────────────────────────
    _hdr("Phase 2: Building HSM Firmware")

    hsm_a_dir = Path(tmp_dir) / "hsm_a"
    hsm_a_dir.mkdir()
    if not build_hsm(repo, secrets_file, args.pin_a, args.perms_a,
                     hsm_a_dir, args.cflags):
        sys.exit(1)

    hsm_b_dir = Path(tmp_dir) / "hsm_b"
    hsm_b_dir.mkdir()
    if not build_hsm(repo, secrets_file, args.pin_b, args.perms_b,
                     hsm_b_dir, args.cflags):
        sys.exit(1)

    # ── Phase 3: Flash ────────────────────────────────────────────────────────
    _hdr("Phase 3: Flashing Firmware to Devices")

    if not flash_hsm(args.dev1, hsm_a_dir / "hsm.bin",
                     "HSM_A", bridge_dir, is_d1=True):
        sys.exit(1)

    if not flash_hsm(args.dev2, hsm_b_dir / "hsm.bin",
                     "HSM_B", bridge_dir, is_d1=False):
        sys.exit(1)

    # ── Done ──────────────────────────────────────────────────────────────────
    _hdr("Setup Complete")
    print(f"""
  Two devices are now running and ready for manual testing.

  HSM_A  ({args.dev1})
    PIN         : {args.pin_a}
    Permissions : {args.perms_a}

  HSM_B  ({args.dev2})
    PIN         : {args.pin_b}
    Permissions : {args.perms_b}

  Temp build dir: {tmp_dir}
  (pass --no-cleanup to keep it, or delete manually when done)
    """)

    if not args.no_cleanup:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
        _info("Temp directory cleaned up.")


if __name__ == "__main__":
    main()
