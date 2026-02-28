#!/usr/bin/env python3
"""
eCTF 2026 HSM Design Testing Script
=====================================

This script tests an eCTF HSM design against all functional requirements and timing rules.
It tests on two development HSM devices at /work/d1 and /work/d2.

Usage:
    python3 test_hsm_design.py <repo_directory>

Requirements:
    - The repository must follow the mandatory format prescribed in ./rules
    - Must have firmware/ directory with Dockerfile
    - Must have ectf26_design/ directory with gen_secrets.py
    - Docker must be installed and running
    - Two HSM devices connected at /work/d1 and /work/d2
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Optional, Tuple


# Timing requirements from specs (in seconds)
TIMING_REQUIREMENTS = {
    "device_wake": 1.0,
    "list_files": 0.5,
    "read_file": 3.0,
    "write_file": 3.0,
    "receive_file": 3.0,
    "interrogate": 1.0,
    "invalid_pin": 5.0,
}
TIMING_REQUIREMENTS = {k: v * 1 for k, v in TIMING_REQUIREMENTS.items()}


@dataclass
class TestResult:
    """Result of a single test"""
    name: str
    passed: bool
    duration: Optional[float] = None
    message: str = ""
    details: Optional[Dict] = None


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(text: str):
    """Print colored header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(80)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}\n")


def print_success(text: str):
    """Print success message"""
    print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")


def print_failure(text: str):
    """Print failure message"""
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")


def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")


def print_info(text: str):
    """Print info message"""
    print(f"{Colors.OKCYAN}ℹ {text}{Colors.ENDC}")


class HSMTester:
    """Main tester class for HSM designs"""
    
    def __init__(self, repo_path: str, dev1_port: str = "/work/d1", dev2_port: str = "/work/d2",
                 skip_docker_rebuild: bool = False, bridge_dir: str = "/work/2026-ectf-utd/bridge",
                 cflags: Optional[str] = None, power_cycle_serial: bool = False,
                 hub_override: Optional[Dict[str, Tuple[str, str]]] = None,
                 power_cycle_mode: str = "cycle", timeout_multiplier: float = 10.0):
        self.repo_path = Path(repo_path).resolve()
        self.dev1_port = dev1_port
        self.dev2_port = dev2_port
        self.skip_docker_rebuild = skip_docker_rebuild
        self.bridge_dir = Path(bridge_dir)
        self.cflags = cflags
        self.power_cycle_serial = power_cycle_serial
        self.hub_override = hub_override or {}
        self.power_cycle_mode = power_cycle_mode
        self.timeout_multiplier = timeout_multiplier
        self.test_results: List[TestResult] = []
        self.temp_dir = None
        self.build_dir = None
        
    def run_command(self, cmd: List[str], timeout: Optional[float] = None, 
                   capture_output: bool = True, cwd: Optional[Path] = None) -> Tuple[bool, str, float]:
        """
        Run a command and return success status, output, and duration
        
        Returns:
            Tuple of (success, output, duration_seconds)
        """
        start_time = time.time()
        out_path = Path("test.log")
        try:
            if cwd is None:
                cwd = self.repo_path

            with open(out_path, "a") as out_file:
                try:
                    result = subprocess.run(
                        cmd,
                        cwd=cwd,
                        capture_output=capture_output,
                        text=True,
                        timeout=timeout
                    )
                    duration = time.time() - start_time

                    output = ""
                    if capture_output:
                        # Ensure output is always str
                        def to_str(val):
                            if isinstance(val, bytes):
                                return val.decode("utf-8", errors="replace")
                            return val or ""
                        output = to_str(result.stdout) + to_str(result.stderr)
                        out_file.write(f"\n{' '.join(cmd)}\n")
                        out_file.write(output)
                        out_file.write("\n---\n")

                        # Emit all debug output lines
                        import string
                        for line in output.splitlines():
                            if "DEBUG_MSG" in line or "DEBUG" in line:
                                # Try to extract the debug payload (after 'Got DEBUG message: ')
                                if "Got DEBUG message:" in line:
                                    parts = line.split("Got DEBUG message:", 1)
                                    payload = parts[1].strip()
                                    # Remove b'' if present
                                    if payload.startswith("b'") and payload.endswith("'"):
                                        payload = payload[2:-1]
                                    # Try to decode hex if it's a hex string
                                    try:
                                        # Remove spaces and newlines
                                        hexstr = payload.replace(" ", "").replace("\\n", "")
                                        # If it's a valid hex string, decode
                                        if all(c in string.hexdigits for c in hexstr) and len(hexstr) % 2 == 0:
                                            ascii_str = bytes.fromhex(hexstr).decode('ascii', errors='replace')
                                            print(f"[FIRMWARE DEBUG] {line} | ASCII: {ascii_str}")
                                        else:
                                            # Try to decode as ascii directly
                                            ascii_str = bytes(payload, 'utf-8').decode('ascii', errors='replace')
                                            print(f"[FIRMWARE DEBUG] {line} | ASCII: {ascii_str}")
                                    except Exception:
                                        print(f"[FIRMWARE DEBUG] {line}")
                                else:
                                    print(f"[FIRMWARE DEBUG] {line}")

                    return (result.returncode == 0, output, duration)
                except subprocess.TimeoutExpired as e:
                    duration = time.time() - start_time
                    # Write whatever output was captured before timeout
                    def to_str(val):
                        if isinstance(val, bytes):
                            return val.decode("utf-8", errors="replace")
                        return val or ""
                    output = ""
                    if capture_output:
                        output = to_str(getattr(e, "stdout", ""))
                        if getattr(e, "stderr", None):
                            output += to_str(e.stderr)
                        out_file.write(f"\n{' '.join(cmd)}\n")
                        out_file.write(output)
                        out_file.write(f"\n[COMMAND TIMED OUT AFTER {timeout}s]\n---\n")
                    return (False, f"Command timed out after {timeout}s", duration)
        except Exception as e:
            duration = time.time() - start_time
            # Log the error to the out file as well
            with open(out_path, "a") as out_file:
                out_file.write(f"\n{' '.join(cmd)}\n")
                out_file.write(f"[ERROR] {str(e)}\n---\n")
            return (False, f"Error running command: {str(e)}", duration)
    
    def validate_repo_structure(self) -> TestResult:
        """Validate that the repository has the required structure"""
        print_info("Validating repository structure...")
        
        required_paths = {
            "firmware": "Firmware directory",
            "firmware/Dockerfile": "Firmware Dockerfile",
            "ectf26_design": "Design package directory",
            "ectf26_design/src": "Design package source directory",
            "ectf26_design/src/gen_secrets.py": "Generate secrets script",
            "ectf26_design/pyproject.toml": "Python project configuration",
        }
        
        missing = []
        for path, description in required_paths.items():
            full_path = self.repo_path / path
            if not full_path.exists():
                missing.append(f"{description} ({path})")
        
        if missing:
            msg = "Missing required files/directories:\n  - " + "\n  - ".join(missing)
            return TestResult("Repository Structure", False, message=msg)
        
        return TestResult("Repository Structure", True, 
                         message="All required files and directories present")
    
    def docker_image_exists(self, image_name: str = "build-hsm") -> bool:
        """Check if a Docker image exists"""
        success, output, _ = self.run_command(
            ["docker", "images", "-q", image_name],
            timeout=10
        )
        return success and len(output.strip()) > 0
    
    def device_enter_update_mode(self, device_port: str) -> bool:
        """Put a device into update/bootloader mode using GPIO control"""
        if not self.bridge_dir.exists():
            return False
        
        # Check if pico-uart service is running (pipe exists)
        service_pipe = Path("/tmp/pico_input_in")
        if not service_pipe.exists():
            # Service not running, can't use GPIO control
            return False
        
        # Determine which device (D1 or D2) based on port
        if device_port == self.dev1_port:
            # D1 update mode
            gpio_cmd = "off 7; off 6; on 6; on 7; input 7; input 6"
        else:
            # D2 update mode  
            gpio_cmd = "off 8; off 9; on 9; on 8; input 8; input 9"
        
        success, _, _ = self.run_command(
            ["uv", "run", "--with", "pyserial", "python", "pico_gpio.py", "--batch", gpio_cmd, 
             "--delay-ms", "100", "--no-wait"],
            cwd=self.bridge_dir,
            timeout=5
        )
        
        if success:
            time.sleep(1.0)  # Give device time to enter update mode
        
        return success
    
    def device_reboot(self, device_port: str) -> bool:
        """Reboot a device using GPIO control"""
        if not self.bridge_dir.exists():
            return False
        
        # Check if pico-uart service is running (pipe exists)
        service_pipe = Path("/tmp/pico_input_in")
        if not service_pipe.exists():
            # Service not running, can't use GPIO control
            return False
        
        # Determine which device (D1 or D2) based on port
        if device_port == self.dev1_port:
            # D1 reboot: Release bootloader to high-Z, reset cycle
            gpio_cmd = "input 7; off 6; on 6; input 6"
        else:
            # D2 reboot: Same sequence but for D2 GPIO pins
            gpio_cmd = "input 8; off 9; on 9; input 9"
        
        success, _, _ = self.run_command(
            ["uv", "run", "--with", "pyserial", "python", "pico_gpio.py", "--batch", gpio_cmd,
             "--delay-ms", "100", "--no-wait"],
            cwd=self.bridge_dir,
            timeout=5
        )
        
        if success:
            time.sleep(1.0)  # Give device time to reboot
        
        return success

    def _resolve_tty(self, device_port: str) -> Optional[str]:
        if not device_port:
            return None
        real_path = os.path.realpath(device_port)
        if real_path.startswith("/dev/"):
            return os.path.basename(real_path)
        return None

    def _is_usb_device_name(self, name: str) -> bool:
        if not name or "-" not in name or ":" in name:
            return False
        parts = name.split("-")
        if len(parts) != 2:
            return False
        bus, rest = parts
        if not bus.isdigit():
            return False
        for seg in rest.split("."):
            if not seg.isdigit():
                return False
        return True

    def _find_usb_device_name(self, tty_name: str) -> Optional[str]:
        sys_path = Path("/sys/class/tty") / tty_name / "device"
        if not sys_path.exists():
            return None
        real_path = Path(os.path.realpath(sys_path))
        device_name = None
        for part in real_path.parts:
            if self._is_usb_device_name(part):
                device_name = part
        return device_name

    def _find_usb_device_dir(self, tty_name: str) -> Optional[Path]:
        sys_path = Path("/sys/class/tty") / tty_name / "device"
        if not sys_path.exists():
            return None
        real_path = Path(os.path.realpath(sys_path))
        for part in real_path.parts:
            if self._is_usb_device_name(part):
                candidate = Path("/")
                for seg in real_path.parts:
                    candidate = candidate / seg
                    if seg == part:
                        return candidate
        return None

    def _hub_for_device(self, device_name: str) -> Optional[Tuple[str, str]]:
        if not device_name or "-" not in device_name:
            return None
        if "." in device_name:
            hub_path, port = device_name.rsplit(".", 1)
            return hub_path, port
        bus, port = device_name.split("-", 1)
        return f"{bus}-0", port

    def power_cycle_serial_adapter(self, device_port: str) -> bool:
        tty_name = self._resolve_tty(device_port)
        if not tty_name:
            print_warning(f"USB power cycle skipped for {device_port}: unable to resolve tty")
            return False

        if self.power_cycle_mode == "reset":
            device_dir = self._find_usb_device_dir(tty_name)
            if not device_dir:
                print_warning(f"USB reset skipped for {device_port}: unable to resolve USB device")
                return False
            try:
                busnum = (device_dir / "busnum").read_text().strip()
                devnum = (device_dir / "devnum").read_text().strip()
            except Exception:
                print_warning(f"USB reset skipped for {device_port}: missing bus/dev numbers")
                return False
            dev_path = f"/dev/bus/usb/{int(busnum):03d}/{int(devnum):03d}"
            success, output, _ = self.run_command(
                ["sudo", "python3", "-c",
                 "import fcntl,sys,os; USBDEVFS_RESET=21780; fd=os.open(sys.argv[1], os.O_RDWR); fcntl.ioctl(fd, USBDEVFS_RESET, 0); os.close(fd)",
                 dev_path],
                timeout=5
            )
            if not success:
                usbreset_path = shutil.which("usbreset")
                if usbreset_path:
                    success, output, _ = self.run_command(
                        ["sudo", usbreset_path, dev_path],
                        timeout=5
                    )
            if not success:
                print_warning(f"USB reset failed for {device_port}: {output.strip()}")
            return success

        if device_port in self.hub_override:
            hub_path, port = self.hub_override[device_port]
        else:
            device_name = self._find_usb_device_name(tty_name)
            hub_info = self._hub_for_device(device_name) if device_name else None
            if not hub_info:
                print_warning(f"USB power cycle skipped for {device_port}: unable to resolve hub/port")
                return False
            hub_path, port = hub_info
        uhubctl_path = shutil.which("uhubctl") or "/usr/sbin/uhubctl"
        success, output, _ = self.run_command(
            ["sudo", uhubctl_path, "-l", hub_path, "-p", port, "-a", "cycle"],
            timeout=10
        )
        if not success:
            print_warning(f"USB power cycle failed for {device_port}: {output.strip()}")
        return success

    def wait_for_bootloader(self, device_port: str, timeout: float = 5.0, interval: float = 0.5) -> bool:
        """Wait for the bootloader to respond to status queries"""
        start = time.time()
        while time.time() - start < timeout:
            success, _, _ = self.run_command(
                ["uvx", "ectf", "hw", device_port, "status"],
                timeout=2
            )
            if success:
                return True
            time.sleep(interval)
        return False
    
    def build_docker_image(self) -> TestResult:
        """Build the Docker image for the HSM firmware"""
        
        # Check if image already exists and we can skip rebuild
        if self.skip_docker_rebuild and self.docker_image_exists():
            print_info("Docker image 'build-hsm' already exists, skipping rebuild...")
            return TestResult("Docker Build", True, duration=0.0,
                            message=f"Reusing existing Docker image 'build-hsm'")
        
        print_info("Building Docker image...")
        
        firmware_dir = self.repo_path / "firmware"
        success, output, duration = self.run_command(
            ["docker", "build", "-t", "build-hsm", "."],
            cwd=firmware_dir,
            timeout=600  # 10 minute timeout
        )
        
        if success:
            return TestResult("Docker Build", True, duration=duration,
                            message=f"Docker image built successfully in {duration:.1f}s")
        else:
            return TestResult("Docker Build", False, duration=duration,
                            message=f"Failed to build Docker image:\n{output}")
    
    def generate_secrets(self, groups: List[str]) -> TestResult:
        """Generate global secrets for the deployment"""
        print_info(f"Generating secrets for groups: {', '.join(groups)}...")
        
        # Create temporary directory for build artifacts
        self.temp_dir = tempfile.mkdtemp(prefix="ectf_test_")
        secrets_file = Path(self.temp_dir) / "global.secrets"
        
        # Create a virtual environment in the repo if it doesn't exist
        venv_path = self.repo_path / ".venv"
        if not venv_path.exists():
            print_info("Creating virtual environment...")
            venv_success, venv_output, _ = self.run_command(
                ["uv", "venv"],
                timeout=30
            )
            if not venv_success:
                print_warning(f"Failed to create venv, will try without: {venv_output}")
        
        # Step 1: Install the design package (following boot_reference.html)
        print_info("Installing design package...")
        install_success, install_output, _ = self.run_command(
            ["uv", "pip", "install", "-e", "./ectf26_design/"],
            timeout=60
        )
        
        if not install_success:
            return TestResult("Generate Secrets", False,
                            message=f"Failed to install design package:\n{install_output}")
        
        # Step 2: Generate secrets using uv run (following boot_reference.html)
        print_info("Running secrets generation...")
        success, output, duration = self.run_command(
            ["uv", "run", "secrets", str(secrets_file)] + groups,
            timeout=30
        )
        
        if success and secrets_file.exists():
            self.secrets_file = secrets_file
            return TestResult("Generate Secrets", True, duration=duration,
                            message=f"Secrets generated successfully in {duration:.2f}s")
        else:
            return TestResult("Generate Secrets", False, duration=duration,
                            message=f"Failed to generate secrets:\n{output}")
    
    def build_hsm(self, pin: str, permissions: str, output_name: str = "hsm") -> TestResult:
        """Build an HSM firmware image"""
        print_info(f"Building HSM with PIN={pin}, PERMS={permissions}...")
        
        output_dir = Path(self.temp_dir) / output_name
        output_dir.mkdir(exist_ok=True)
        
        cmd = [
            "docker", "run", "--rm",
            "-u", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{self.repo_path / 'firmware'}:/hsm",
            "-v", f"{self.secrets_file}:/secrets/global.secrets:ro",
            "-v", f"{output_dir}:/out",
            "-e", f"HSM_PIN={pin}",
            "-e", f"PERMISSIONS={permissions}",
            "build-hsm"
        ]

        if self.cflags:
            cmd[-1:-1] = ["-e", f"CFLAGS={self.cflags}"]
        
        success, output, duration = self.run_command(cmd, timeout=120)
        
        hsm_bin = output_dir / "hsm.bin"
        if success and hsm_bin.exists():
            setattr(self, f"{output_name}_bin", hsm_bin)
            return TestResult(f"Build HSM ({output_name})", True, duration=duration,
                            message=f"HSM built successfully in {duration:.1f}s")
        else:
            return TestResult(f"Build HSM ({output_name})", False, duration=duration,
                            message=f"Failed to build HSM:\n{output}")
    
    def flash_hsm(self, device_port: str, hsm_bin_path: Path, name: str) -> TestResult:
        """Flash HSM firmware to a device"""
        print_info(f"Flashing {name} to {device_port}...")
        
        # Check if device exists
        if not Path(device_port).exists():
            return TestResult(f"Flash {name}", False,
                            message=f"Device not found at {device_port}")
        
        # Automatically enter update mode if bridge is available
        service_pipe = Path("/tmp/pico_input_in")
        if self.bridge_dir.exists() and service_pipe.exists():
            print_info(f"Putting {name} into update mode via GPIO...")
            if self.device_enter_update_mode(device_port):
                print_info("Device in update mode")
                if not self.wait_for_bootloader(device_port):
                    print_warning("Bootloader not ready yet; erase may fail")
            else:
                print_warning("GPIO command failed, manually put device in update mode (hold PB21, tap NRST)")
                time.sleep(2)  # Give user time to do it manually
        elif self.bridge_dir.exists():
            print_warning("pico-uart service not running - manually enter update mode (hold PB21, tap NRST)")
            time.sleep(2)  # Give user time to do it manually
        else:
            print_warning("Bridge not available - manually put device in update mode (hold PB21, tap NRST)")
            time.sleep(2)  # Give user time to do it manually
        
        # Erase flash (with retry on failure)
        erase_success, erase_output, _ = self.run_command(
            ["uvx", "ectf", "hw", device_port, "erase"],
            timeout=30
        )
        
        if not erase_success:
            print_warning(f"Erase failed: {erase_output.strip()}")
            print_info("Rebooting device and retrying erase...")
            
            # Reboot device
            if self.bridge_dir.exists() and Path("/tmp/pico_input_in").exists():
                self.device_reboot(device_port)
                time.sleep(0.5)
            
            # Re-enter bootloader mode
            if self.bridge_dir.exists() and Path("/tmp/pico_input_in").exists():
                if self.device_enter_update_mode(device_port):
                    print_info("Device re-entered bootloader mode")
                    if not self.wait_for_bootloader(device_port):
                        print_warning("Bootloader not ready yet; erase may fail")
                else:
                    print_warning("Could not re-enter bootloader, erase may fail")
            
            # Retry erase
            erase_success, erase_output, _ = self.run_command(
                ["uvx", "ectf", "hw", device_port, "erase"],
                timeout=30
            )
            
            if erase_success:
                print_info("Erase succeeded on retry")
            else:
                print_warning(f"Erase still failing: {erase_output.strip()}")

        
        # Flash firmware (retry on transient busy)
        flash_success = False
        flash_output = ""
        duration = 0.0
        for attempt in range(2):
            if attempt > 0:
                time.sleep(1.0)
            flash_success, flash_output, duration = self.run_command(
                ["uvx", "ectf", "hw", device_port, "flash", str(hsm_bin_path), "-n", name],
                timeout=60
            )
            if flash_success:
                break
            if "Device or resource busy" not in flash_output and "Errno 16" not in flash_output:
                break
        
        if not flash_success:
            return TestResult(f"Flash {name}", False, duration=duration,
                            message=f"Failed to flash firmware:\n{flash_output}")
        
        # Start the application
        start_success, start_output, _ = self.run_command(
            ["uvx", "ectf", "hw", device_port, "start"],
            timeout=10
        )
        
        if start_success:
            # Wait for device to wake
            time.sleep(TIMING_REQUIREMENTS["device_wake"])
            return TestResult(f"Flash {name}", True, duration=duration,
                            message=f"Firmware flashed and started successfully")
        else:
            return TestResult(f"Flash {name}", False,
                            message=f"Failed to start firmware:\n{start_output}")
    
    def test_list_files(self, device_port: str, pin: str, name: str, 
                       max_time: float = None) -> TestResult:
        """Test the list files command"""
        if max_time is None:
            max_time = TIMING_REQUIREMENTS["list_files"]
        
        print_info(f"Testing list files on {name}...")
        
        success, output, duration = self.run_command(
            ["uvx", "ectf", "-v", "tools", device_port, "list", pin],
            timeout=(max_time * self.timeout_multiplier) + 1
        )
        
        timing_ok = duration <= max_time
        
        if success and "List successful" in output and timing_ok:
            return TestResult(f"List Files ({name})", True, duration=duration,
                            message=f"List completed in {duration:.3f}s (limit: {max_time}s)")
        elif success and "List successful" in output:
            return TestResult(f"List Files ({name})", False, duration=duration,
                            message=f"List succeeded but took {duration:.3f}s (limit: {max_time}s)")
        else:
            return TestResult(f"List Files ({name})", False, duration=duration,
                            message=f"List failed:\n{output}")
    
    def test_write_file(self, device_port: str, pin: str, slot: int, group: str,
                       content: str, name: str, max_time: float = None) -> TestResult:
        """Test writing a file to the HSM"""
        if max_time is None:
            max_time = TIMING_REQUIREMENTS["write_file"]
        
        print_info(f"Testing write file to {name}...")
        
        # Create temporary test file
        test_file = Path(self.temp_dir) / f"test_{name}_{slot}.txt"
        test_file.write_text(content)
        
        success, output, duration = self.run_command(
            ["uvx", "ectf", "-v", "tools", device_port, "write", pin, str(slot), group, str(test_file)],
            timeout=(max_time * self.timeout_multiplier) + 1
        )
        
        timing_ok = duration <= max_time
        
        if success and "Write successful" in output and timing_ok:
            return TestResult(f"Write File ({name}, slot {slot})", True, duration=duration,
                            message=f"Write completed in {duration:.3f}s (limit: {max_time}s)")
        elif success and "Write successful" in output:
            return TestResult(f"Write File ({name}, slot {slot})", False, duration=duration,
                            message=f"Write succeeded but took {duration:.3f}s (limit: {max_time}s)")
        else:
            return TestResult(f"Write File ({name}, slot {slot})", False, duration=duration,
                            message=f"Write failed:\n{output}")
    
    def test_read_file(self, device_port: str, pin: str, slot: int, name: str,
                      max_time: float = None) -> TestResult:
        """Test reading a file from the HSM"""
        if max_time is None:
            max_time = TIMING_REQUIREMENTS["read_file"]
        
        print_info(f"Testing read file from {name}...")
        
        output_dir = Path(self.temp_dir) / f"read_{name}_{slot}"
        output_dir.mkdir(exist_ok=True)
        
        success, output, duration = self.run_command(
            ["uvx", "ectf", "-v", "tools", device_port, "read", "-f", pin, str(slot), str(output_dir)],
            timeout=(max_time * self.timeout_multiplier) + 1
        )
        
        timing_ok = duration <= max_time
        
        if success and "Read successful" in output and timing_ok:
            return TestResult(f"Read File ({name}, slot {slot})", True, duration=duration,
                            message=f"Read completed in {duration:.3f}s (limit: {max_time}s)")
        elif success and "Read successful" in output:
            return TestResult(f"Read File ({name}, slot {slot})", False, duration=duration,
                            message=f"Read succeeded but took {duration:.3f}s (limit: {max_time}s)")
        else:
            return TestResult(f"Read File ({name}, slot {slot})", False, duration=duration,
                            message=f"Read failed:\n{output}")

    def test_read_file_denied(self, device_port: str, pin: str, slot: int, name: str,
                             max_time: float = None) -> TestResult:
        """Test reading a file is denied when permissions are missing"""
        if max_time is None:
            max_time = TIMING_REQUIREMENTS["read_file"]

        print_info(f"Testing read denied from {name}...")

        output_dir = Path(self.temp_dir) / f"read_denied_{name}_{slot}"
        output_dir.mkdir(exist_ok=True)

        success, output, duration = self.run_command(
            ["uvx", "ectf", "-v", "tools", device_port, "read", pin, str(slot), str(output_dir)],
            timeout=(max_time * self.timeout_multiplier) + 1
        )

        timing_ok = duration <= max_time
        denied = (not success) or ("Read successful" not in output)

        if denied and timing_ok:
            return TestResult(f"Read Denied ({name}, slot {slot})", True, duration=duration,
                            message=f"Read correctly denied in {duration:.3f}s (limit: {max_time}s)")
        elif denied:
            return TestResult(f"Read Denied ({name}, slot {slot})", False, duration=duration,
                            message=f"Read denied but took {duration:.3f}s (limit: {max_time}s)")
        else:
            return TestResult(f"Read Denied ({name}, slot {slot})", False, duration=duration,
                            message=f"Read unexpectedly succeeded")
    
    def test_invalid_pin(self, device_port: str, name: str, max_time: float = None) -> TestResult:
        """Test that invalid PIN is handled correctly within timing constraints"""
        if max_time is None:
            max_time = TIMING_REQUIREMENTS["invalid_pin"]
        
        print_info(f"Testing invalid PIN on {name}...")
        
        invalid_pin = "000000"
        success, output, duration = self.run_command(
            ["uvx", "ectf", "-v", "tools", device_port, "list", invalid_pin],
            timeout=(max_time * self.timeout_multiplier) + 1
        )
        
        timing_ok = duration <= max_time
        
        # Invalid PIN should fail, but within time limit
        if not success and timing_ok:
            return TestResult(f"Invalid PIN ({name})", True, duration=duration,
                            message=f"Invalid PIN rejected in {duration:.3f}s (limit: {max_time}s)")
        elif not success:
            return TestResult(f"Invalid PIN ({name})", False, duration=duration,
                            message=f"Invalid PIN rejected but took {duration:.3f}s (limit: {max_time}s)")
        else:
            return TestResult(f"Invalid PIN ({name})", False, duration=duration,
                            message=f"Invalid PIN accepted (security issue!)")
    
    def test_interrogate(self, local_port: str, local_pin: str, remote_port: str,
                        local_name: str, remote_name: str, max_time: float = None) -> TestResult:
        """Test interrogate command between two HSMs"""
        if max_time is None:
            max_time = TIMING_REQUIREMENTS["interrogate"]
        
        print_info(f"Testing interrogate from {local_name} to {remote_name}...")
        
        # Put remote device in listen mode (in background)
        print_info(f"Setting {remote_name} to listen mode...")
        listen_process = subprocess.Popen(
            ["uvx", "ectf", "-v", "tools", remote_port, "listen"],
            stdout=open(f"{remote_name.lower()}_debug.log", "a"),
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Give it a moment to enter listen mode
        time.sleep(0.5)
        
        # Run interrogate
        success, output, duration = self.run_command(
            ["uvx", "ectf", "-v", "tools", local_port, "interrogate", local_pin],
            timeout=(max_time * self.timeout_multiplier) + 1
        )
        
        # Terminate listen process
        listen_process.terminate()
        try:
            listen_process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            listen_process.kill()
        
        timing_ok = duration <= max_time
        
        if success and "Interrogate successful" in output and timing_ok:
            return TestResult(f"Interrogate ({local_name} → {remote_name})", True, duration=duration,
                            message=f"Interrogate completed in {duration:.3f}s (limit: {max_time}s)")
        elif success and "Interrogate successful" in output:
            return TestResult(f"Interrogate ({local_name} → {remote_name})", False, duration=duration,
                            message=f"Interrogate succeeded but took {duration:.3f}s (limit: {max_time}s)")
        else:
            return TestResult(f"Interrogate ({local_name} → {remote_name})", False, duration=duration,
                            message=f"Interrogate failed:\n{output}")
    
    def test_receive_file(self, local_port: str, local_pin: str, remote_port: str,
                         slot: int, local_name: str, remote_name: str,
                         max_time: float = None) -> TestResult:
        """Test receive file command between two HSMs"""
        if max_time is None:
            max_time = TIMING_REQUIREMENTS["receive_file"]
        
        print_info(f"Testing receive file from {remote_name} to {local_name}...")
        
        # Put remote device in listen mode (in background)
        print_info(f"Setting {remote_name} to listen mode...")
        listen_process = subprocess.Popen(
            ["uvx", "ectf", "-v", "tools", remote_port, "listen"],
            stdout=open(f"{remote_name.lower()}_debug.log", "a"),
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Give it a moment to enter listen mode
        time.sleep(0.5)
        
        # Run receive
        success, output, duration = self.run_command(
            ["uvx", "ectf", "-v", "tools", local_port, "receive", local_pin, str(slot), "0"],
            timeout=(max_time * self.timeout_multiplier) + 1
        )
        
        # Terminate listen process
        listen_process.terminate()
        try:
            listen_process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            listen_process.kill()
        
        timing_ok = duration <= max_time
        
        if success and "Receive successful" in output and timing_ok:
            return TestResult(f"Receive File ({local_name} ← {remote_name}, slot {slot})", 
                            True, duration=duration,
                            message=f"Receive completed in {duration:.3f}s (limit: {max_time}s)")
        elif success and "Receive successful" in output:
            return TestResult(f"Receive File ({local_name} ← {remote_name}, slot {slot})",
                            False, duration=duration,
                            message=f"Receive succeeded but took {duration:.3f}s (limit: {max_time}s)")
        else:
            return TestResult(f"Receive File ({local_name} ← {remote_name}, slot {slot})",
                            False, duration=duration,
                            message=f"Receive failed:\n{output}")
    
    def test_file_persistence(self, device_port: str, pin: str, hsm_bin: Path,
                             name: str) -> TestResult:
        """Test that files persist after power cycle"""
        print_info(f"Testing file persistence on {name}...")
        
        # List files before power cycle
        success1, output1, _ = self.run_command(
            ["uvx", "ectf", "-v", "tools", device_port, "list", pin],
            timeout=2
        )
        
        if not success1:
            return TestResult(f"File Persistence ({name})", False,
                            message=f"Failed to list files before power cycle")
        
        # Extract file list
        files_before = self._extract_file_list(output1)
        
        # Power cycle via GPIO reboot
        print_info(f"Power cycling {name}...")
        if not self.device_reboot(device_port):
            return TestResult(f"File Persistence ({name})", False,
                            message=f"Failed to reboot device during power cycle test")
        
        # List files after power cycle
        success2, output2, _ = self.run_command(
            ["uvx", "ectf", "-v", "tools", device_port, "list", pin],
            timeout=2
        )
        
        if not success2:
            return TestResult(f"File Persistence ({name})", False,
                            message=f"Failed to list files after power cycle")
        
        files_after = self._extract_file_list(output2)
        
        # Compare
        if files_before == files_after:
            return TestResult(f"File Persistence ({name})", True,
                            message=f"Files persisted correctly after power cycle")
        else:
            return TestResult(f"File Persistence ({name})", False,
                            message=f"Files changed after power cycle!\nBefore: {files_before}\nAfter: {files_after}")
    
    def _extract_file_list(self, output: str) -> List[Dict]:
        """Extract file information from list command output"""
        files = []
        for line in output.split('\n'):
            if "Found file:" in line:
                # Parse: "Found file: Slot 0, Group 1111, filename.txt"
                parts = line.split("Found file:")[-1].strip()
                files.append(parts)
        return sorted(files)
    
    def run_all_tests(self) -> bool:
        """Run all tests and return overall success status"""
        print_header("eCTF 2026 HSM Design Testing")
        print(f"Testing repository: {self.repo_path}")
        print(f"Device 1: {self.dev1_port}")
        print(f"Device 2: {self.dev2_port}")
        
        # Phase 1: Repository and Build Validation
        print_header("Phase 1: Repository and Build Validation")
        
        result = self.validate_repo_structure()
        self.test_results.append(result)
        self._print_result(result)
        if not result.passed:
            return False
        
        result = self.build_docker_image()
        self.test_results.append(result)
        self._print_result(result)
        if not result.passed:
            return False
        
        # Define test groups
        test_groups = ["0x1111", "0x2222", "0x3333", "0x4444"]
        
        result = self.generate_secrets(test_groups)
        self.test_results.append(result)
        self._print_result(result)
        if not result.passed:
            return False
        
        # Phase 2: Build HSMs
        print_header("Phase 2: Building HSM Firmware")
        
        # HSM A: Write permissions for group 0x1111
        result = self.build_hsm(pin="123abc", permissions="0x1111=-W-:0x2222=R--", 
                               output_name="hsm_a")
        self.test_results.append(result)
        self._print_result(result)
        if not result.passed:
            return False
        
        # HSM B: Read and Receive permissions for group 0x1111
        result = self.build_hsm(pin="456def", permissions="0x1111=R-C:0x2222=-W-",
                               output_name="hsm_b")
        self.test_results.append(result)
        self._print_result(result)
        if not result.passed:
            return False
        
        # Phase 3: Flash Firmware
        print_header("Phase 3: Flashing Firmware to Devices")

        if self.power_cycle_serial:
            print_info("Power-cycling USB serial adapters...")
            self.power_cycle_serial_adapter(self.dev1_port)
            self.power_cycle_serial_adapter(self.dev2_port)
            time.sleep(2.0)
        
        result = self.flash_hsm(self.dev1_port, self.hsm_a_bin, "HSM_A")
        self.test_results.append(result)
        self._print_result(result)
        if not result.passed:
            return False
        
        result = self.flash_hsm(self.dev2_port, self.hsm_b_bin, "HSM_B")
        self.test_results.append(result)
        self._print_result(result)
        if not result.passed:
            return False
        
        # Phase 4: Basic Functional Tests
        print_header("Phase 4: Basic Functional Tests")
        
        # Test list on both devices
        result = self.test_list_files(self.dev1_port, "123abc", "HSM_A")
        self.test_results.append(result)
        self._print_result(result)
        
        result = self.test_list_files(self.dev2_port, "456def", "HSM_B")
        self.test_results.append(result)
        self._print_result(result)
        
        # Test invalid PIN
        result = self.test_invalid_pin(self.dev1_port, "HSM_A")
        self.test_results.append(result)
        self._print_result(result)
        
        result = self.test_invalid_pin(self.dev2_port, "HSM_B")
        self.test_results.append(result)
        self._print_result(result)
        
        # Phase 5: File Operations Tests
        print_header("Phase 5: File Operations Tests")
        
        # Write files to HSM A
        result = self.test_write_file(self.dev1_port, "123abc", 0, "0x1111",
                                     "Test file content for slot 0", "HSM_A")
        self.test_results.append(result)
        self._print_result(result)
        
        result = self.test_write_file(self.dev1_port, "123abc", 1, "0x1111",
                                     "Test file content for slot 1", "HSM_A")
        self.test_results.append(result)
        self._print_result(result)
        
        # List files on HSM A to verify writes
        result = self.test_list_files(self.dev1_port, "123abc", "HSM_A")
        self.test_results.append(result)
        self._print_result(result)
        
        # Write a file to HSM B in a group it cannot read
        result = self.test_write_file(self.dev2_port, "456def", 0, "0x2222",
                                     "Test file on HSM B", "HSM_B")
        self.test_results.append(result)
        self._print_result(result)
        
        # Verify read is denied (no read permission for 0x2222)
        #result = self.test_read_file_denied(self.dev2_port, "456def", 0, "HSM_B")
        #self.test_results.append(result)
        #self._print_result(result)
        
        # Phase 6: Cross-Device Communication Tests
        print_header("Phase 6: Cross-Device Communication Tests")
        
        print_info("Please ensure HSMs are connected via UART1 for these tests")
        time.sleep(2)  # Give user time to connect devices
        
        # Test interrogate (B interrogates A)
        result = self.test_interrogate(self.dev2_port, "456def", self.dev1_port,
                                      "HSM_B", "HSM_A")
        self.test_results.append(result)
        self._print_result(result)
        
        # Test receive (B receives from A)
        result = self.test_receive_file(self.dev2_port, "456def", self.dev1_port,
                                       0, "HSM_B", "HSM_A")
        self.test_results.append(result)
        self._print_result(result)
        
        # Verify file was received by listing on B
        result = self.test_list_files(self.dev2_port, "456def", "HSM_B")
        self.test_results.append(result)
        self._print_result(result)

        # Read received file on B (has read permission for 0x1111)
        result = self.test_read_file(self.dev2_port, "456def", 0, "HSM_B")
        self.test_results.append(result)
        self._print_result(result)
        
        # Phase 7: File Persistence Tests
        print_header("Phase 7: File Persistence Tests")
        
        result = self.test_file_persistence(self.dev1_port, "123abc", 
                                           self.hsm_a_bin, "HSM_A")
        self.test_results.append(result)
        self._print_result(result)
        
        # Phase 8: Test Summary
        self.print_summary()
        
        # Overall success
        all_passed = all(r.passed for r in self.test_results)
        return all_passed
    
    def _print_result(self, result: TestResult):
        """Print a test result"""
        status = "PASS" if result.passed else "FAIL"
        color = Colors.OKGREEN if result.passed else Colors.FAIL
        
        duration_str = ""
        if result.duration is not None:
            duration_str = f" ({result.duration:.3f}s)"
        
        print(f"{color}{status}{Colors.ENDC} {result.name}{duration_str}")
        if result.message:
            print(f"      {result.message}")
    
    def print_summary(self):
        """Print test summary"""
        print_header("Test Summary")
        
        passed = sum(1 for r in self.test_results if r.passed)
        failed = sum(1 for r in self.test_results if not r.passed)
        total = len(self.test_results)
        
        print(f"\nTotal Tests: {total}")
        print_success(f"Passed: {passed}")
        if failed > 0:
            print_failure(f"Failed: {failed}")
        
        # Show timing summary
        print(f"\n{Colors.BOLD}Timing Summary:{Colors.ENDC}")
        timing_tests = [r for r in self.test_results if r.duration is not None and any(keyword in r.name for keyword in ["List", "Read", "Write", "Receive", "Interrogate", "Invalid PIN"])]
        
        if timing_tests:
            print(f"\n{'Test':<40} {'Time (s)':<12} {'Limit (s)':<12} {'Status':<10}")
            print("-" * 80)
            for result in timing_tests:
                status = "✓" if result.passed else "✗"
                # Extract limit from message if available
                limit = "N/A"
                if "limit:" in result.message:
                    try:
                        limit = result.message.split("limit:")[1].split("s")[0].strip()
                    except:
                        pass
                print(f"{result.name:<40} {result.duration:<12.3f} {limit:<12} {status:<10}")
        
        # Show failed tests
        if failed > 0:
            print(f"\n{Colors.FAIL}{Colors.BOLD}Failed Tests:{Colors.ENDC}")
            for result in self.test_results:
                if not result.passed:
                    print(f"  ✗ {result.name}")
                    if result.message:
                        print(f"      {result.message}")
        
        # Overall result
        if failed == 0:
            print(f"\n{Colors.OKGREEN}{Colors.BOLD}ALL TESTS PASSED!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}Design meets all functional requirements and timing constraints.{Colors.ENDC}")
        else:
            print(f"\n{Colors.FAIL}{Colors.BOLD}SOME TESTS FAILED!{Colors.ENDC}")
            print(f"{Colors.FAIL}Design does not meet all requirements.{Colors.ENDC}")
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and Path(self.temp_dir).exists():
            def _on_rm_error(func, path, exc_info):
                try:
                    os.chmod(path, 0o700)
                    func(path)
                except Exception:
                    pass

            shutil.rmtree(self.temp_dir, onerror=_on_rm_error)
            print_info(f"Cleaned up temporary directory: {self.temp_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Test an eCTF 2026 HSM design against all requirements",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 test_hsm_design.py /path/to/design/repo
  python3 test_hsm_design.py /path/to/design/repo --dev1 /dev/ttyACM0 --dev2 /dev/ttyACM1
  python3 test_hsm_design.py /path/to/design/repo --skip-docker-rebuild  # Reuse existing image
        """
    )
    
    parser.add_argument("repo_path", help="Path to the HSM design repository")
    parser.add_argument("--dev1", default="/work/d1", help="Device port for HSM 1 (default: /work/d1)")
    parser.add_argument("--dev2", default="/work/d2", help="Device port for HSM 2 (default: /work/d2)")
    parser.add_argument("--skip-docker-rebuild", action="store_true", 
                       help="Skip Docker rebuild if image already exists (faster for repeated tests)")
    parser.add_argument("--bridge-dir", default="/work/2026-ectf-utd/bridge",
                       help="Path to bridge directory for GPIO control (default: /work/2026-ectf-utd/bridge)")
    parser.add_argument("--no-cleanup", action="store_true", help="Don't clean up temporary files")
    parser.add_argument("--cflags", default=None,
                       help="Extra CFLAGS to pass to the firmware build (e.g., -DENABLE_DEBUG_MESSAGES)")
    parser.add_argument("--power-cycle-serial", action="store_true",
                       help="Power-cycle USB serial adapters for /work/d1 and /work/d2 before flashing")
    parser.add_argument("--only-power-cycle-serial", action="store_true",
                       help="Only power-cycle USB serial adapters and exit")
    parser.add_argument("--power-cycle-mode", choices=["cycle", "reset"], default="cycle",
                       help="USB power action: 'cycle' uses uhubctl, 'reset' uses usbreset/ioctl")
    parser.add_argument("--timeout-multiplier", type=float, default=1.0,
                       help="Multiply tool timeouts by this factor (does not change timing limits)")
    parser.add_argument("--hub-d1", default=None,
                       help="Override uhubctl hub path:port for dev1 (e.g., 1-1:2)")
    parser.add_argument("--hub-d2", default=None,
                       help="Override uhubctl hub path:port for dev2 (e.g., 1-1:3)")
    
    args = parser.parse_args()
    
    # Validate repo path
    if not Path(args.repo_path).exists():
        print_failure(f"Repository path does not exist: {args.repo_path}")
        sys.exit(1)

    def _parse_hub_override(value: Optional[str]) -> Optional[Tuple[str, str]]:
        if not value:
            return None
        if ":" not in value:
            return None
        hub_path, port = value.split(":", 1)
        if not hub_path or not port:
            return None
        return hub_path, port

    hub_override: Dict[str, Tuple[str, str]] = {}
    hub_d1 = _parse_hub_override(args.hub_d1)
    if hub_d1:
        hub_override[args.dev1] = hub_d1
    hub_d2 = _parse_hub_override(args.hub_d2)
    if hub_d2:
        hub_override[args.dev2] = hub_d2
    
    # Create tester
    tester = HSMTester(args.repo_path, args.dev1, args.dev2, args.skip_docker_rebuild,
                       args.bridge_dir, args.cflags, args.power_cycle_serial, hub_override,
                       args.power_cycle_mode, args.timeout_multiplier)
    
    try:
        if args.only_power_cycle_serial:
            print_info("Power-cycling USB serial adapters...")
            tester.power_cycle_serial_adapter(args.dev1)
            tester.power_cycle_serial_adapter(args.dev2)
            sys.exit(0)

        # Run tests
        success = tester.run_all_tests()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Testing interrupted by user{Colors.ENDC}")
        sys.exit(130)
        
    except Exception as e:
        print_failure(f"Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
        
    finally:
        if not args.no_cleanup:
            tester.cleanup()


if __name__ == "__main__":
    main()
