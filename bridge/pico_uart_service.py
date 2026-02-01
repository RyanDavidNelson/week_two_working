#!/usr/bin/env python3
"""
Raspberry Pi Pico UART Stream Service

This service manages the serial connection to a Pico and provides named pipes
for other processes to listen to UART output and send input.

Named pipes (FIFOs):
  /tmp/pico_uart0_out  - Read UART0 output (base64-encoded)
  /tmp/pico_uart1_out  - Read UART1 output (base64-encoded)
  /tmp/pico_input_in   - Write commands/data to Pico

Usage:
  pico_uart_service.py [--port PORT] [--baud BAUD]

Environment:
  PICO_PORT - Serial port (overrides auto-detection)
"""

import serial
import sys
import os
import signal
import time
import glob
import argparse
import threading
import select
from pathlib import Path

# Configuration
BAUD_RATE = 115200
PIPE_DIR = "/tmp"
UART0_OUT_PIPE = f"{PIPE_DIR}/pico_uart0_out"
UART1_OUT_PIPE = f"{PIPE_DIR}/pico_uart1_out"
INPUT_IN_PIPE = f"{PIPE_DIR}/pico_input_in"
OUTPUT_OUT_PIPE = f"{PIPE_DIR}/pico_output"

class PicoUARTService:
    def __init__(self, port=None, baud=BAUD_RATE):
        self.port = port or self._find_pico_port()
        self.baud = baud
        self.ser = None
        self.running = False
        self.uart0_fd = None
        self.uart1_fd = None
        self.input_fd = None
        self.output_fd = None
        
    def _find_pico_port(self):
        """Auto-detect the Raspberry Pi Pico serial port."""
        patterns = [
            '/dev/serial/by-id/*Pico*',
            '/dev/serial/by-id/*RP2040*',
            '/dev/ttyACM*',
            '/dev/ttyUSB*',
        ]
        
        for pattern in patterns:
            ports = glob.glob(pattern)
            if ports:
                return ports[0]
        
        raise RuntimeError("Cannot find Raspberry Pi Pico serial port")
    
    def _setup_pipes(self):
        """Create named pipes if they don't exist."""
        for pipe in [UART0_OUT_PIPE, UART1_OUT_PIPE, INPUT_IN_PIPE, OUTPUT_OUT_PIPE]:
            if os.path.exists(pipe):
                try:
                    os.remove(pipe)
                except OSError:
                    pass
        
        try:
            os.mkfifo(UART0_OUT_PIPE, 0o666)
            os.mkfifo(UART1_OUT_PIPE, 0o666)
            os.mkfifo(INPUT_IN_PIPE, 0o666)
            os.mkfifo(OUTPUT_OUT_PIPE, 0o666)

            # Ensure permissions are world-writable regardless of umask
            for pipe in [UART0_OUT_PIPE, UART1_OUT_PIPE, INPUT_IN_PIPE, OUTPUT_OUT_PIPE]:
                try:
                    os.chmod(pipe, 0o666)
                except OSError:
                    pass
            print(f"Created named pipes:")
            print(f"  {UART0_OUT_PIPE} - UART0 output")
            print(f"  {UART1_OUT_PIPE} - UART1 output")
            print(f"  {INPUT_IN_PIPE} - Input to Pico")
            print(f"  {OUTPUT_OUT_PIPE} - GPIO command responses")
        except FileExistsError:
            pass  # Pipes already exist
        except Exception as e:
            print(f"Warning: Could not create pipes: {e}")
    
    def _connect(self):
        """Connect to the serial port."""
        try:
            self.ser = serial.Serial(self.port, self.baud, timeout=0.1)
            print(f"Connected to {self.port} at {self.baud} baud")
            time.sleep(0.5)
            return True
        except serial.SerialException as e:
            print(f"Error: Cannot open serial port {self.port}: {e}")
            return False
    
    def _open_pipes(self):
        """Open named pipes in non-blocking mode."""
        try:
            # Open UART output pipes for writing (non-blocking)
            self.uart0_fd = os.open(UART0_OUT_PIPE, os.O_WRONLY | os.O_NONBLOCK)
            self.uart1_fd = os.open(UART1_OUT_PIPE, os.O_WRONLY | os.O_NONBLOCK)
            print("Opened UART output pipes")
        except OSError as e:
            print(f"Warning: Could not open UART output pipes: {e}")
        
        try:
            # Open input pipe for reading (non-blocking)
            self.input_fd = os.open(INPUT_IN_PIPE, os.O_RDONLY | os.O_NONBLOCK)
            print("Opened input pipe")
        except OSError as e:
            print(f"Warning: Could not open input pipe: {e}")
        
        try:
            # Open output pipe for writing command responses (non-blocking)
            self.output_fd = os.open(OUTPUT_OUT_PIPE, os.O_WRONLY | os.O_NONBLOCK)
            print("Opened output pipe")
        except OSError as e:
            print(f"Warning: Could not open output pipe: {e}")
    
    def _close_pipes(self):
        """Close all open pipes."""
        for fd_ref in [self.uart0_fd, self.uart1_fd, self.input_fd, self.output_fd]:
            if fd_ref is not None:
                try:
                    os.close(fd_ref)
                except OSError:
                    pass
        self.uart0_fd = None
        self.uart1_fd = None
        self.input_fd = None
        self.output_fd = None
    
    def _write_to_pipe(self, fd, data):
        """Write data to a pipe, handling broken pipe gracefully."""
        if fd is None:
            return
        try:
            os.write(fd, data)
        except OSError as e:
            if e.errno == 32:  # Broken pipe
                pass  # No readers on this pipe
            else:
                print(f"Error writing to pipe: {e}")
    
    def _parse_and_route_line(self, line):
        """Parse UART output and route to appropriate pipe."""
        line = line.strip()
        if not line:
            return
        
        if line.startswith("[UART0]"):
            data = line[7:].strip()  # Remove "[UART0]"
            self._write_to_pipe(self.uart0_fd, (data + "\n").encode('utf-8'))
        elif line.startswith("[UART1]"):
            data = line[7:].strip()  # Remove "[UART1]"
            self._write_to_pipe(self.uart1_fd, (data + "\n").encode('utf-8'))
        else:
            # Non-UART output (GPIO responses, prompts, etc.) goes to output pipe
            self._write_to_pipe(self.output_fd, (line + "\n").encode('utf-8'))
    
    def _read_input_pipe(self):
        """Read pending data from input pipe and send to Pico."""
        if self.input_fd is None or self.ser is None:
            return
        
        try:
            data = os.read(self.input_fd, 1024)
            if data:
                self.ser.write(data)
                self.ser.flush()
        except OSError:
            pass  # No data available or pipe closed
    
    def _read_serial(self):
        """Read and process data from serial port."""
        if self.ser is None:
            return
        
        try:
            if self.ser.in_waiting > 0:
                data = self.ser.read(self.ser.in_waiting)
                for byte in data:
                    self._process_byte(byte)
        except serial.SerialException as e:
            print(f"Serial read error: {e}")
            self.ser = None
    
    def _process_byte(self, byte):
        """Process incoming byte and accumulate into lines."""
        if not hasattr(self, '_serial_buffer'):
            self._serial_buffer = b''
        
        self._serial_buffer += bytes([byte])
        
        if byte == ord('\n'):
            line = self._serial_buffer.decode('utf-8', errors='ignore')
            self._parse_and_route_line(line)
            self._serial_buffer = b''
    
    def _reconnect_loop(self):
        """Try to reconnect to Pico with backoff."""
        retry_delay = 1
        max_retry_delay = 30
        
        while self.running:
            if self.ser is None or not self.ser.is_open:
                print(f"Reconnecting in {retry_delay}s...")
                time.sleep(retry_delay)
                
                if self._connect():
                    retry_delay = 1
                    self._open_pipes()
                else:
                    retry_delay = min(retry_delay * 2, max_retry_delay)
            else:
                self._read_serial()
                self._read_input_pipe()
                time.sleep(0.01)
    
    def start(self):
        """Start the service."""
        print("Starting Pico UART Stream Service")
        self._setup_pipes()
        
        if not self._connect():
            print("Failed to connect to Pico")
            sys.exit(1)
        
        self._open_pipes()
        self.running = True
        
        try:
            self._reconnect_loop()
        except KeyboardInterrupt:
            print("Shutting down...")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the service and cleanup."""
        self.running = False
        if self.ser and self.ser.is_open:
            self.ser.close()
        self._close_pipes()
        print("Service stopped")

def main():
    parser = argparse.ArgumentParser(description='Raspberry Pi Pico UART Stream Service')
    parser.add_argument('--port', help='Serial port (auto-detect if not specified)')
    parser.add_argument('--baud', type=int, default=BAUD_RATE, help=f'Baud rate (default: {BAUD_RATE})')
    args = parser.parse_args()
    
    port = os.environ.get('PICO_PORT') or args.port
    
    try:
        service = PicoUARTService(port=port, baud=args.baud)
        service.start()
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
