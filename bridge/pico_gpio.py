#!/usr/bin/env python3
"""
GPIO Control Client for Raspberry Pi Pico
Sends serial commands to control GPIO pins from Linux command line.

By default, uses the pico_uart_service named pipes.
Supports direct serial connection with --direct flag.

Usage:
    pico_gpio.py [--direct] toggle <pin>
    pico_gpio.py [--direct] on <pin>
    pico_gpio.py [--direct] off <pin>
    pico_gpio.py [--direct] read <pin>
    pico_gpio.py [--direct] input <pin>
    pico_gpio.py [--direct] output <pin>
    pico_gpio.py [--direct] pullup <pin>
    pico_gpio.py [--direct] <custom_command>

Examples:
    pico_gpio.py toggle 25       # Toggle onboard LED
    pico_gpio.py on 15           # Set GPIO15 HIGH
    pico_gpio.py off 15          # Set GPIO15 LOW
    pico_gpio.py read 10         # Read GPIO10 state
    pico_gpio.py --direct on 25  # Use direct serial connection
"""

import serial
import sys
import time
import glob
import argparse
import os
from pathlib import Path

# Serial port settings
BAUD_RATE = 115200
TIMEOUT = 2.0

# Service named pipes
INPUT_PIPE = "/tmp/pico_input_in"
OUTPUT_PIPE = "/tmp/pico_output"

def find_pico_port():
    """
    Auto-detect the Raspberry Pi Pico serial port.
    Returns the port path or None if not found.
    """
    # Common Pico port patterns on Linux
    patterns = [
        #'/dev/ttyACM*',
        #'/dev/ttyUSB*',
        '/dev/serial/by-id/*Pico*',
        '/dev/serial/by-id/*RP2040*',
    ]
    
    for pattern in patterns:
        ports = glob.glob(pattern)
        if ports:
            return ports[0]
    
    return None

def send_command_via_service(command):
    """
    Send a command via the pico_uart_service named pipes.
    Returns the response or error message.
    """
    try:
        # Check if service pipes exist
        if not os.path.exists(INPUT_PIPE):
            return f"Error: Service pipe not found at {INPUT_PIPE}. Is pico-uart service running?"
        
        # Send command
        with open(INPUT_PIPE, 'w') as pipe:
            pipe.write(command + '\n')
            pipe.flush()
        
        # Try to read response from output pipe
        response_lines = []
        start_time = time.time()
        
        try:
            # Read from output pipe with a timeout
            output = open(OUTPUT_PIPE, 'r', buffering=1)
            while time.time() - start_time < TIMEOUT:
                try:
                    line = output.readline()
                    if not line:
                        time.sleep(0.01)
                        continue
                    line = line.strip()
                    if line and line != 'command:>':
                        response_lines.append(line)
                    # Stop when we see the prompt
                    if line == 'command:>':
                        break
                except Exception:
                    break
            output.close()
        except (FileNotFoundError, BlockingIOError, IOError):
            # If output pipe can't be read, return what we have
            pass
        
        return '\n'.join(response_lines) if response_lines else ""
    
    except IOError as e:
        return f"Error: Cannot write to service pipe: {e}"
    except Exception as e:
        return f"Error: {e}"

def send_command(port, command):
    """
    Send a command to the Pico via direct serial connection and return the response.
    """
    try:
        with serial.Serial(port, BAUD_RATE, timeout=TIMEOUT) as ser:
            # Wait a bit for the connection to stabilize
            time.sleep(0.1)
            
            # Clear any pending input
            ser.reset_input_buffer()
            
            # Send command
            cmd = command + '\n'
            ser.write(cmd.encode('utf-8'))
            ser.flush()
            
            # Read response (wait for next prompt)
            response_lines = []
            start_time = time.time()
            
            while time.time() - start_time < TIMEOUT:
                if ser.in_waiting:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    if line and line != '>':
                        response_lines.append(line)
                    if line == '>':
                        break
                else:
                    time.sleep(0.01)
            
            return '\n'.join(response_lines)
            
    except serial.SerialException as e:
        return f"Error: Cannot open serial port {port}: {e}"
    except Exception as e:
        return f"Error: {e}"

def send_commands(port, commands, delay_ms=0, wait_prompt=True):
    """Send multiple commands over a single serial session with optional delay."""
    responses = []
    try:
        with serial.Serial(port, BAUD_RATE, timeout=TIMEOUT) as ser:
            time.sleep(0.1)
            ser.reset_input_buffer()

            for cmd in commands:
                if not cmd:
                    continue
                line = cmd.strip() + '\n'
                ser.write(line.encode('utf-8'))
                ser.flush()

                if wait_prompt:
                    start_time = time.time()
                    while time.time() - start_time < TIMEOUT:
                        if ser.in_waiting:
                            rx = ser.readline().decode('utf-8', errors='ignore').strip()
                            if rx and rx != '>':
                                responses.append(rx)
                            if rx == '>':
                                break
                        else:
                            time.sleep(0.005)

                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

        return '\n'.join(responses)
    except serial.SerialException as e:
        return f"Error: Cannot open serial port {port}: {e}"
    except Exception as e:
        return f"Error: {e}"

def main():
    parser = argparse.ArgumentParser(description='Raspberry Pi Pico GPIO command client')
    parser.add_argument('--direct', action='store_true', help='Use direct serial connection instead of service pipes')
    parser.add_argument('--port', help='Serial port (for --direct mode, auto-detect if not specified)')
    parser.add_argument('--batch', help='Semicolon-separated commands to send in one session')
    parser.add_argument('--delay-ms', type=int, default=0, help='Delay between batch commands in milliseconds')
    parser.add_argument('--no-wait', action='store_true', help='Do not wait for Pico prompt between commands')
    parser.add_argument('cmd', nargs='*', help='Single command and arguments (e.g., on 25)')
    args = parser.parse_args()

    # Determine which method to use
    if args.direct:
        # Direct serial connection mode
        port = os.environ.get('PICO_PORT') or args.port or find_pico_port()
        if not port:
            print('Error: Cannot find Raspberry Pi Pico serial port')
            print('Set PICO_PORT env var (e.g., /dev/ttyACM0) or use --port, or connect the device.')
            sys.exit(1)
        
        if args.batch:
            commands = [c.strip() for c in args.batch.split(';') if c.strip()]
            response = send_commands(port, commands, delay_ms=args.delay_ms, wait_prompt=(not args.no_wait))
            if response:
                print(response)
            return
        
        if not args.cmd:
            parser.print_help()
            sys.exit(1)
        
        command = ' '.join(args.cmd)
        response = send_command(port, command)
        if response:
            print(response)
    
    else:
        # Service mode (default)
        if args.batch:
            commands = [c.strip() for c in args.batch.split(';') if c.strip()]
            for cmd in commands:
                if cmd:
                    response = send_command_via_service(cmd)
                    if response:
                        print(response)
                if args.delay_ms > 0:
                    time.sleep(args.delay_ms / 1000.0)
            return
        
        if not args.cmd:
            parser.print_help()
            sys.exit(1)
        
        command = ' '.join(args.cmd)
        response = send_command_via_service(command)
        if response:
            print(response)

if __name__ == '__main__':
    main()
