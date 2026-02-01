#!/bin/bash
# Installation script for Pico UART Stream Service

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="pico-uart"
SERVICE_FILE="${SCRIPT_DIR}/${SERVICE_NAME}.service"
PYTHON_SCRIPT="${SCRIPT_DIR}/pico_uart_service.py"
INSTALL_DIR="/usr/local/bin"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Installing $SERVICE_NAME service..."

# Copy Python script to /usr/local/bin
#echo "Installing Python script to $INSTALL_DIR..."
#cp "$PYTHON_SCRIPT" "$INSTALL_DIR/"
#chmod +x "$INSTALL_DIR/pico_uart_service.py"

# Copy systemd service file
echo "Installing systemd service..."
cp "$SERVICE_FILE" "/etc/systemd/system/"
chmod 644 "/etc/systemd/system/$(basename $SERVICE_FILE)"

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

echo ""
echo "Installation complete!"
echo ""
echo "To start the service:"
echo "  sudo systemctl start $SERVICE_NAME"
echo ""
echo "To enable at boot:"
echo "  sudo systemctl enable $SERVICE_NAME"
echo ""
echo "To check status:"
echo "  sudo systemctl status $SERVICE_NAME"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo "Named pipes will be created at:"
echo "  /tmp/pico_uart0_out  - Read UART0 output"
echo "  /tmp/pico_uart1_out  - Read UART1 output"
echo "  /tmp/pico_input_in   - Write input to Pico"
echo ""
echo "Example usage:"
echo "  tail -f /tmp/pico_uart0_out           # Monitor UART0"
echo "  echo 'on 25' > /tmp/pico_input_in     # Send command"
