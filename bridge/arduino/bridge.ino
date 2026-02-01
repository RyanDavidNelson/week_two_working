/*
 * GPIO Control + UART Sniffer for Raspberry Pi Pico
 * 
 * GPIO Serial Commands:
 *   toggle <pin>     - Toggle GPIO pin
 *   on <pin>         - Set GPIO pin HIGH
 *   off <pin>        - Set GPIO pin LOW
 *   read <pin>       - Read GPIO pin state
 *   input <pin>      - Set pin as INPUT
 *   output <pin>     - Set pin as OUTPUT
 *   pullup <pin>     - Set pin as INPUT_PULLUP
 *   help             - Show available commands
 *
 * UART Snooping:
 *   GP1 (UART0 RX)   - Sniff 115200 baud stream
 *   GP5 (UART1 RX)   - Sniff 115200 baud stream
 *   Output labeled to main USB serial
 */

#include <string.h>
#include <ctype.h>
#include <hardware/uart.h>
#include <hardware/gpio.h>

#define BAUD_RATE 115200
#define SNIFF_BAUD 115200
#define MAX_INPUT 64
#define MAX_UART_BUFFER 256

// Raspberry Pi Pico has GPIO0-GPIO28
#define MIN_GPIO 0
#define MAX_GPIO 28

// Base64 encoding table
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// UART pin assignments
// UART0: GP0(TX), GP1(RX)
// UART1: GP4(TX), GP5(RX)

char inputBuffer[MAX_INPUT];
int bufferIndex = 0;

// UART data buffers
uint8_t uart0_buffer[MAX_UART_BUFFER];
int uart0_index = 0;
unsigned long last_uart0_flush = 0;
uint8_t uart1_buffer[MAX_UART_BUFFER];
int uart1_index = 0;
unsigned long last_uart1_flush = 0;

// Base64 encoding function
String base64_encode(const uint8_t* data, size_t len) {
  String encoded = "";
  
  for (size_t i = 0; i < len; i += 3) {
    uint8_t b1 = data[i];
    uint8_t b2 = (i + 1 < len) ? data[i + 1] : 0;
    uint8_t b3 = (i + 2 < len) ? data[i + 2] : 0;
    
    uint32_t n = ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | b3;
    
    encoded += base64_table[(n >> 18) & 0x3F];
    encoded += base64_table[(n >> 12) & 0x3F];
    
    if (i + 1 < len) {
      encoded += base64_table[(n >> 6) & 0x3F];
    } else {
      encoded += '=';
    }
    
    if (i + 2 < len) {
      encoded += base64_table[n & 0x3F];
    } else {
      encoded += '=';
    }
  }
  
  return encoded;
}

// Flush UART buffer with base64 encoding
void flush_uart_buffer(uint8_t uart_num, uint8_t* buffer, int* index, unsigned long* last_flush) {
  if (*index > 0) {
    String encoded = base64_encode(buffer, *index);
    Serial.print("[UART");
    Serial.print(uart_num);
    Serial.print"] ");
    Serial.println(encoded);
    *index = 0;
    *last_flush = millis();
  }
}

void setup() {
  Serial.begin(BAUD_RATE);
  delay(500); // Allow USB serial to stabilize
  
  Serial.println("\n=== Raspberry Pi Pico GPIO Controller + UART Sniffer ===");
  Serial.println("GPIO commands: toggle/on/off/read <pin>, input/output/pullup <pin>, help");
  Serial.println("UART Snooping active on GP1 (UART0/Serial1) and GP5 (UART1) @ 115200 baud");
  Serial.println("command:> ");
  
  // Initialize Serial1 (UART0) - default pins: GP0(TX), GP1(RX)
  Serial1.begin(SNIFF_BAUD);
  
  // Initialize UART1 on GP4(TX) and GP5(RX)
  uart_init(uart1, SNIFF_BAUD);
  gpio_set_function(4, GPIO_FUNC_UART);  // GP4 = UART1 TX
  gpio_set_function(5, GPIO_FUNC_UART);  // GP5 = UART1 RX

  digitalRead(9);
  digitalRead(8);
  digitalRead(7);
  digitalRead(6);
}

void loop() {
  unsigned long current_time = millis();
  
  // Sniff Serial1 (UART0 on GP1/RX)
  while (Serial1.available() > 0) {
    char c = Serial1.read();
    uart0_buffer[uart0_index++] = (uint8_t)c;
    
    // Flush buffer on newline or when full
    if (c == '\n' || uart0_index >= MAX_UART_BUFFER) {
      flush_uart_buffer(0, uart0_buffer, &uart0_index, &last_uart0_flush);
    }
  }
  
  // Flush UART0 if 100ms has elapsed
  if (uart0_index > 0 && current_time - last_uart0_flush >= 100) {
    flush_uart_buffer(0, uart0_buffer, &uart0_index, &last_uart0_flush);
  }
  
  // Sniff UART1 (on GP5/RX)
  while (uart_is_readable(uart1)) {
    uint8_t c = uart_getc(uart1);
    uart1_buffer[uart1_index++] = c;
    
    // Flush buffer on newline or when full
    if (c == '\n' || uart1_index >= MAX_UART_BUFFER) {
      flush_uart_buffer(1, uart1_buffer, &uart1_index, &last_uart1_flush);
    }
  }
  
  // Flush UART1 if 100ms has elapsed
  if (uart1_index > 0 && current_time - last_uart1_flush >= 100) {
    flush_uart_buffer(1, uart1_buffer, &uart1_index, &last_uart1_flush);
  }
  
  // Process GPIO commands from USB serial
  while (Serial.available() > 0) {
    char c = Serial.read();
    
    if (c == '\n' || c == '\r') {
      if (bufferIndex > 0) {
        inputBuffer[bufferIndex] = '\0';
        processCommand(inputBuffer);
        bufferIndex = 0;
        Serial.print("command:> ");
      }
    } else if (bufferIndex < MAX_INPUT - 1) {
      inputBuffer[bufferIndex++] = c;
    }
  }
}

void processCommand(char* cmd) {
  // Trim leading spaces
  while (*cmd == ' ') cmd++;
  
  if (strlen(cmd) == 0) return;
  
  // Parse command
  char* space = strchr(cmd, ' ');
  char* arg = NULL;
  
  if (space != NULL) {
    *space = '\0';
    arg = space + 1;
    while (*arg == ' ') arg++; // Trim leading spaces from argument
  }
  
  // Convert command to lowercase
  for (char* p = cmd; *p; p++) {
    *p = tolower(*p);
  }
  
  // Execute command
  if (strcmp(cmd, "help") == 0) {
    showHelp();
  } else if (strcmp(cmd, "toggle") == 0) {
    togglePin(arg);
  } else if (strcmp(cmd, "on") == 0) {
    setPin(arg, HIGH);
  } else if (strcmp(cmd, "off") == 0) {
    setPin(arg, LOW);
  } else if (strcmp(cmd, "read") == 0) {
    readPin(arg);
  } else if (strcmp(cmd, "input") == 0) {
    setPinMode(arg, INPUT);
  } else if (strcmp(cmd, "output") == 0) {
    setPinMode(arg, OUTPUT);
  } else if (strcmp(cmd, "pullup") == 0) {
    setPinMode(arg, INPUT_PULLUP);
  } else {
    Serial.print("Unknown command: ");
    Serial.println(cmd);
    Serial.println("Type 'help' for available commands");
  }
}

void showHelp() {
  Serial.println("\nAvailable commands:");
  Serial.println("  toggle <pin>     - Toggle GPIO pin");
  Serial.println("  on <pin>         - Set GPIO pin HIGH");
  Serial.println("  off <pin>        - Set GPIO pin LOW");
  Serial.println("  read <pin>       - Read GPIO pin state");
  Serial.println("  input <pin>      - Set pin as INPUT");
  Serial.println("  output <pin>     - Set pin as OUTPUT");
  Serial.println("  pullup <pin>     - Set pin as INPUT_PULLUP");
  Serial.println("  help             - Show this help message");
  Serial.println("\nValid GPIO pins: 0-28");
  Serial.println("Note: GPIO25 is typically connected to onboard LED");
  Serial.println("\nUART Snooping (running simultaneously):");
  Serial.println("  Serial1 on GP1 (UART0 RX) @ 115200 baud - labeled [UART0/GP1]");
  Serial.println("  uart1 on GP5 (UART1 RX) @ 115200 baud - labeled [UART1/GP5]");
}

int parsePin(char* arg) {
  if (arg == NULL || strlen(arg) == 0) {
    Serial.println("Error: Pin number required");
    return -1;
  }
  
  int pin = atoi(arg);
  
  if (pin < MIN_GPIO || pin > MAX_GPIO) {
    Serial.print("Error: Invalid pin ");
    Serial.print(pin);
    Serial.print(". Valid range: ");
    Serial.print(MIN_GPIO);
    Serial.print("-");
    Serial.println(MAX_GPIO);
    return -1;
  }
  
  return pin;
}

void togglePin(char* arg) {
  int pin = parsePin(arg);
  if (pin < 0) return;
  
  pinMode(pin, OUTPUT);
  int currentState = digitalRead(pin);
  int newState = !currentState;
  digitalWrite(pin, newState);
  
  Serial.print("GPIO");
  Serial.print(pin);
  Serial.print(" toggled: ");
  Serial.print(currentState ? "HIGH" : "LOW");
  Serial.print(" -> ");
  Serial.println(newState ? "HIGH" : "LOW");
}

void setPin(char* arg, int state) {
  int pin = parsePin(arg);
  if (pin < 0) return;
  
  pinMode(pin, OUTPUT);
  digitalWrite(pin, state);
  
  Serial.print("GPIO");
  Serial.print(pin);
  Serial.print(" set to ");
  Serial.println(state ? "HIGH" : "LOW");
}

void readPin(char* arg) {
  int pin = parsePin(arg);
  if (pin < 0) return;
  
  int state = digitalRead(pin);
  
  Serial.print("GPIO");
  Serial.print(pin);
  Serial.print(" is ");
  Serial.println(state ? "HIGH" : "LOW");
}

void setPinMode(char* arg, int mode) {
  int pin = parsePin(arg);
  if (pin < 0) return;
  
  pinMode(pin, mode);
  
  Serial.print("GPIO");
  Serial.print(pin);
  Serial.print(" set to ");
  if (mode == INPUT) {
    Serial.println("INPUT");
  } else if (mode == OUTPUT) {
    Serial.println("OUTPUT");
  } else if (mode == INPUT_PULLUP) {
    Serial.println("INPUT_PULLUP");
  }
}
