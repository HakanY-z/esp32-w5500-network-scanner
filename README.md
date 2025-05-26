# esp32-w5500-network-scanner  
Advanced IP scanner based on ESP32 + W5500

## ESP32-WROOM-32 + W5500 USR-ES1 / W5500 Lite IP Scanner

**Description**  
This project provides a web interface over ESP32-WROOM-32 (in Access Point mode) to scan Ethernet networks using the W5500 USR-ES1 or W5500 Lite module. It detects active devices, their IP and MAC addresses, manufacturer information, and open TCP ports.

## Features
- ARP-based MAC address detection  
- TCP port scanning  
- Real-time updates using WebSocket  
- Static web interface served via SPIFFS  

## Hardware Modules
- **ESP32-WROOM-32** (Access Point & Web Server)  
- **W5500 USR-ES1** or **W5500 Lite** (Ethernet network scanner)

## Hardware Connections

| ESP32-WROOM-32 Pin | W5500 USR-ES1 / W5500 Lite Pin | Description      |
|--------------------|--------------------------------|------------------|
| 3V3                | VCC                            | Power (3.3V)     |
| GND                | GND                            | Ground           |
| GPIO18             | SCK                            | SPI Clock        |
| GPIO19             | MISO                           | SPI MISO         |
| GPIO23             | MOSI                           | SPI MOSI         |
| GPIO5              | CS                             | SPI Chip Select  |

> **Note:** Use jumper wires or a breadboard for the connections.  
> Make sure the W5500 module is connected to a router or switch via Ethernet.

## Software Setup

1. **Install ESP32 Board Package in Arduino IDE**  
   - Go to **File → Preferences → Additional Boards Manager URLs**  
     and add:  
     ```
     https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
     ```
   - Then go to **Tools → Board → Boards Manager** and install “esp32 by Espressif Systems”.

2. **Required Libraries**  
   Install the following libraries via **Tools → Manage Libraries**:  
   - **Ethernet2** (for W5500 support)  
   - **ArduinoJson**  
   - **WebSockets by Markus Sattler**  
   - **SPIFFS** (comes built-in with the ESP32 board package)

3. **Install SPIFFS Uploader Plugin**  
   - Download `esp32fs.jar` from [ESP32FS GitHub repo](https://github.com/me-no-dev/arduino-esp32fs-plugin)  
   - Place it under `Arduino/tools/ESP32FS/tool/`  
   - Restart Arduino IDE  
   - You should now see **Tools → ESP32 Sketch Data Upload**

4. **Upload Web Interface Files to SPIFFS**  
   - Create a `data/` folder in your project root  
   - Place your `index.html` (and other frontend files) inside it  
   - Use **Tools → ESP32 Sketch Data Upload** to flash them to SPIFFS

5. **Compile and Upload the Code**  
   - Select **Tools → Board → ESP32 Dev Module**  
   - Select the correct **Tools → Port** (matching your ESP32)  
   - Make sure SSID/password and pin assignments in `main.cpp` are correct  
   - Click **Upload**  
   - Open Serial Monitor (baud rate: 115200) for debug output

## Usage

1. Once powered, the ESP32 will start broadcasting a Wi-Fi network named `ESP32_Scanner`  
2. Connect to it using your phone or computer  
3. Open your browser and go to `http://192.168.4.1`  
4. Click **Get Network Info** to auto-fill the IP range  
5. Click **Start Scan** to begin scanning and view results in real time

## File Structure
├─ data/index.html # Static web interface
├─ NetworkScanner.ino # Arduino sketch
├─ README.md # Project documentation
└─ .gitignore # Ignores build and temporary files