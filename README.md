# EASUN ISOLAR SMX II - Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/custom-components/hacs)
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)

Home Assistant custom integration for EASUN ISOLAR SMX II solar inverters with WiFi Plug Pro datalogger.

## Features

- 📊 **Real-time monitoring** of all inverter parameters
- ⚡ **Control buttons** for inverter management
- 🔋 **Battery management** including equalization
- 🌐 **Local network communication** - no cloud required
- 🔄 **Automatic reconnection** handling
- 📈 **Energy statistics** tracking

## Supported Devices

- EASUN ISOLAR SMX II (all power ratings: 3.6kW, 5.6kW, etc.)
- SRNE Solar HF series (uses same protocol)
- Any inverter using WiFi Plug Pro datalogger

## Requirements

- Home Assistant 2023.1 or newer
- EASUN inverter with WiFi Plug Pro adapter
- Inverter connected to your local network
- Python 3.11+

## Installation

### Method 1: HACS (Recommended)

1. Open HACS in Home Assistant
2. Click on "Integrations"
3. Click the three dots in the top right corner
4. Select "Custom repositories"
5. Add this repository URL: `https://github.com/YOUR_USERNAME/easun_smx`
6. Select category: "Integration"
7. Click "Add"
8. Find "EASUN ISOLAR SMX II" in HACS and click "Download"
9. Restart Home Assistant

### Method 2: Manual Installation

1. Download the latest release from GitHub
2. Copy the `custom_components/easun_smx` folder to your Home Assistant `config/custom_components/` directory
3. Restart Home Assistant

```bash
cd /config
mkdir -p custom_components
cd custom_components
git clone https://github.com/YOUR_USERNAME/easun_smx.git
# Or download and extract the ZIP file
```

## Configuration

### Step 1: Find Your Inverter IP Address

The WiFi Plug Pro adapter should be connected to your local network. Find its IP address from your router's DHCP client list.

### Step 2: Add Integration

1. Go to **Settings** → **Devices & Services**
2. Click **+ Add Integration**
3. Search for "EASUN ISOLAR SMX II"
4. Enter your inverter's IP address (e.g., `172.16.4.27`)
5. Port is automatically set to `502` (Modbus TCP default)
6. Click **Submit**

### Step 3: Wait for Connection

The integration will:
1. Create a TCP server on your Home Assistant machine
2. Send a UDP broadcast to the datalogger
3. Wait for the datalogger to connect back
4. If the datalogger is already connected to another server, it will automatically disconnect and reconnect to Home Assistant

**Note:** The initial connection may take up to 30 seconds.

## Available Entities

### Sensors (Read-only)

#### Power & Energy
- PV Voltage, Current, Power
- Battery Voltage, Current, SOC (State of Charge)
- Load Voltage, Current, Active Power, Apparent Power
- Line Voltage, Current, Frequency
- Inverter Current, Frequency

#### Status
- Machine State (Power on, Standby, Running, etc.)
- Current Faults (detailed error messages)
- Battery Charge Step
- Load Ratio

#### Temperature
- DC Temperature
- AC Temperature
- Transformer Temperature

#### Statistics
- Daily/Cumulative PV Generation
- Daily/Cumulative Load Consumption
- Daily/Cumulative Battery Charge/Discharge
- Battery Charge/Discharge Hours

#### Configuration (Read-only)
- Output Priority (SOL/UTI/SBU)
- Charger Source Priority (CSO/CUB/SNU/OSO)
- Battery Type
- Various voltage/current limits

### Buttons (Actions)

- **Start Battery Equalization** - Initiates battery equalization cycle
- **Reset Machine** - Soft reset of the inverter
- **Shutdown Machine** - Powers down the inverter
- **Boot Machine** - Powers up the inverter

## Troubleshooting

### Connection Issues

#### Error: "Timeout: Datalogger did not connect via TCP within 30 seconds"

**Possible causes:**
1. Inverter is not powered on or not connected to network
2. Incorrect IP address
3. Firewall blocking UDP port 58899 or TCP port 8900
4. Datalogger already connected to another server (e.g., SmartESS app)

**Solutions:**
- Verify the inverter IP address is correct
- Check that the inverter is powered on and WiFi LED is lit
- Ensure no firewall is blocking ports 58899 (UDP) and 8900 (TCP)
- Close SmartESS app if running
- Try restarting the integration
- Power cycle the WiFi Plug Pro adapter

#### Error: "Failed to bind TCP server"

The TCP port 8900 is already in use.

**Solution:**
- Restart Home Assistant to free up the port
- Check if another instance of the integration is running

### Data Issues

#### Sensors showing "Unknown" or "Unavailable"

**Solutions:**
- Check Home Assistant logs for errors
- Verify the inverter is responding (check Machine State sensor)
- Restart the integration
- Check network connectivity

#### CRC Errors in Logs

Occasional CRC errors are normal due to serial communication noise. If frequent:
- Check RS485 cable connection between inverter and WiFi adapter
- Try power cycling the WiFi adapter
- Check for electromagnetic interference near the inverter

## Network Configuration

### Ports Used

- **UDP 58899** - Command port for datalogger configuration
- **TCP 8900** - Data communication port (configurable in code)

### Firewall Rules

If you have a firewall, allow:
```bash
# Incoming UDP on port 58899
ufw allow 58899/udp

# Incoming TCP on port 8900
ufw allow 8900/tcp
```

## Advanced Configuration

### Changing Scan Interval

The default scan interval is 30 seconds. To change it, modify `const.py`:

```python
DEFAULT_SCAN_INTERVAL = 30  # Change to desired seconds
```

### Changing TCP Port

If port 8900 is in use, you can change it in `modbus_client.py`:

```python
self._tcp_port = 8900  # Change to desired port
```

## Protocol Information

This integration uses a custom Modbus TCP protocol specific to EASUN inverters with WiFi Plug Pro:

1. **UDP Discovery**: Sends `set>server=IP:PORT;` to configure datalogger
2. **TCP Connection**: Datalogger connects back to Home Assistant
3. **Modbus Encapsulation**: Modbus RTU packets wrapped in Modbus TCP frames
4. **Register Access**: Standard Modbus function codes (0x03 read, 0x10 write)

Based on reverse engineering work by [suletom](https://github.com/suletom/EASUN-ISOLAR-SMX-II-CONTROL).

## Known Limitations

- Only one client can connect to the datalogger at a time
- SmartESS app cannot be used simultaneously
- Some advanced parameters are read-only (firmware limitation)
- Connection may drop occasionally (automatic reconnection implemented)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

⚠️ **Use at your own risk!** This integration can control your inverter. Incorrect settings may damage your equipment or void your warranty. Always verify settings before applying changes.

## Changelog

### Version 1.0.0 (2024-11-10)
- Initial release
- Full sensor support for all inverter parameters
- Control buttons for inverter management
- Automatic reconnection handling
- Support for datalogger server switching
