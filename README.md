# Rogue Wi-Fi Monitoring System

This project implements a Wi-Fi monitoring and preliminary detection logic system for Phase 1 of the rogue access point detection project.

## What it does
- Continuously scans nearby wireless networks
- Tracks SSID, BSSID, signal strength, channel/frequency, security type, and timestamps
- Maintains historical profiles for each network
- Detects duplicate SSIDs, parameter inconsistencies, signal anomalies, and transient networks
- Assigns a cumulative risk score and classification (low, moderate, high)
- Prints structured real-time console output and logs events to files

## Files
- `wifi_monitor.py` - main monitoring application
- `README.md` - project overview and usage
- `context/phase1.txt` - original phase 1 prompt

## Usage
Run the monitor with Python:

```bash
python wifi_monitor.py
```

For simulation mode (useful when a real Wi-Fi scan is not available):

```bash
python wifi_monitor.py --simulate
```

## Notes
- On Windows, the script uses `netsh wlan show networks mode=bssid` for scanning.
- On Linux, the script uses `nmcli device wifi list`.
- The system is designed to be modular so it can support a second device or richer detection logic later.

## Logs
- `wifi_monitor.log` - general scan and error log
- `wifi_monitor_events.log` - anomaly and event trace log
