# Android MITM SSL Interceptor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive toolkit for intercepting, analyzing, and reverse engineering Android application traffic. Perfect for security research, app testing, and API analysis.

## Overview

This toolkit provides a complete workflow for:

1. Setting up an Android emulator with Man-in-the-Middle capabilities
2. Intercepting and decrypting SSL/TLS traffic from Android applications
3. Analyzing APIs, payloads, and protocols
4. Reverse engineering complex binary formats and custom protocols
5. Generating documentation and client code

## Features

- **Complete Environment**: Sets up everything you need in one go
- **SSL Pinning Bypass**: Advanced Frida scripts to bypass certificate pinning
- **Traffic Analysis**: Identify API patterns, parameters, and authentication mechanisms
- **Payload Extraction**: Organize captured payloads for detailed analysis
- **Protocol Detection**: Automatically identify REST, GraphQL, gRPC, WebSockets, MQTT, and custom protocols
- **Binary Analysis**: Reverse engineer custom binary formats and encoded data
- **API Mapping**: Generate comprehensive documentation of discovered APIs

## Getting Started

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/android-mitm-ssl-interceptor.git
cd android-mitm-ssl-interceptor

# Make the setup script executable
chmod +x setup_android_mitm.sh

# Run the setup script
./setup_android_mitm.sh
```

### Basic Usage

1. **Capture Traffic**:
   ```bash
   # Install your APK
   adb install /path/to/your.apk
   
   # Bypass SSL pinning
   objection -g com.example.app explore
   # In the objection console
   android sslpinning disable
   
   # Capture traffic
   mitmdump -w captured_traffic.mitm
   ```

2. **Analyze Traffic**:
   ```bash
   python analyze_traffic.py captured_traffic.mitm
   ```

3. **Extract Payloads**:
   ```bash
   python extract_payloads.py captured_traffic.mitm
   ```

4. **Detect Protocols**:
   ```bash
   python detect_protocol.py captured_traffic.mitm
   ```

5. **Decode Payloads**:
   ```bash
   python decode_payload.py payload.bin
   ```

6. **Map API**:
   ```bash
   python map_api.py --output api_docs captured_traffic.mitm
   ```

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [Analysis Workflow](docs/ANALYSIS_WORKFLOW.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Advanced Configuration](docs/ADVANCED.md)

## Tool Reference

### Analysis Tools

- **analyze_traffic.py**: Analyze mitmproxy dump files to identify API patterns
- **extract_payloads.py**: Extract and organize request/response payloads
- **decode_payload.py**: Decode various encoding formats
- **analyze_binary.py**: Identify binary data structures
- **map_api.py**: Generate API documentation
- **detect_protocol.py**: Identify and reverse engineer protocols

### Frida Scripts

- **ssl_pinning_bypass.js**: Advanced SSL pinning bypass script

## Use Cases

- Security research and penetration testing
- Reverse engineering of mobile apps
- API documentation and testing
- Debugging network-related issues
- Educational purposes for understanding mobile security

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and research purposes only. Always obtain proper authorization before analyzing any application. The authors are not responsible for any misuse of this tool.