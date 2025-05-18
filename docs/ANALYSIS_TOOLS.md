# Android MITM Analysis Tools

This directory contains specialized tools for analyzing captured network traffic from Android applications, helping you reverse engineer and understand APIs, payloads, and protocols.

## Tool Overview

1. **Traffic Analyzer (`analyze_traffic.py`)**
   - Analyzes mitmproxy dump files to identify API patterns
   - Detects authentication mechanisms
   - Displays summary statistics of captured traffic
   - Identifies common parameters and data structures

2. **Payload Extractor (`extract_payloads.py`)**
   - Extracts request and response payloads from mitmproxy dumps
   - Organizes them by domain, endpoint, or flow
   - Creates metadata files with context information
   - Generates a summary report of extracted payloads

3. **Payload Decoder (`decode_payload.py`)**
   - Decodes various formats (Base64, URL encoding, gzip, etc.)
   - Detects encoding types automatically
   - Parses common data structures (JSON, XML, etc.)
   - Performs recursive decoding for multi-layered encodings

4. **Binary Format Analyzer (`analyze_binary.py`)**
   - Identifies binary data structure patterns
   - Detects common serialization formats (Protocol Buffers, Thrift, etc.)
   - Visualizes binary data structures
   - Generates parser templates for detected formats

5. **API Mapper (`map_api.py`)**
   - Generates API documentation from captured traffic
   - Creates sequence diagrams of API flows
   - Extracts JSON schema definitions
   - Produces interactive HTML reports

6. **Protocol Detector (`detect_protocol.py`)**
   - Identifies protocols used in mobile applications
   - Extracts protocol-specific details and patterns
   - Generates client code templates
   - Reverse engineers custom protocols

## Workflow

These tools are designed to work together in a cohesive analysis workflow:

1. **Capture Traffic**: Use the Android MITM SSL Interceptor to capture encrypted traffic
2. **Initial Analysis**: Run `analyze_traffic.py` to get an overview of API endpoints and patterns
3. **Extract Payloads**: Use `extract_payloads.py` to extract interesting payloads for deeper analysis
4. **Decode Payloads**: Use `decode_payload.py` to decode encoded or encrypted payloads
5. **Analyze Binary Formats**: For custom binary formats, use `analyze_binary.py` to understand the structure
6. **Detect Protocols**: Use `detect_protocol.py` to identify protocols and extract protocol-specific elements
7. **Document API**: Generate comprehensive API documentation with `map_api.py`

## Usage Examples

### Traffic Analysis

```bash
# Analyze a mitmproxy dump file
python analyze_traffic.py captured_traffic.mitm

# Generate detailed JSON output with payload decoding
python analyze_traffic.py --json --decode --output analysis.json captured_traffic.mitm
```

### Payload Extraction

```bash
# Extract all payloads
python extract_payloads.py captured_traffic.mitm

# Extract only JSON responses for a specific domain
python extract_payloads.py --filter api.example.com --type application/json captured_traffic.mitm

# Group by endpoint and attempt to decode payloads
python extract_payloads.py --group endpoint --decode captured_traffic.mitm
```

### Payload Decoding

```bash
# Auto-detect and decode a payload
python decode_payload.py payload.bin

# Force base64 decoding
python decode_payload.py --type base64 payload.bin

# Verbose analysis of all encoding layers
python decode_payload.py --verbose payload.bin
```

### Binary Format Analysis

```bash
# Analyze a binary file
python analyze_binary.py binary_payload.bin

# Extract strings and generate visualization
python analyze_binary.py --strings --visualize binary_payload.bin

# Generate a parser template for Protocol Buffers
python analyze_binary.py --format protobuf --template binary_payload.bin
```

### Protocol Detection

```bash
# Detect protocols used in traffic
python detect_protocol.py captured_traffic.mitm

# Force analysis as a specific protocol and extract elements
python detect_protocol.py --protocol graphql --extract captured_traffic.mitm

# Generate client code templates
python detect_protocol.py --generate --output client_code captured_traffic.mitm
```

### API Mapping

```bash
# Generate comprehensive API documentation
python map_api.py --output api_docs --format html,markdown,json captured_traffic.mitm

# Create sequence diagrams of API flows
python map_api.py --output api_flow --format diagram --sequence captured_traffic.mitm
```

## Advanced Techniques

### Finding Authentication Tokens

```bash
# Extract authentication-related payloads
python extract_payloads.py --filter "auth|token|login" captured_traffic.mitm

# Analyze extracted payloads
python analyze_traffic.py --filter "authorization" captured_traffic.mitm
```

### Identifying Custom Encryption

```bash
# Extract suspicious binary payloads
python extract_payloads.py --type application/octet-stream captured_traffic.mitm

# Analyze binary patterns
python analyze_binary.py --strings extracted_payloads/suspicious_payload.bin
```

### Correlating API Calls

```bash
# Generate a sequence diagram of API flows
python map_api.py --sequence --group flow captured_traffic.mitm
```

## Troubleshooting

If you encounter issues with any of the tools:

1. **SSL Pinning Bypass Failures**: Try using the advanced Frida script in the `scripts/frida_scripts/` directory
2. **Payload Decoding Failures**: Use the binary analyzer to identify the format first
3. **Large Capture Files**: Split the capture into smaller chunks or use the filter options
4. **Binary Format Detection**: Try specifying the format explicitly if auto-detection fails
5. **Protocol Detection Issues**: Use the `--verbose` flag to see detailed analysis information