# Android MITM Analysis Tools

This directory contains helper scripts for working with captured mitmproxy traffic.

## Available tools

- `analyze_traffic.py` - Analyze endpoints, status codes, auth patterns, and content types.
- `extract_payloads.py` - Extract request/response payloads to a directory with metadata and summary stats.

## Requirements

Install requirements with:

```bash
pip install -r tools/requirements.txt
```

## Example usage

```bash
python tools/analyze_traffic.py capture.mitm
python tools/extract_payloads.py --decode --group endpoint capture.mitm
```
