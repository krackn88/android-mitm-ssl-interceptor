#!/usr/bin/env python3
"""
Payload Extractor - A utility for extracting and organizing request/response payloads from mitmproxy dumps

This tool can:
1. Extract all request/response bodies from a mitmproxy dump file
2. Organize them by domain, endpoint, or flow
3. Filter by content type, status code, or URL pattern
4. Automatically decode common formats
5. Generate summary reports of extracted payloads

Usage:
    python3 extract_payloads.py [options] <mitmproxy_dump_file>

Options:
    -o, --output DIR     Output directory for extracted payloads (default: ./extracted_payloads)
    -f, --filter STR     Filter by URL pattern
    -t, --type TYPE      Filter by content type (e.g., application/json)
    -s, --status CODE    Filter by response status code
    -g, --group BY       Group by: domain, endpoint, flow, or flat (default: endpoint)
    -d, --decode         Attempt to decode payloads (base64, gzip, etc.)
    -m, --max-size SIZE  Max file size to extract in KB (default: 10240)
    -v, --verbose        Verbose output
"""

import os
import sys
import json
import base64
import zlib
import gzip
import argparse
import re
import hashlib
import time
from io import BytesIO
from urllib.parse import urlparse, unquote
from collections import defaultdict
from datetime import datetime

try:
    from mitmproxy import io
    from mitmproxy.exceptions import FlowReadException
except ImportError:
    io = None

    class FlowReadException(Exception):
        """Fallback exception used when mitmproxy is unavailable."""

        pass


class PayloadExtractor:
    def __init__(self, options):
        self.options = options
        self.base_dir = options.output
        self.stats = {
            "total_flows": 0,
            "extracted_requests": 0,
            "extracted_responses": 0,
            "bytes_extracted": 0,
            "domains": set(),
            "content_types": defaultdict(int),
            "status_codes": defaultdict(int),
            "endpoints": defaultdict(int)
        }
        
    def extract_payloads(self, dump_file):
        """Extract payloads from a mitmproxy dump file"""
        print(f"Processing {dump_file}...")

        if not os.path.isfile(dump_file):
            print(f"Error: file not found: {dump_file}", file=sys.stderr)
            sys.exit(1)
        
        # Create output directory
        os.makedirs(self.base_dir, exist_ok=True)
        
        # Process each flow as it is read to avoid loading large captures into memory
        for flow in self._read_flows(dump_file):
            self._process_flow(flow)
        
        # Generate summary report
        self._generate_summary()
        
        print(f"Extracted {self.stats['extracted_requests']} requests and {self.stats['extracted_responses']} responses")
        print(f"Total extracted: {self._format_size(self.stats['bytes_extracted'])}")
        print(f"Summary written to {os.path.join(self.base_dir, 'summary.json')}")
    
    def _read_flows(self, dump_file):
        """Read flows from a mitmproxy dump file"""
        if io is None:
            print("Error: mitmproxy package not found. Install with: pip install mitmproxy", file=sys.stderr)
            sys.exit(1)

        try:
            with open(dump_file, "rb") as f:
                freader = io.FlowReader(f)
                for flow in freader.stream():
                    if flow.request and flow.response:
                        # Apply filters
                        if self._apply_filters(flow):
                            self.stats["total_flows"] += 1
                            yield flow
        except FlowReadException as e:
            print(f"Error reading flow file: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _apply_filters(self, flow):
        """Apply configured filters to a flow"""
        # URL filter
        if self.options.filter and self.options.filter not in flow.request.url:
            return False
        
        # Content type filter
        if self.options.type:
            req_type = flow.request.headers.get("content-type", "")
            resp_type = flow.response.headers.get("content-type", "")
            if self.options.type not in req_type and self.options.type not in resp_type:
                return False
        
        # Status code filter
        if self.options.status is not None and self.options.status != flow.response.status_code:
            return False
        
        return True
    
    def _process_flow(self, flow):
        """Process a single flow and extract payloads"""
        req = flow.request
        resp = flow.response
        
        # Parse URL
        url_parts = urlparse(req.url)
        domain = url_parts.netloc
        path = url_parts.path
        
        # Create a flow identifier
        flow_id = hashlib.md5(f"{req.url}-{flow.timestamp_start}".encode()).hexdigest()
        
        # Track statistics
        self.stats["domains"].add(domain)
        self.stats["status_codes"][resp.status_code] += 1
        
        # Determine grouping path
        if self.options.group == "domain":
            group_path = domain
        elif self.options.group == "endpoint":
            # Normalize path by replacing IDs with placeholders
            normalized_path = self._normalize_path(path)
            group_path = os.path.join(domain, normalized_path.strip("/").replace("/", "_"))
        elif self.options.group == "flow":
            # Use timestamp to create flow directory
            timestamp = datetime.fromtimestamp(flow.timestamp_start).strftime("%Y%m%d_%H%M%S")
            group_path = os.path.join(domain, timestamp + "_" + flow_id[:8])
        else:  # flat
            group_path = ""
        
        # Create directory for the group
        group_dir = os.path.join(self.base_dir, group_path)
        os.makedirs(group_dir, exist_ok=True)
        
        # Process request payload
        if req.content and len(req.content) > 0:
            req_content_type = req.headers.get("content-type", "")
            self.stats["content_types"][req_content_type] += 1
            
            # Skip if too large
            if len(req.content) > self.options.max_size * 1024:
                if self.options.verbose:
                    print(f"Skipping large request: {req.url} ({len(req.content)} bytes)")
            else:
                # Create filename based on method, path and timestamp
                timestamp = datetime.fromtimestamp(flow.timestamp_start).strftime("%Y%m%d_%H%M%S")
                filename_base = f"{timestamp}_{req.method}_{self._safe_filename(path)}"
                
                # Add content type to filename if available
                if req_content_type:
                    ct_suffix = req_content_type.split(";")[0].split("/")[-1].replace("+", "_")
                    filename = f"{filename_base}_req.{ct_suffix}"
                else:
                    filename = f"{filename_base}_req.bin"
                
                # Extract payload
                payload_path = os.path.join(group_dir, filename)
                decoded_content = self._decode_payload(req.content, req_content_type) if self.options.decode else req.content
                
                with open(payload_path, "wb") as f:
                    f.write(decoded_content)
                
                self.stats["extracted_requests"] += 1
                self.stats["bytes_extracted"] += len(decoded_content)
                
                # Create metadata file
                metadata = {
                    "url": req.url,
                    "method": req.method,
                    "timestamp": flow.timestamp_start,
                    "date": datetime.fromtimestamp(flow.timestamp_start).isoformat(),
                    "headers": dict(req.headers),
                    "content_type": req_content_type,
                    "content_length": len(req.content),
                    "decoded": self.options.decode,
                    "flow_id": flow_id
                }
                
                metadata_path = os.path.join(group_dir, f"{filename}.meta.json")
                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=2)
        
        # Process response payload
        if resp.content and len(resp.content) > 0:
            resp_content_type = resp.headers.get("content-type", "")
            self.stats["content_types"][resp_content_type] += 1
            
            # Skip if too large
            if len(resp.content) > self.options.max_size * 1024:
                if self.options.verbose:
                    print(f"Skipping large response: {req.url} ({len(resp.content)} bytes)")
            else:
                # Create filename based on method, path, timestamp and status
                timestamp = datetime.fromtimestamp(flow.timestamp_start).strftime("%Y%m%d_%H%M%S")
                filename_base = f"{timestamp}_{req.method}_{self._safe_filename(path)}"
                
                # Add content type to filename if available
                if resp_content_type:
                    ct_suffix = resp_content_type.split(";")[0].split("/")[-1].replace("+", "_")
                    filename = f"{filename_base}_resp_{resp.status_code}.{ct_suffix}"
                else:
                    filename = f"{filename_base}_resp_{resp.status_code}.bin"
                
                # Extract payload
                payload_path = os.path.join(group_dir, filename)
                decoded_content = self._decode_payload(resp.content, resp_content_type) if self.options.decode else resp.content
                
                with open(payload_path, "wb") as f:
                    f.write(decoded_content)
                
                self.stats["extracted_responses"] += 1
                self.stats["bytes_extracted"] += len(decoded_content)
                
                # Create metadata file
                metadata = {
                    "url": req.url,
                    "method": req.method,
                    "status_code": resp.status_code,
                    "timestamp": flow.timestamp_start,
                    "date": datetime.fromtimestamp(flow.timestamp_start).isoformat(),
                    "headers": dict(resp.headers),
                    "content_type": resp_content_type,
                    "content_length": len(resp.content),
                    "decoded": self.options.decode,
                    "flow_id": flow_id
                }
                
                metadata_path = os.path.join(group_dir, f"{filename}.meta.json")
                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=2)
                
                # Track endpoint statistics
                endpoint = f"{req.method} {self._normalize_path(path)}"
                self.stats["endpoints"][endpoint] += 1
    
    def _decode_payload(self, content, content_type):
        """Attempt to decode payload based on content type and payload characteristics"""
        # If it's a JSON content type, no need to decode further
        if content_type and "json" in content_type.lower():
            return content
        
        # Try to detect and decode common formats
        # Check for gzip
        if content.startswith(b'\x1f\x8b'):
            try:
                with gzip.GzipFile(fileobj=BytesIO(content), mode='rb') as f:
                    return f.read()
            except Exception:
                pass
        
        # Check for zlib
        try:
            return zlib.decompress(content)
        except zlib.error:
            try:
                return zlib.decompress(content, -zlib.MAX_WBITS)
            except Exception:
                pass
        
        # Check for base64
        try:
            # Only try base64 if the content looks like it (only contains valid chars)
            if all(c in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in content):
                decoded = base64.b64decode(content)
                # Only return if it decoded to something different
                if decoded != content:
                    return decoded
        except Exception:
            pass
        
        # No successful decoding
        return content
    
    def _normalize_path(self, path):
        """Normalize paths by replacing likely IDs with placeholders"""
        # Replace UUIDs first to avoid partial replacement of leading digits
        normalized = re.sub(
            r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            '/{uuid}',
            path,
        )

        # Replace numeric segments in path
        normalized = re.sub(r'/\d+(?=/|$)', '/{id}', normalized)
        
        # Replace long hex strings
        normalized = re.sub(r'/[0-9a-fA-F]{16,}', '/{hash}', normalized)
        
        return normalized
    
    def _safe_filename(self, path):
        """Create a safe filename from a path"""
        # Remove leading and trailing slashes
        path = path.strip("/")
        
        # Replace slashes with underscores
        path = path.replace("/", "_")
        
        # Replace other unsafe characters
        path = re.sub(r'[^a-zA-Z0-9_.-]', '_', path)
        
        # Limit length
        if len(path) > 100:
            path = path[:50] + "__" + hashlib.md5(path.encode()).hexdigest()[:8]
        
        return path
    
    def _generate_summary(self):
        """Generate a summary report of extracted payloads"""
        summary = {
            "timestamp": time.time(),
            "date": datetime.now().isoformat(),
            "statistics": {
                "total_flows": self.stats["total_flows"],
                "extracted_requests": self.stats["extracted_requests"],
                "extracted_responses": self.stats["extracted_responses"],
                "total_bytes": self.stats["bytes_extracted"],
                "domains": list(self.stats["domains"]),
                "content_types": dict(self.stats["content_types"]),
                "status_codes": dict(self.stats["status_codes"]),
                "top_endpoints": dict(sorted(self.stats["endpoints"].items(), key=lambda x: x[1], reverse=True)[:20])
            }
        }
        
        summary_path = os.path.join(self.base_dir, "summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
    
    def _format_size(self, size):
        """Format byte size to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024 or unit == 'GB':
                return f"{size:.2f} {unit}"
            size /= 1024


def main():
    parser = argparse.ArgumentParser(description="Extract payloads from mitmproxy dumps")
    parser.add_argument("dump_file", help="mitmproxy dump file to process")
    parser.add_argument("-o", "--output", default="./extracted_payloads", help="Output directory for extracted payloads")
    parser.add_argument("-f", "--filter", help="Filter by URL pattern")
    parser.add_argument("-t", "--type", help="Filter by content type")
    parser.add_argument("-s", "--status", type=int, help="Filter by response status code")
    parser.add_argument("-g", "--group", default="endpoint", choices=["domain", "endpoint", "flow", "flat"], help="How to group extractions")
    parser.add_argument("-d", "--decode", action="store_true", help="Attempt to decode payloads")
    parser.add_argument("-m", "--max-size", type=int, default=10240, help="Max file size to extract in KB")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    extractor = PayloadExtractor(args)
    extractor.extract_payloads(args.dump_file)


if __name__ == "__main__":
    main()
