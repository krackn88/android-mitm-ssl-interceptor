#!/usr/bin/env python3
"""
Traffic Analyzer for Android MITM SSL Interceptor

This script processes mitmproxy dump files and provides analysis of:
- API endpoints
- Request/response patterns
- Authentication mechanisms
- Data structures and formats
- Common parameters and headers

Usage:
    python3 analyze_traffic.py [options] <mitmproxy-dump-file>

Options:
    -j, --json          Output results in JSON format
    -o, --output FILE   Write results to FILE instead of stdout
    -f, --filter STR    Filter by URL pattern
    -d, --decode        Attempt to decode encoded/encrypted payloads
    -v, --verbose       Increase output verbosity
"""

import os
import sys
import json
import base64
import zlib
import argparse
import re
from urllib.parse import urlparse, parse_qs
from collections import defaultdict, Counter
import time
from datetime import datetime

try:
    from mitmproxy import io
    from mitmproxy.exceptions import FlowReadException
except ImportError:
    print("Error: mitmproxy package not found. Install with: pip install mitmproxy", file=sys.stderr)
    sys.exit(1)


class TrafficAnalyzer:
    def __init__(self, options):
        self.options = options
        self.endpoints = {}
        self.auth_headers = {}
        self.cookies = set()
        self.content_types = set()
        self.domains = set()
        self.status_codes = Counter()
        self.api_patterns = {}
        self.auth_mechanisms = {}
        
    def read_flows(self, flow_file):
        """Read flows from a mitmproxy dump file"""
        try:
            with open(flow_file, "rb") as f:
                freader = io.FlowReader(f)
                for flow in freader.stream():
                    if flow.request and flow.response:
                        # Filter by URL if specified
                        if self.options.filter and self.options.filter not in flow.request.url:
                            continue
                        yield flow
        except FlowReadException as e:
            print(f"Error reading flow file: {e}", file=sys.stderr)
            sys.exit(1)
            
    def analyze_flows(self, flow_file):
        """Main analysis function"""
        print(f"Analyzing traffic from {flow_file}...")
        
        for flow in self.read_flows(flow_file):
            self._analyze_flow(flow)
            
        self._identify_api_patterns()
        self._identify_auth_mechanisms()
        
        return self._prepare_results()
    
    def _analyze_flow(self, flow):
        """Analyze a single flow"""
        # Extract domain
        req = flow.request
        url_parts = urlparse(req.url)
        domain = url_parts.netloc
        path = url_parts.path
        
        self.domains.add(domain)
        self.status_codes[flow.response.status_code] += 1
        
        # Extract endpoint
        endpoint_key = f"{req.method} {self._normalize_path(path)}"
        
        # Initialize endpoint if not seen before
        if endpoint_key not in self.endpoints:
            self.endpoints[endpoint_key] = {
                "domain": domain,
                "path": self._normalize_path(path),
                "method": req.method,
                "count": 0,
                "parameters": set(),
                "status_codes": Counter(),
                "headers": set(),
                "content_types": set(),
                "response_types": set(),
                "sample_url": req.url
            }
        
        self.endpoints[endpoint_key]["count"] += 1
        self.endpoints[endpoint_key]["status_codes"][flow.response.status_code] += 1
        
        # Extract query parameters
        query_params = parse_qs(url_parts.query)
        for param in query_params:
            self.endpoints[endpoint_key]["parameters"].add(param)
        
        # Extract headers
        for header, value in req.headers.items():
            header_lower = header.lower()
            self.endpoints[endpoint_key]["headers"].add(header_lower)
            
            # Look for auth headers
            if header_lower in ("authorization", "x-api-key", "api-key", "token", "x-auth", "auth"):
                if header_lower not in self.auth_headers:
                    self.auth_headers[header_lower] = {
                        "count": 0,
                        "samples": set()
                    }
                
                self.auth_headers[header_lower]["count"] += 1
                
                # Store sample (remove sensitive info for display)
                if len(self.auth_headers[header_lower]["samples"]) < 3:
                    # Try to get just the auth type (e.g., "Bearer") without the token
                    if " " in value and header_lower == "authorization":
                        auth_type = value.split(" ")[0]
                        self.auth_headers[header_lower]["samples"].add(f"{auth_type} [TOKEN]")
                    else:
                        # For other auth headers, just store the pattern
                        self.auth_headers[header_lower]["samples"].add("[AUTH VALUE]")
        
        # Extract content types
        req_content_type = req.headers.get("content-type", "")
        resp_content_type = flow.response.headers.get("content-type", "")
        
        if req_content_type:
            self.content_types.add(req_content_type)
            self.endpoints[endpoint_key]["content_types"].add(req_content_type)
        
        if resp_content_type:
            self.content_types.add(resp_content_type)
            self.endpoints[endpoint_key]["response_types"].add(resp_content_type)
        
        # Extract cookies
        if "cookie" in req.headers:
            cookie_header = req.headers["cookie"]
            cookie_pairs = cookie_header.split(";")
            for pair in cookie_pairs:
                if "=" in pair:
                    name = pair.split("=")[0].strip()
                    self.cookies.add(name)
        
        # Extract request body parameters (JSON or form)
        if req.content and len(req.content) > 0:
            if "application/json" in req_content_type:
                try:
                    body = json.loads(req.content)
                    if isinstance(body, dict):
                        for key in body.keys():
                            self.endpoints[endpoint_key]["parameters"].add(key)
                except:
                    pass
            elif "x-www-form-urlencoded" in req_content_type:
                try:
                    form_data = parse_qs(req.content.decode('utf-8'))
                    for key in form_data.keys():
                        self.endpoints[endpoint_key]["parameters"].add(key)
                except:
                    pass
    
    def _normalize_path(self, path):
        """Normalize paths by replacing likely IDs with placeholders"""
        # Replace numeric segments in path
        normalized = re.sub(r'/\d+', '/{id}', path)
        
        # Replace UUIDs
        normalized = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}', normalized)
        
        # Replace long hex strings
        normalized = re.sub(r'/[0-9a-f]{16,}', '/{hash}', normalized)
        
        return normalized
    
    def _identify_api_patterns(self):
        """Identify patterns in API endpoints"""
        # Group endpoints by common patterns
        pattern_groups = defaultdict(list)
        
        for endpoint_key, endpoint in self.endpoints.items():
            path_parts = endpoint["path"].split('/')
            pattern = []
            
            for part in path_parts:
                if part in ('', '{id}', '{uuid}', '{hash}'):
                    pattern.append(part if part else "root")
                else:
                    pattern.append(part)
            
            pattern_key = '/'.join(pattern)
            pattern_groups[pattern_key].append(endpoint_key)
        
        # Analyze each pattern group
        for pattern_key, endpoint_keys in pattern_groups.items():
            if len(endpoint_keys) > 0:
                self.api_patterns[pattern_key] = {
                    "endpoints": endpoint_keys,
                    "methods": set(),
                    "count": sum(self.endpoints[key]["count"] for key in endpoint_keys),
                    "parameters": set(),
                }
                
                # Collect methods and parameters
                for key in endpoint_keys:
                    self.api_patterns[pattern_key]["methods"].add(self.endpoints[key]["method"])
                    self.api_patterns[pattern_key]["parameters"].update(self.endpoints[key]["parameters"])
    
    def _identify_auth_mechanisms(self):
        """Identify authentication mechanisms"""
        # Check for common auth headers
        if self.auth_headers:
            for header, details in self.auth_headers.items():
                mech_name = header.replace("-", "_")
                self.auth_mechanisms[mech_name] = {
                    "type": "header",
                    "header": header,
                    "count": details["count"],
                    "samples": list(details["samples"])
                }
        
        # Check for common auth cookie patterns
        auth_cookie_names = ("session", "token", "auth", "jwt", "access")
        auth_cookies = [cookie for cookie in self.cookies if any(auth in cookie.lower() for auth in auth_cookie_names)]
        
        if auth_cookies:
            self.auth_mechanisms["cookie_auth"] = {
                "type": "cookie",
                "cookies": auth_cookies
            }
        
        # Check for common auth endpoints
        auth_endpoints = []
        for endpoint_key, endpoint in self.endpoints.items():
            path = endpoint["path"].lower()
            if any(auth_path in path for auth_path in ('/login', '/auth', '/token', '/signin', '/oauth')):
                auth_endpoints.append(endpoint_key)
        
        if auth_endpoints:
            self.auth_mechanisms["auth_endpoints"] = {
                "type": "endpoint",
                "endpoints": auth_endpoints
            }
    
    def _prepare_results(self):
        """Prepare final analysis results"""
        # Basic statistics
        stats = {
            "total_flows": sum(endpoint["count"] for endpoint in self.endpoints.values()),
            "unique_endpoints": len(self.endpoints),
            "domains": list(self.domains),
            "status_codes": {str(code): count for code, count in self.status_codes.items()},
            "content_types": list(self.content_types),
            "auth_mechanisms": self.auth_mechanisms
        }
        
        # Convert sets to lists for JSON serialization
        endpoints = {}
        for key, endpoint in self.endpoints.items():
            endpoints[key] = {
                "domain": endpoint["domain"],
                "path": endpoint["path"],
                "method": endpoint["method"],
                "count": endpoint["count"],
                "parameters": list(endpoint["parameters"]),
                "status_codes": {str(code): count for code, count in endpoint["status_codes"].items()},
                "headers": list(endpoint["headers"]),
                "content_types": list(endpoint["content_types"]),
                "response_types": list(endpoint["response_types"]),
                "sample_url": endpoint["sample_url"]
            }
        
        patterns = {}
        for key, pattern in self.api_patterns.items():
            patterns[key] = {
                "endpoints": pattern["endpoints"],
                "methods": list(pattern["methods"]),
                "count": pattern["count"],
                "parameters": list(pattern["parameters"])
            }
        
        results = {
            "timestamp": time.time(),
            "date": datetime.now().isoformat(),
            "statistics": stats,
            "endpoints": endpoints,
            "patterns": patterns
        }
        
        return results


def print_text_report(results):
    """Print results in text format"""
    stats = results["statistics"]
    
    print("\n=== Traffic Analysis Summary ===")
    print(f"Total Flows: {stats['total_flows']}")
    print(f"Unique Endpoints: {stats['unique_endpoints']}")
    print(f"Domains: {', '.join(stats['domains'])}")
    
    # Status code distribution
    print("\n=== Status Code Distribution ===")
    for code, count in sorted(stats['status_codes'].items()):
        print(f"{code}: {count}")
    
    # Authentication mechanisms
    if stats['auth_mechanisms']:
        print("\n=== Authentication Mechanisms ===")
        for name, mechanism in stats['auth_mechanisms'].items():
            if mechanism['type'] == 'header':
                print(f"Header-based auth using {mechanism['header']}")
                if 'samples' in mechanism:
                    print(f"  Examples: {', '.join(mechanism['samples'])}")
            elif mechanism['type'] == 'cookie':
                print(f"Cookie-based auth using: {', '.join(mechanism['cookies'])}")
            elif mechanism['type'] == 'endpoint':
                print(f"Authentication endpoints: {', '.join(mechanism['endpoints'])}")
    
    # API patterns
    print("\n=== API Patterns ===")
    for pattern, details in sorted(results["patterns"].items(), key=lambda x: x[1]["count"], reverse=True):
        print(f"Pattern: {pattern}")
        print(f"  Methods: {', '.join(details['methods'])}")
        print(f"  Request count: {details['count']}")
        if details['parameters']:
            params = details['parameters']
            print(f"  Parameters: {', '.join(params[:10])}{' and more...' if len(params) > 10 else ''}")
        print()
    
    # Top endpoints
    print("=== Top Endpoints ===")
    top_endpoints = sorted(results["endpoints"].items(), key=lambda x: x[1]["count"], reverse=True)[:15]
    for endpoint, details in top_endpoints:
        print(f"{details['method']} {details['path']} ({details['count']} requests)")
        status_codes = ', '.join(f"{code}: {count}" for code, count in details['status_codes'].items())
        print(f"  Status Codes: {status_codes}")
        if details['parameters']:
            params = details['parameters']
            print(f"  Parameters: {', '.join(params[:5])}{' and more...' if len(params) > 5 else ''}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Analyze mitmproxy traffic dumps")
    parser.add_argument("flow_file", help="mitmproxy flow file to analyze")
    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format")
    parser.add_argument("-o", "--output", help="Write output to file")
    parser.add_argument("-f", "--filter", help="Filter by URL pattern")
    parser.add_argument("-d", "--decode", action="store_true", help="Attempt to decode payloads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    analyzer = TrafficAnalyzer(args)
    results = analyzer.analyze_flows(args.flow_file)
    
    if args.json or args.output:
        # JSON output
        output = json.dumps(results, indent=2)
        
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Results written to {args.output}")
        else:
            print(output)
    else:
        # Text output
        print_text_report(results)


if __name__ == "__main__":
    main()