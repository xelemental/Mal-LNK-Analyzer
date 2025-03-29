#!/usr/bin/env python3
"""
LNK File Analyzer
-----------------
A cross-platform tool to parse Windows LNK files and check them against VirusTotal.
Extracts important artifacts such as target path, machine ID, MAC address, and command line arguments.

Usage:
    python lnk_analyzer.py <path_to_lnk_file> [--api-key API_KEY]

Requirements:
    - pylnk3
    - requests
    - colorama
"""

import os
import sys
import argparse
import hashlib
import json
import time
from pathlib import Path
import requests
from colorama import Fore, Style, init

# Try to import pylnk3, handle import error with helpful message
try:
    import pylnk3
except ImportError:
    print("Error: pylnk3 module not found. Install it using: pip install pylnk3")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class LnkAnalyzer:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.vt_api_url = "https://www.virustotal.com/api/v3"
        
    def parse_lnk(self, lnk_path):
        """Parse a LNK file and extract important artifacts."""
        try:
            # Ensure file exists
            if not os.path.isfile(lnk_path):
                print(f"{Fore.RED}Error: File '{lnk_path}' not found.")
                return None
                
            # Parse LNK file
            lnk = pylnk3.parse(lnk_path)
            
            # Extract basic information
            info = {
                "filename": os.path.basename(lnk_path),
                "file_size": os.path.getsize(lnk_path),
                "md5": self._calculate_md5(lnk_path),
                "sha1": self._calculate_sha1(lnk_path),
                "sha256": self._calculate_sha256(lnk_path),
                "target_path": getattr(lnk, 'path', 'N/A'),
                "target_relative_path": getattr(lnk, 'relative_path', 'N/A'),
                "working_directory": getattr(lnk, 'working_directory', 'N/A'),
                "command_line_args": getattr(lnk, 'arguments', 'N/A'),
                "machine_id": getattr(lnk, 'machine_identifier', 'N/A'),
                "droid_volume_id": getattr(lnk, 'droid_volume_identifier', 'N/A'),
                "droid_file_id": getattr(lnk, 'droid_file_identifier', 'N/A'),
                "creation_time": getattr(lnk, 'creation_time', 'N/A'),
                "modification_time": getattr(lnk, 'modification_time', 'N/A'),
                "access_time": getattr(lnk, 'access_time', 'N/A')
            }
            
            # Extract MAC address (if available in network share information)
            mac_address = 'N/A'
            if hasattr(lnk, 'network_share_information') and lnk.network_share_information:
                if hasattr(lnk.network_share_information, 'device_name'):
                    info["network_share_device"] = lnk.network_share_information.device_name
                # MAC address might be in different locations depending on LNK format
                # This is a placeholder - actual implementation may need adjustments
                
            info["mac_address"] = mac_address
            
            return info
            
        except Exception as e:
            print(f"{Fore.RED}Error parsing LNK file: {str(e)}")
            return None
    
    def check_virustotal(self, file_hash):
        """Check a file hash against VirusTotal API."""
        if not self.api_key:
            return {"error": "No VirusTotal API key provided"}
            
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            response = requests.get(
                f"{self.vt_api_url}/files/{file_hash}",
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    "detected": stats.get('malicious', 0) + stats.get('suspicious', 0),
                    "total": sum(stats.values()) if stats else 0,
                    "scan_date": result.get('data', {}).get('attributes', {}).get('last_analysis_date', 'N/A'),
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}/detection",
                    "full_result": result
                }
            elif response.status_code == 404:
                return {"error": "File not found in VirusTotal database"}
            else:
                return {"error": f"VirusTotal API error: {response.status_code} - {response.text}"}
                
        except Exception as e:
            return {"error": f"Error connecting to VirusTotal: {str(e)}"}
    
    def upload_to_virustotal(self, file_path):
        """Upload a file to VirusTotal for scanning and wait for analysis results."""
        if not self.api_key:
            return {"error": "No VirusTotal API key provided"}
            
        headers = {
            "x-apikey": self.api_key,
        }
        
        try:
            # Calculate file hash for later lookup
            file_sha256 = self._calculate_sha256(file_path)
            
            # Get upload URL
            response = requests.get(
                f"{self.vt_api_url}/files/upload_url",
                headers=headers
            )
            
            if response.status_code != 200:
                return {"error": f"Failed to get upload URL: {response.status_code} - {response.text}"}
                
            upload_url = response.json().get('data')
            
            # Upload file
            files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
            response = requests.post(upload_url, files=files, headers=headers)
            
            if response.status_code != 200:
                return {"error": f"Failed to upload file: {response.status_code} - {response.text}"}
                
            analysis_id = response.json().get('data', {}).get('id')
            
            # Wait for analysis to complete with polling
            print(f"{Fore.YELLOW}File uploaded to VirusTotal. Analysis in progress...")
            
            max_wait_time = 60  # Maximum wait time in seconds
            poll_interval = 5   # Time between polling attempts in seconds
            wait_time = 0
            
            while wait_time < max_wait_time:
                # First check if analysis has completed
                analysis_response = requests.get(
                    f"{self.vt_api_url}/analyses/{analysis_id}",
                    headers=headers
                )
                
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json().get('data', {})
                    status = analysis_data.get('attributes', {}).get('status')
                    
                    if status == "completed":
                        print(f"{Fore.GREEN}Analysis completed!")
                        
                        # Now get the full file report which contains more details
                        return self.check_virustotal(file_sha256)
                
                # If we reach here, analysis isn't complete yet
                wait_time += poll_interval
                print(f"{Fore.YELLOW}Still analyzing... waited {wait_time} seconds")
                time.sleep(poll_interval)
            
            # If we exit the loop, we've waited too long
            return {
                "message": "File uploaded successfully but analysis is taking longer than expected", 
                "analysis_id": analysis_id,
                "permalink": f"https://www.virustotal.com/gui/file-analysis/{analysis_id}"
            }
                
        except Exception as e:
            return {"error": f"Error uploading to VirusTotal: {str(e)}"}
    
    def _calculate_md5(self, file_path):
        """Calculate MD5 hash of a file."""
        return self._calculate_hash(file_path, hashlib.md5())
    
    def _calculate_sha1(self, file_path):
        """Calculate SHA1 hash of a file."""
        return self._calculate_hash(file_path, hashlib.sha1())
    
    def _calculate_sha256(self, file_path):
        """Calculate SHA256 hash of a file."""
        return self._calculate_hash(file_path, hashlib.sha256())
    
    def _calculate_hash(self, file_path, hash_obj):
        """Helper method to calculate file hash."""
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def print_results(self, lnk_info, vt_result=None):
        """Print analysis results in a formatted way."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}LNK File Analysis Results")
        print(f"{Fore.CYAN}{'='*60}")
        
        # File information
        print(f"{Fore.GREEN}File Information:")
        print(f"  Filename: {lnk_info['filename']}")
        print(f"  File Size: {lnk_info['file_size']} bytes")
        print(f"  MD5: {lnk_info['md5']}")
        print(f"  SHA1: {lnk_info['sha1']}")
        print(f"  SHA256: {lnk_info['sha256']}")
        
        # Target information
        print(f"\n{Fore.GREEN}Target Information:")
        print(f"  Target Path: {lnk_info['target_path']}")
        print(f"  Target Relative Path: {lnk_info['target_relative_path']}")
        print(f"  Working Directory: {lnk_info['working_directory']}")
        print(f"  Command Line Arguments: {lnk_info['command_line_args']}")
        
        # Machine information
        print(f"\n{Fore.GREEN}Machine Information:")
        print(f"  Machine ID: {lnk_info['machine_id']}")
        print(f"  MAC Address: {lnk_info['mac_address']}")
        print(f"  Droid Volume ID: {lnk_info['droid_volume_id']}")
        print(f"  Droid File ID: {lnk_info['droid_file_id']}")
        
        # Timestamps
        print(f"\n{Fore.GREEN}Timestamps:")
        print(f"  Creation Time: {lnk_info['creation_time']}")
        print(f"  Modification Time: {lnk_info['modification_time']}")
        print(f"  Access Time: {lnk_info['access_time']}")
        
        # VirusTotal results
        if vt_result:
            print(f"\n{Fore.GREEN}VirusTotal Results:")
            if "error" in vt_result:
                print(f"  {Fore.YELLOW}{vt_result['error']}")
            else:
                detection_ratio = f"{vt_result['detected']}/{vt_result['total']}"
                if vt_result['detected'] > 0:
                    detection_color = Fore.RED
                else:
                    detection_color = Fore.GREEN
                
                print(f"  Detection: {detection_color}{detection_ratio}")
                print(f"  Scan Date: {vt_result['scan_date']}")
                print(f"  Permalink: {vt_result['permalink']}")
                
        print(f"{Fore.CYAN}{'='*60}\n")

def main():
    parser = argparse.ArgumentParser(description="LNK File Analyzer - Extract artifacts and check against VirusTotal")
    parser.add_argument("lnk_file", help="Path to the LNK file to analyze")
    parser.add_argument("--api-key", help="VirusTotal API key")
    parser.add_argument("--upload", action="store_true", help="Upload file to VirusTotal if not already present")
    parser.add_argument("--output", help="Save results to specified JSON file")
    args = parser.parse_args()
    
    # Get API key from arguments or environment variable
    api_key = args.api_key or os.environ.get("VT_API_KEY")
    
    # Initialize analyzer
    analyzer = LnkAnalyzer(api_key)
    
    # Parse LNK file
    print(f"{Fore.CYAN}Analyzing LNK file: {args.lnk_file}")
    lnk_info = analyzer.parse_lnk(args.lnk_file)
    
    if not lnk_info:
        sys.exit(1)
    
    # Check VirusTotal if API key provided
    vt_result = None
    if api_key:
        print(f"{Fore.CYAN}Checking VirusTotal for file hash: {lnk_info['sha256']}")
        vt_result = analyzer.check_virustotal(lnk_info['sha256'])
        
        # Upload file if requested and not found in VT
        if args.upload and vt_result.get("error") == "File not found in VirusTotal database":
            print(f"{Fore.YELLOW}File not found in VirusTotal database. Uploading...")
            upload_result = analyzer.upload_to_virustotal(args.lnk_file)
            if "error" not in upload_result:
                # Update the VT result with the results from the upload
                vt_result = upload_result
            else:
                print(f"{Fore.RED}{upload_result['error']}")
    else:
        print(f"{Fore.YELLOW}No VirusTotal API key provided. Skipping VirusTotal check.")
    
    # Print results
    analyzer.print_results(lnk_info, vt_result)
    
    # Save results to file if requested
    if args.output:
        results = {
            "lnk_info": lnk_info,
            "virustotal": vt_result
        }
        
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4, default=str)
        
        print(f"{Fore.GREEN}Results saved to {args.output}")

if __name__ == "__main__":
    main()
