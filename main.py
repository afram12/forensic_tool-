import email
import argparse
import subprocess
import sqlite3
import os
import re

import dns.resolver
from email.policy import default

#==============================================================
# MODULE 1: EMAIL ANALYSIS FUNCTION (UPGRADED)
#==============================================================
def analyze_email(filepath):
    print(f"--- Analyzing Email File: {filepath} ---")
    try:
        with open(filepath, 'rb') as file:
            # Using policy=default to handle different email formats
            msg = email.message_from_binary_file(file, policy=default)
            
        print(f"\n[+] Basic Headers:")
        print(f"  ✅ From: {msg['From']}")
        print(f"  ✅ To: {msg['To']}")
        print(f"  ✅ Subject: {msg['Subject']}")
        print(f"  ✅ Date: {msg['Date']}")

        # --- Spoofing Analysis ---
        print("\n[+] Anti-Spoofing Analysis:")
        auth_results = msg.get('Authentication-Results', 'Not found')
        
        if 'spf=pass' in auth_results:
            print("  ✅ SPF Check: PASS")
        elif 'spf=fail' in auth_results:
            print("  ❌ SPF Check: FAIL - This email may be spoofed!")
        else:
            print("  ⚠️ SPF Check: Not found or indeterminate.")

        if 'dkim=pass' in auth_results:
            print("  ✅ DKIM Check: PASS")
        elif 'dkim=fail' in auth_results:
            print("  ❌ DKIM Check: FAIL - The message may have been altered!")
        else:
            print("  ⚠️ DKIM Check: Not found or indeterminate.")

        # --- Trace Email Path ---
        print("\n[+] Email Path Trace (Received Headers):")
        received_headers = msg.get_all('Received', [])
        for i, header in enumerate(received_headers):
            # Clean up the header for display
            clean_header = header.replace('\n', ' ').replace('\t', ' ').strip()
            print(f"  Hop {len(received_headers) - i}: {clean_header}")

    except FileNotFoundError:
        print(f"❌ ERROR: File not found at '{filepath}'")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")

# ... (The other module functions remain the same) ...

#==============================================================
# MODULE 2: NETWORK ANALYSIS FUNCTION
#==============================================================
def analyze_pcap(filepath):
    print(f"--- Analyzing PCAP File: {filepath} ---")
    command = ["tshark", "-r", filepath, "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("Frame | Source IP       | Destination IP  | Protocol")
        print("-----------------------------------------------------")
        for line in result.stdout.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) == 4:
                frame, src, dst, proto = parts
                print(f"{frame:<5} | {src:<15} | {dst:<15} | {proto}")
    except FileNotFoundError:
        print("❌ ERROR: 'tshark' is not installed or not in your PATH.")

#==============================================================
# MODULE 3: STEGANOGRAPHY ANALYSIS FUNCTION
#==============================================================
def analyze_stego(filepath):
    print(f"--- Analyzing Steganography in File: {filepath} ---")
    print("\n[+] Running zsteg analysis...")
    try:
        zsteg_command = ["zsteg", filepath]
        result = subprocess.run(zsteg_command, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            print("✅ zsteg found potential hidden data:")
            print(result.stdout)
        else:
            print("✅ zsteg found no obvious hidden data.")
    except FileNotFoundError:
        print("❌ ERROR: 'zsteg' is not installed or not in your PATH.")

    print("\n[+] Running steghide analysis...")
    try:
        steghide_command = ["steghide", "info", filepath, "-p", ""]
        result = subprocess.run(steghide_command, capture_output=True, text=True)
        if "could not open the file" in result.stderr:
             print("❌ ERROR: File not found or is not a supported format for steghide.")
        elif "extracting data" in result.stdout:
             print("✅ steghide found embedded file information:")
             print(result.stdout)
        else:
             print("✅ steghide found no embedded file with a blank passphrase.")
    except FileNotFoundError:
        print("❌ ERROR: 'steghide' is not installed or not in your PATH.")
        
#==============================================================
# MODULE 4: BROWSER HISTORY ANALYSIS
#==============================================================
def analyze_browser(db_path):
    print(f"--- Analyzing Browser History From: {db_path} ---")
    if not os.path.exists(db_path):
        print(f"❌ ERROR: Database file not found at '{db_path}'")
        return
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = "SELECT url, visit_count FROM moz_places ORDER BY visit_count DESC LIMIT 15;"
        print("\n[+] Top 15 Most Visited Sites:")
        print("Visits | URL")
        print("-------------------------------------------------")
        for row in cursor.execute(query):
            print(f"{row[1]:<6} | {row[0]}")
        conn.close()
    except sqlite3.Error as e:
        print(f"❌ DATABASE ERROR: {e}")

#==============================================================
# MAIN SCRIPT EXECUTION
#==============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="My Forensics Tool - A digital forensics Swiss Army knife.")
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available tools')

    # Sub-parsers for each tool
    email_parser = subparsers.add_parser('email', help='Analyze an email (.eml) file, including spoofing checks.')
    email_parser.add_argument("-f", "--file", required=True, help="Path to the email file.")

    network_parser = subparsers.add_parser('network', help='Analyze a network capture (.pcap) file.')
    network_parser.add_argument("-f", "--file", required=True, help="Path to the PCAP file.")

    stego_parser = subparsers.add_parser('stego', help='Check an image for hidden steganographic data.')
    stego_parser.add_argument("-f", "--file", required=True, help="Path to the image file.")
    
    browser_parser = subparsers.add_parser('browser', help="Analyze Firefox browser history.")
    browser_parser.add_argument("-p", "--profile", required=True, help="Path to the Firefox profile directory containing places.sqlite.")

    args = parser.parse_args()

    # Logic to call the correct function
    if args.command == 'email':
        analyze_email(args.file)
    elif args.command == 'network':
        analyze_pcap(args.file)
    elif args.command == 'stego':
        analyze_stego(args.file)
    elif args.command == 'browser':
        db_file_path = os.path.join(args.profile, 'places.sqlite')
        analyze_browser(db_file_path)