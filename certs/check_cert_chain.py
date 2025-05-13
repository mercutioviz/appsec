#!/usr/bin/env python3
"""
SSL/TLS Certificate Chain Checker

This script connects to a given domain using OpenSSL, retrieves the certificate chain,
and verifies its completeness and validity. It provides colored output for easy status reading.
"""

import argparse
import subprocess
import tempfile
import os
import re
import sys

# ANSI color codes for terminal output
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_RED = "\033[31m"

def check_openssl_available():
    """Check if OpenSSL is available in the system PATH."""
    try:
        subprocess.run(['openssl', 'version'], capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def extract_certificates(output):
    """
    Extract PEM certificates from OpenSSL s_client output.

    Args:
        output (str): Output from OpenSSL s_client.

    Returns:
        list of str: List of PEM-formatted certificate strings.
    """
    return re.findall(
        r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
        output,
        re.DOTALL
    )

def save_certificates(certificates, temp_dir):
    """
    Save each certificate to a separate file in a temporary directory.

    Args:
        certificates (list of str): List of PEM certificates.
        temp_dir (str): Path to temporary directory.

    Returns:
        list of str: List of file paths to saved certificates.
    """
    cert_paths = []
    for idx, cert in enumerate(certificates, 1):
        cert_path = os.path.join(temp_dir, f'cert{idx}.pem')
        with open(cert_path, 'w') as f:
            f.write(cert)
        cert_paths.append(cert_path)
    return cert_paths

def parse_verification_output(output):
    """
    Parse OpenSSL verify output to determine status and reason.

    Args:
        output (str): Output from OpenSSL verify.

    Returns:
        tuple: (status, reason)
    """
    if "OK" in output:
        return ("OK", "")
    match = re.search(r'error (\d+) at \d+ depth lookup:(.+)', output)
    if match:
        error_code = match.group(1)
        reason = match.group(2).strip()
        return (f"ERROR_{error_code}", reason)
    return ("UNKNOWN_ERROR", output.strip())

def get_certificate_cn(cert_path):
    """
    Extract the Common Name (CN) from a certificate file.

    Args:
        cert_path (str): Path to certificate file.

    Returns:
        str: Common Name (CN) or 'Unknown CN' if not found.
    """
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-subject', '-in', cert_path],
            capture_output=True, text=True, check=True
        )
        subject = result.stdout.strip()
        match = re.search(r'CN\s*=\s*([^,\/]+)', subject)
        return match.group(1) if match else "Unknown CN"
    except subprocess.CalledProcessError:
        return "Unknown CN"

def verify_certificate_chain(cert_files, temp_dir, domain, cafile=None):
    """
    Verify the certificate chain using OpenSSL and print colored output.

    Args:
        cert_files (list of str): List of certificate file paths.
        temp_dir (str): Path to temporary directory.
        domain (str): Domain name being checked.
        cafile (str, optional): Path to CA certificate file.
    """
    if not cert_files:
        print(f"{COLOR_RED}No certificates found.{COLOR_RESET}")
        return

    leaf_cert = cert_files[0]
    intermediates = cert_files[1:-1]
    root_cert = cert_files[-1] if len(cert_files) > 1 else None

    # Combine intermediate certificates into a single file if present
    intermediates_file = None
    if intermediates:
        intermediates_file = os.path.join(temp_dir, 'intermediates.pem')
        with open(intermediates_file, 'w') as f:
            for cert in intermediates:
                with open(cert, 'r') as cf:
                    f.write(cf.read())

    # Build OpenSSL verify command
    cmd = ['openssl', 'verify']
    if cafile:
        cmd.extend(['-CAfile', cafile])
    elif root_cert:
        cmd.extend(['-CAfile', root_cert])
    if intermediates_file:
        cmd.extend(['-untrusted', intermediates_file])
    cmd.append(leaf_cert)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        status, reason = parse_verification_output(result.stdout)
        cn = get_certificate_cn(leaf_cert)
        if status == "OK":
            print(f"{COLOR_GREEN}{domain} ({cn}): OK{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}{domain} ({cn}): {reason}{COLOR_RESET}")
    except subprocess.CalledProcessError as e:
        status, reason = parse_verification_output(e.stderr)
        cn = get_certificate_cn(leaf_cert)
        if status == "ERROR_10":
            print(f"{COLOR_YELLOW}{domain} ({cn}): Certificate has expired ({reason}){COLOR_RESET}")
        elif status == "ERROR_20":
            print(f"{COLOR_RED}{domain} ({cn}): Probable incomplete chain ({reason}){COLOR_RESET}")
        else:
            print(f"{COLOR_RED}{domain} ({cn}): Verification failed ({reason}){COLOR_RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='Check SSL/TLS certificate chain completeness.'
    )
    parser.add_argument('domain', nargs='?', help='Domain to check (e.g., example.com)')
    parser.add_argument('--cafile', help='Path to CA certificate file')
    args = parser.parse_args()

    # Check for OpenSSL availability
    if not check_openssl_available():
        print(f"{COLOR_YELLOW}OpenSSL is not available on your system. Please install OpenSSL to use this script.{COLOR_RESET}")
        print("Installation instructions:")
        print("  - For Debian/Ubuntu: sudo apt-get install openssl")
        print("  - For Red Hat/CentOS: sudo yum install openssl")
        print("  - For macOS: brew install openssl")
        print("  - For Windows: Download from https://slproweb.com/products/Win32OpenSSL.html")
        print("                 or install from admin CLI: winget install ShiningLight.OpenSSL.Light")
        sys.exit(1)

    if not args.domain:
        print(f"{COLOR_YELLOW}Please specify domain name as a CLI argument.{COLOR_RESET}")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Retrieve certificates using OpenSSL s_client
            cmd = ['openssl', 's_client', '-connect', f'{args.domain}:443', '-showcerts']
            result = subprocess.run(cmd, capture_output=True, text=True, input='', timeout=10)
            output = result.stdout
        except subprocess.TimeoutExpired:
            print(f"{COLOR_RED}Connection to {args.domain} timed out.{COLOR_RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{COLOR_RED}An error occurred: {e}{COLOR_RESET}")
            sys.exit(1)

        certs = extract_certificates(output)
        if not certs:
            print(f"{COLOR_RED}No certificates retrieved from {args.domain}.{COLOR_RESET}")
            sys.exit(1)

        print(f"Retrieved {len(certs)} certificate(s) from {args.domain}.")

        cert_files = save_certificates(certs, temp_dir)
        verify_certificate_chain(cert_files, temp_dir, args.domain, cafile=args.cafile)

if __name__ == '__main__':
    main()
