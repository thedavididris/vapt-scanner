"""
SSLyze Scanner - SSL/TLS configuration analyzer
Tests SSL/TLS security, certificates, cipher suites, and vulnerabilities
"""

import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Any
from urllib.parse import urlparse
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
    ScanCommandAttemptStatusEnum
)
from sslyze.errors import ConnectionToServerFailed

logger = logging.getLogger(__name__)


class SSLyzeScanner:
    """Wrapper for SSLyze SSL/TLS scanner"""

    def __init__(self):
        """Initialize SSLyze scanner"""
        self.tool_version = self.get_version()
        logger.info(f"SSLyze scanner initialized (version: {self.tool_version})")

    def get_version(self) -> str:
        """Get SSLyze version"""
        try:
            import sslyze
            return sslyze.__version__
        except:
            return "5.2.0"

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Run SSLyze scan on target

        Args:
            target: Target URL or hostname

        Returns:
            Dict containing scan results and findings
        """
        scan_started = datetime.now(timezone.utc)
        logger.info(f"Starting SSLyze scan on {target}")

        try:
            # Extract hostname and port
            hostname, port = self.parse_target(target)

            if not hostname:
                raise ValueError(f"Invalid target: {target}")

            # Create server location
            server_location = ServerNetworkLocation(
                hostname=hostname,
                port=port
            )

            # Queue all SSL/TLS scans
            scanner = Scanner()
            server_scan_req = ServerScanRequest(
                server_location=server_location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.TLS_COMPRESSION,
                    ScanCommand.TLS_FALLBACK_SCSV,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.ROBOT,
                    ScanCommand.SESSION_RENEGOTIATION,
                    ScanCommand.HTTP_HEADERS,
                }
            )

            # Run scan
            scanner.queue_scans([server_scan_req])
            scan_results = []

            for result in scanner.get_results():
                scan_results.append(result)

            # Parse results
            findings = self.parse_results(hostname, scan_results[0] if scan_results else None)

            scan_completed = datetime.now(timezone.utc)
            scan_duration = (scan_completed - scan_started).total_seconds()

            return {
                'tool_name': 'sslyze',
                'tool_version': self.tool_version,
                'target': target,
                'hostname': hostname,
                'port': port,
                'scan_started_at': scan_started.isoformat(),
                'scan_completed_at': scan_completed.isoformat(),
                'scan_duration_seconds': int(scan_duration),
                'findings': findings,
                'raw_output': str(scan_results)
            }

        except ConnectionToServerFailed as e:
            logger.error(f"Connection failed: {e}")
            return self.error_result(target, scan_started, f"Connection failed: {e}")
        except Exception as e:
            logger.error(f"SSLyze scan error: {e}", exc_info=True)
            return self.error_result(target, scan_started, str(e))

    def parse_results(self, hostname: str, scan_result) -> List[Dict[str, Any]]:
        """Parse SSLyze scan results"""
        findings = []

        if not scan_result:
            return findings

        try:
            # Check certificate
            cert_result = scan_result.scan_result.certificate_info
            if cert_result.status == ScanCommandAttemptStatusEnum.COMPLETED:
                cert_findings = self.analyze_certificate(hostname, cert_result.result)
                findings.extend(cert_findings)

            # Check weak protocols
            if scan_result.scan_result.ssl_2_0_cipher_suites:
                if scan_result.scan_result.ssl_2_0_cipher_suites.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    if scan_result.scan_result.ssl_2_0_cipher_suites.result.cipher_suites:
                        findings.append({
                            'category': 'ssl_tls',
                            'title': 'SSLv2 Enabled (Critical)',
                            'description': 'SSLv2 is enabled. This protocol has known critical vulnerabilities.',
                            'severity': 'critical',
                            'target': hostname,
                            'remediation': 'Disable SSLv2 completely. Use TLS 1.2 or TLS 1.3 only.',
                            'cvss_score': 9.8
                        })

            if scan_result.scan_result.ssl_3_0_cipher_suites:
                if scan_result.scan_result.ssl_3_0_cipher_suites.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    if scan_result.scan_result.ssl_3_0_cipher_suites.result.cipher_suites:
                        findings.append({
                            'category': 'ssl_tls',
                            'title': 'SSLv3 Enabled (POODLE)',
                            'description': 'SSLv3 is enabled and vulnerable to POODLE attack.',
                            'severity': 'high',
                            'target': hostname,
                            'cve_id': 'CVE-2014-3566',
                            'remediation': 'Disable SSLv3. Use TLS 1.2 or TLS 1.3 only.',
                            'cvss_score': 7.5
                        })

            if scan_result.scan_result.tls_1_0_cipher_suites:
                if scan_result.scan_result.tls_1_0_cipher_suites.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    if scan_result.scan_result.tls_1_0_cipher_suites.result.cipher_suites:
                        findings.append({
                            'category': 'ssl_tls',
                            'title': 'TLS 1.0 Enabled (Deprecated)',
                            'description': 'TLS 1.0 is enabled. This protocol is deprecated and should be disabled.',
                            'severity': 'medium',
                            'target': hostname,
                            'remediation': 'Disable TLS 1.0. Use TLS 1.2 or TLS 1.3 only.',
                            'cvss_score': 5.3
                        })

            if scan_result.scan_result.tls_1_1_cipher_suites:
                if scan_result.scan_result.tls_1_1_cipher_suites.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    if scan_result.scan_result.tls_1_1_cipher_suites.result.cipher_suites:
                        findings.append({
                            'category': 'ssl_tls',
                            'title': 'TLS 1.1 Enabled (Deprecated)',
                            'description': 'TLS 1.1 is enabled. This protocol is deprecated.',
                            'severity': 'low',
                            'target': hostname,
                            'remediation': 'Consider disabling TLS 1.1. Prefer TLS 1.2 and TLS 1.3.',
                            'cvss_score': 3.7
                        })

            # Check for Heartbleed
            if scan_result.scan_result.heartbleed:
                if scan_result.scan_result.heartbleed.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    if scan_result.scan_result.heartbleed.result.is_vulnerable_to_heartbleed:
                        findings.append({
                            'category': 'ssl_tls',
                            'title': 'Heartbleed Vulnerability (Critical)',
                            'description': 'Server is vulnerable to the Heartbleed attack (CVE-2014-0160).',
                            'severity': 'critical',
                            'target': hostname,
                            'cve_id': 'CVE-2014-0160',
                            'remediation': 'Immediately update OpenSSL to a patched version. Revoke and reissue certificates.',
                            'cvss_score': 10.0
                        })

            # Check for ROBOT
            if scan_result.scan_result.robot:
                if scan_result.scan_result.robot.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    robot_result = scan_result.scan_result.robot.result
                    if robot_result.robot_result_enum.name != 'NOT_VULNERABLE':
                        findings.append({
                            'category': 'ssl_tls',
                            'title': 'ROBOT Attack Vulnerability',
                            'description': f'Server is vulnerable to ROBOT attack: {robot_result.robot_result_enum.name}',
                            'severity': 'high',
                            'target': hostname,
                            'cve_id': 'CVE-2017-13099',
                            'remediation': 'Disable RSA encryption cipher suites or apply vendor patches.',
                            'cvss_score': 7.5
                        })

            # Check compression
            if scan_result.scan_result.tls_compression:
                if scan_result.scan_result.tls_compression.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    if scan_result.scan_result.tls_compression.result.supports_compression:
                        findings.append({
                            'category': 'ssl_tls',
                            'title': 'TLS Compression Enabled (CRIME)',
                            'description': 'TLS compression is enabled, making the server vulnerable to CRIME attack.',
                            'severity': 'medium',
                            'target': hostname,
                            'cve_id': 'CVE-2012-4929',
                            'remediation': 'Disable TLS compression.',
                            'cvss_score': 5.9
                        })

            # Check HTTP headers
            if scan_result.scan_result.http_headers:
                if scan_result.scan_result.http_headers.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    header_result = scan_result.scan_result.http_headers.result
                    if not header_result.strict_transport_security_header:
                        findings.append({
                            'category': 'ssl_tls',
                            'title': 'Missing HSTS Header',
                            'description': 'HTTP Strict Transport Security (HSTS) header is not set.',
                            'severity': 'medium',
                            'target': hostname,
                            'remediation': 'Add Strict-Transport-Security header with max-age of at least 31536000.',
                            'cvss_score': 5.3
                        })

        except Exception as e:
            logger.error(f"Error parsing SSLyze results: {e}")

        return findings

    def analyze_certificate(self, hostname: str, cert_result) -> List[Dict[str, Any]]:
        """Analyze SSL certificate"""
        findings = []

        try:
            for cert_deployment in cert_result.certificate_deployments:
                # Check if certificate is trusted
                if not cert_deployment.path_validation_results:
                    findings.append({
                        'category': 'ssl_tls',
                        'title': 'SSL Certificate Validation Issues',
                        'description': 'SSL certificate has validation issues.',
                        'severity': 'high',
                        'target': hostname,
                        'remediation': 'Install a valid SSL certificate from a trusted CA.',
                        'cvss_score': 7.5
                    })

                # Check certificate expiry
                cert_info = cert_deployment.received_certificate_chain[0]
                days_until_expiry = (cert_info.not_valid_after - datetime.now()).days

                if days_until_expiry < 0:
                    findings.append({
                        'category': 'ssl_tls',
                        'title': 'SSL Certificate Expired',
                        'description': f'SSL certificate expired {abs(days_until_expiry)} days ago.',
                        'severity': 'critical',
                        'target': hostname,
                        'remediation': 'Immediately renew the SSL certificate.',
                        'cvss_score': 9.0
                    })
                elif days_until_expiry < 30:
                    findings.append({
                        'category': 'ssl_tls',
                        'title': 'SSL Certificate Expiring Soon',
                        'description': f'SSL certificate expires in {days_until_expiry} days.',
                        'severity': 'medium',
                        'target': hostname,
                        'remediation': 'Renew the SSL certificate before expiry.',
                        'cvss_score': 5.0
                    })

                # Check hostname match
                if hostname not in cert_info.subject_alternative_names:
                    findings.append({
                        'category': 'ssl_tls',
                        'title': 'SSL Certificate Hostname Mismatch',
                        'description': f'Certificate is not valid for {hostname}.',
                        'severity': 'high',
                        'target': hostname,
                        'remediation': 'Obtain a certificate that includes the correct hostname.',
                        'cvss_score': 7.5
                    })

        except Exception as e:
            logger.error(f"Error analyzing certificate: {e}")

        return findings

    def parse_target(self, target: str) -> tuple:
        """Parse target URL to extract hostname and port"""
        try:
            if target.startswith('http://') or target.startswith('https://'):
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            else:
                # Assume it's a hostname, default to HTTPS port
                if ':' in target:
                    hostname, port_str = target.rsplit(':', 1)
                    port = int(port_str)
                else:
                    hostname = target
                    port = 443

            return hostname, port
        except:
            return None, None

    def error_result(self, target: str, scan_started: datetime, error: str) -> Dict:
        """Return result for error scenario"""
        scan_completed = datetime.now(timezone.utc)
        return {
            'tool_name': 'sslyze',
            'tool_version': self.tool_version,
            'target': target,
            'scan_started_at': scan_started.isoformat(),
            'scan_completed_at': scan_completed.isoformat(),
            'scan_duration_seconds': int((scan_completed - scan_started).total_seconds()),
            'findings': [],
            'error': error
        }
