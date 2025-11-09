"""
Nmap Scanner - Network discovery and port scanning
Uses python-nmap wrapper for the Nmap security scanner
"""

import logging
import nmap
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class NmapScanner:
    """Wrapper for Nmap network scanner"""

    def __init__(self):
        """Initialize Nmap scanner"""
        self.nm = nmap.PortScanner()
        self.tool_version = self.get_version()
        logger.info(f"Nmap scanner initialized (version: {self.tool_version})")

    def get_version(self) -> str:
        """Get Nmap version"""
        try:
            return self.nm.nmap_version()
        except:
            return "unknown"

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Run Nmap scan on target

        Args:
            target: Target URL or IP address

        Returns:
            Dict containing scan results and findings
        """
        scan_started = datetime.now(timezone.utc)
        logger.info(f"Starting Nmap scan on {target}")

        try:
            # Extract hostname from URL if needed
            hostname = self.extract_hostname(target)

            # Run scan in thread pool to avoid blocking
            scan_results = await asyncio.to_thread(
                self.nm.scan,
                hosts=hostname,
                arguments='-sV -sC -T4 --script=vuln',
                timeout=300  # 5 minute timeout
            )

            findings = self.parse_results(hostname, scan_results)

            scan_completed = datetime.now(timezone.utc)
            scan_duration = (scan_completed - scan_started).total_seconds()

            result = {
                'tool_name': 'nmap',
                'tool_version': self.tool_version,
                'target': target,
                'hostname': hostname,
                'scan_started_at': scan_started.isoformat(),
                'scan_completed_at': scan_completed.isoformat(),
                'scan_duration_seconds': int(scan_duration),
                'findings': findings,
                'raw_output': str(scan_results),
                'stats': self.get_scan_stats(scan_results)
            }

            logger.info(f"Nmap scan completed: {len(findings)} findings in {scan_duration:.1f}s")
            return result

        except Exception as e:
            logger.error(f"Nmap scan error: {e}", exc_info=True)
            scan_completed = datetime.now(timezone.utc)
            return {
                'tool_name': 'nmap',
                'tool_version': self.tool_version,
                'target': target,
                'scan_started_at': scan_started.isoformat(),
                'scan_completed_at': scan_completed.isoformat(),
                'scan_duration_seconds': int((scan_completed - scan_started).total_seconds()),
                'findings': [],
                'error': str(e)
            }

    def parse_results(self, hostname: str, scan_results: Dict) -> List[Dict[str, Any]]:
        """Parse Nmap scan results into normalized findings"""
        findings = []

        try:
            if hostname not in scan_results['scan']:
                logger.warning(f"No scan results for {hostname}")
                return findings

            host_data = scan_results['scan'][hostname]

            # Parse open ports
            if 'tcp' in host_data:
                for port, port_data in host_data['tcp'].items():
                    finding = self.create_port_finding(hostname, port, port_data)
                    if finding:
                        findings.append(finding)

            # Parse script results (vulnerability checks)
            if 'hostscript' in host_data:
                for script_result in host_data['hostscript']:
                    finding = self.create_script_finding(hostname, script_result)
                    if finding:
                        findings.append(finding)

        except Exception as e:
            logger.error(f"Error parsing Nmap results: {e}")

        return findings

    def create_port_finding(self, hostname: str, port: int, port_data: Dict) -> Optional[Dict]:
        """Create finding from port scan data"""
        state = port_data.get('state', 'unknown')

        if state != 'open':
            return None

        service = port_data.get('name', 'unknown')
        product = port_data.get('product', '')
        version = port_data.get('version', '')
        extrainfo = port_data.get('extrainfo', '')

        # Determine severity based on port and service
        severity = self.determine_port_severity(port, service)

        service_info = f"{product} {version}".strip() if product else service
        if extrainfo:
            service_info += f" ({extrainfo})"

        finding = {
            'category': 'port_scan',
            'title': f'Open Port: {port}/{service}',
            'description': f'Port {port} is open running {service_info}',
            'severity': severity,
            'target': hostname,
            'port': port,
            'protocol': 'tcp',
            'service': service,
            'service_product': product,
            'service_version': version,
            'state': state,
            'remediation': self.get_port_remediation(port, service),
            'cvss_score': self.get_port_cvss(port, service)
        }

        return finding

    def create_script_finding(self, hostname: str, script_result: Dict) -> Optional[Dict]:
        """Create finding from Nmap script results"""
        script_id = script_result.get('id', '')
        output = script_result.get('output', '')

        if not output or 'VULNERABLE' not in output.upper():
            return None

        severity = 'high' if 'VULNERABLE' in output else 'medium'

        finding = {
            'category': 'vulnerability',
            'title': f'Vulnerability Detected: {script_id}',
            'description': output[:500],  # Limit description length
            'severity': severity,
            'target': hostname,
            'script_id': script_id,
            'remediation': 'Review script output and apply appropriate patches',
            'cvss_score': 7.5 if severity == 'high' else 5.0
        }

        return finding

    def determine_port_severity(self, port: int, service: str) -> str:
        """Determine severity level for an open port"""
        # Critical services that should not be exposed
        critical_ports = {
            3389: 'critical',  # RDP
            5432: 'critical',  # PostgreSQL
            3306: 'critical',  # MySQL
            1433: 'critical',  # MSSQL
            27017: 'critical', # MongoDB
            6379: 'critical',  # Redis
            9200: 'critical',  # Elasticsearch
        }

        # High risk ports
        high_risk_ports = {
            21: 'high',   # FTP
            23: 'high',   # Telnet
            445: 'high',  # SMB
            139: 'high',  # NetBIOS
            111: 'high',  # RPC
            2049: 'high', # NFS
        }

        # Medium risk ports
        medium_risk_ports = {
            22: 'medium',   # SSH
            3000: 'medium', # Dev servers
            8080: 'medium', # HTTP Alt
            8443: 'medium', # HTTPS Alt
        }

        # Low risk ports
        low_risk_ports = {
            80: 'low',   # HTTP
            443: 'low',  # HTTPS
        }

        if port in critical_ports:
            return critical_ports[port]
        elif port in high_risk_ports:
            return high_risk_ports[port]
        elif port in medium_risk_ports:
            return medium_risk_ports[port]
        elif port in low_risk_ports:
            return low_risk_ports[port]
        else:
            return 'medium'  # Default for unknown ports

    def get_port_remediation(self, port: int, service: str) -> str:
        """Get remediation advice for a port"""
        remediations = {
            3389: 'Disable RDP if not needed. Use VPN for remote access. Enable Network Level Authentication.',
            5432: 'PostgreSQL should not be exposed to internet. Use firewall rules and require SSL connections.',
            3306: 'MySQL should not be publicly accessible. Bind to localhost and use SSH tunnels.',
            1433: 'MSSQL should not be exposed. Use firewall rules and VPN for remote access.',
            27017: 'MongoDB should not be publicly accessible. Enable authentication and use firewall rules.',
            6379: 'Redis should not be exposed to internet. Bind to localhost and require authentication.',
            21: 'Disable FTP. Use SFTP or SCP instead for file transfers.',
            23: 'Disable Telnet. Use SSH for secure remote access.',
            22: 'Ensure SSH uses key-based authentication and disable password authentication.',
            80: 'Redirect HTTP traffic to HTTPS. Consider disabling HTTP entirely.',
            443: 'Ensure strong TLS configuration and valid certificate.',
        }

        return remediations.get(port, f'Review if {service} service on port {port} needs to be exposed.')

    def get_port_cvss(self, port: int, service: str) -> float:
        """Get CVSS score for port exposure"""
        cvss_scores = {
            3389: 9.8,  # RDP
            5432: 9.8,  # PostgreSQL
            3306: 9.8,  # MySQL
            1433: 9.8,  # MSSQL
            27017: 9.8, # MongoDB
            6379: 9.8,  # Redis
            21: 8.1,    # FTP
            23: 9.8,    # Telnet
            445: 8.1,   # SMB
            22: 5.3,    # SSH
            80: 3.7,    # HTTP
            443: 3.1,   # HTTPS
        }

        return cvss_scores.get(port, 5.0)

    def get_scan_stats(self, scan_results: Dict) -> Dict[str, Any]:
        """Extract scan statistics"""
        try:
            stats = {
                'hosts_scanned': len(scan_results.get('scan', {})),
                'elapsed_time': scan_results.get('nmap', {}).get('scanstats', {}).get('elapsed', '0'),
                'command_line': scan_results.get('nmap', {}).get('command_line', '')
            }
            return stats
        except:
            return {}

    @staticmethod
    def extract_hostname(target: str) -> str:
        """Extract hostname from URL or return as-is if IP"""
        if target.startswith('http://') or target.startswith('https://'):
            parsed = urlparse(target)
            return parsed.hostname or parsed.netloc
        return target
