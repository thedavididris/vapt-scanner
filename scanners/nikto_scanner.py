"""
Nikto Scanner - Web server vulnerability scanner
Fast web server security scanner with 6700+ vulnerability checks
"""

import logging
import asyncio
import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class NiktoScanner:
    """Wrapper for Nikto web server scanner"""

    def __init__(self):
        """Initialize Nikto scanner"""
        self.tool_version = self.get_version()
        logger.info(f"Nikto scanner initialized (version: {self.tool_version})")

    def get_version(self) -> str:
        """Get Nikto version"""
        try:
            result = subprocess.run(
                ['nikto', '-Version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Parse version from output
            for line in result.stdout.split('\n'):
                if 'Nikto' in line and 'v' in line:
                    return line.strip()
            return "2.5.0"
        except:
            return "2.5.0"

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Run Nikto scan on target

        Args:
            target: Target URL

        Returns:
            Dict containing scan results and findings
        """
        scan_started = datetime.now(timezone.utc)
        logger.info(f"Starting Nikto scan on {target}")

        try:
            output_file = f'/tmp/nikto_{int(time.time())}.json'

            # Run Nikto with JSON output
            cmd = [
                'nikto',
                '-h', target,
                '-Format', 'json',
                '-output', output_file,
                '-Tuning', 'x',  # All tests except DoS
                '-timeout', '10',
                '-maxtime', '5m'  # 5 minute max
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=360  # 6 minute overall timeout
            )

            # Parse JSON output
            findings = self.parse_json_output(output_file)

            scan_completed = datetime.now(timezone.utc)
            scan_duration = (scan_completed - scan_started).total_seconds()

            return {
                'tool_name': 'nikto',
                'tool_version': self.tool_version,
                'target': target,
                'scan_started_at': scan_started.isoformat(),
                'scan_completed_at': scan_completed.isoformat(),
                'scan_duration_seconds': int(scan_duration),
                'findings': findings,
                'raw_output': result.stdout
            }

        except subprocess.TimeoutExpired:
            logger.warning("Nikto scan timed out")
            return self.timeout_result(target, scan_started)
        except Exception as e:
            logger.error(f"Nikto scan error: {e}", exc_info=True)
            return self.error_result(target, scan_started, str(e))

    def parse_json_output(self, output_file: str) -> List[Dict[str, Any]]:
        """Parse Nikto JSON output"""
        findings = []

        try:
            with open(output_file, 'r') as f:
                data = json.load(f)

            for host_data in data.get('vulnerabilities', []):
                for vuln in host_data.get('vulnerabilities', []):
                    finding = {
                        'category': 'web_server',
                        'title': vuln.get('msg', 'Web Server Vulnerability'),
                        'description': vuln.get('msg', ''),
                        'severity': self.determine_severity(vuln),
                        'url': vuln.get('url', ''),
                        'method': vuln.get('method', 'GET'),
                        'nikto_id': vuln.get('id', ''),
                        'osvdb': vuln.get('OSVDB', ''),
                        'remediation': self.get_remediation(vuln),
                        'cvss_score': self.get_cvss_score(vuln)
                    }
                    findings.append(finding)

        except FileNotFoundError:
            logger.warning(f"Nikto output file not found: {output_file}")
        except json.JSONDecodeError:
            logger.warning("Invalid JSON in Nikto output")
        except Exception as e:
            logger.error(f"Error parsing Nikto output: {e}")

        return findings

    def determine_severity(self, vuln: Dict) -> str:
        """Determine severity from Nikto vulnerability data"""
        msg = vuln.get('msg', '').lower()

        # Critical keywords
        if any(keyword in msg for keyword in ['sql injection', 'remote code execution', 'rce', 'shell']):
            return 'critical'

        # High severity keywords
        if any(keyword in msg for keyword in ['xss', 'cross-site', 'authentication', 'bypass', 'disclosure']):
            return 'high'

        # Medium severity keywords
        if any(keyword in msg for keyword in ['outdated', 'vulnerable', 'exposure', 'misconfiguration']):
            return 'medium'

        # Default to low
        return 'low'

    def get_remediation(self, vuln: Dict) -> str:
        """Get remediation advice for vulnerability"""
        msg = vuln.get('msg', '')

        if 'outdated' in msg.lower() or 'version' in msg.lower():
            return 'Update web server and all components to the latest stable versions'

        if 'directory' in msg.lower() or 'file' in msg.lower():
            return 'Remove or restrict access to sensitive directories and files'

        if 'header' in msg.lower():
            return 'Configure security headers properly in web server configuration'

        return 'Review finding and apply appropriate security measures'

    def get_cvss_score(self, vuln: Dict) -> float:
        """Estimate CVSS score for vulnerability"""
        severity = self.determine_severity(vuln)

        scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0
        }

        return scores.get(severity, 4.0)

    def timeout_result(self, target: str, scan_started: datetime) -> Dict:
        """Return result for timeout scenario"""
        scan_completed = datetime.now(timezone.utc)
        return {
            'tool_name': 'nikto',
            'tool_version': self.tool_version,
            'target': target,
            'scan_started_at': scan_started.isoformat(),
            'scan_completed_at': scan_completed.isoformat(),
            'scan_duration_seconds': int((scan_completed - scan_started).total_seconds()),
            'findings': [],
            'error': 'Scan timed out'
        }

    def error_result(self, target: str, scan_started: datetime, error: str) -> Dict:
        """Return result for error scenario"""
        scan_completed = datetime.now(timezone.utc)
        return {
            'tool_name': 'nikto',
            'tool_version': self.tool_version,
            'target': target,
            'scan_started_at': scan_started.isoformat(),
            'scan_completed_at': scan_completed.isoformat(),
            'scan_duration_seconds': int((scan_completed - scan_started).total_seconds()),
            'findings': [],
            'error': error
        }
