"""
OWASP ZAP Scanner - Web application security testing
Uses ZAP's Python API for automated web app vulnerability scanning
"""

import logging
import asyncio
import subprocess
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ZapScanner:
    """Wrapper for OWASP ZAP scanner"""

    def __init__(self):
        """Initialize ZAP scanner"""
        self.tool_version = self.get_version()
        logger.info(f"OWASP ZAP scanner initialized (version: {self.tool_version})")

    def get_version(self) -> str:
        """Get ZAP version"""
        try:
            result = subprocess.run(
                ['/opt/zap/zap.sh', '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip() if result.stdout else "2.14.0"
        except:
            return "2.14.0"

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Run OWASP ZAP scan on target

        Args:
            target: Target URL

        Returns:
            Dict containing scan results and findings
        """
        scan_started = datetime.now(timezone.utc)
        logger.info(f"Starting OWASP ZAP scan on {target}")

        try:
            # Run ZAP baseline scan (quick scan)
            # For production, you'd want to run more comprehensive scans
            cmd = [
                '/opt/zap/zap-baseline.py',
                '-t', target,
                '-J', '/tmp/zap_report.json',
                '-m', '5',  # 5 minute timeout
                '--hook', '/dev/null'  # Disable hooks for faster scan
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=360  # 6 minute overall timeout
            )

            # Parse JSON output
            findings = self.parse_json_output()

            scan_completed = datetime.now(timezone.utc)
            scan_duration = (scan_completed - scan_started).total_seconds()

            return {
                'tool_name': 'zap',
                'tool_version': self.tool_version,
                'target': target,
                'scan_started_at': scan_started.isoformat(),
                'scan_completed_at': scan_completed.isoformat(),
                'scan_duration_seconds': int(scan_duration),
                'findings': findings,
                'raw_output': result.stdout
            }

        except subprocess.TimeoutExpired:
            logger.warning("ZAP scan timed out")
            return self.timeout_result(target, scan_started)
        except Exception as e:
            logger.error(f"ZAP scan error: {e}", exc_info=True)
            return self.error_result(target, scan_started, str(e))

    def parse_json_output(self) -> List[Dict[str, Any]]:
        """Parse ZAP JSON report"""
        findings = []

        try:
            with open('/tmp/zap_report.json', 'r') as f:
                data = json.load(f)

            for site in data.get('site', []):
                for alert in site.get('alerts', []):
                    finding = {
                        'category': 'web_app',
                        'title': alert.get('name', 'Unknown Vulnerability'),
                        'description': alert.get('desc', ''),
                        'severity': self.map_severity(alert.get('riskcode', '0')),
                        'url': alert.get('url', ''),
                        'method': alert.get('method', ''),
                        'param': alert.get('param', ''),
                        'attack': alert.get('attack', ''),
                        'evidence': alert.get('evidence', ''),
                        'solution': alert.get('solution', ''),
                        'reference': alert.get('reference', ''),
                        'cwe_id': alert.get('cweid', ''),
                        'wasc_id': alert.get('wascid', ''),
                        'remediation': alert.get('solution', 'Apply recommended security patches'),
                        'cvss_score': self.get_cvss_from_risk(alert.get('riskcode', '0')),
                        'owasp_category': self.get_owasp_category(alert.get('cweid', ''))
                    }
                    findings.append(finding)

        except FileNotFoundError:
            logger.warning("ZAP report file not found")
        except Exception as e:
            logger.error(f"Error parsing ZAP output: {e}")

        return findings

    def map_severity(self, risk_code: str) -> str:
        """Map ZAP risk code to severity level"""
        mapping = {
            '3': 'high',
            '2': 'medium',
            '1': 'low',
            '0': 'info'
        }
        return mapping.get(str(risk_code), 'medium')

    def get_cvss_from_risk(self, risk_code: str) -> float:
        """Get CVSS score from ZAP risk code"""
        scores = {
            '3': 7.5,
            '2': 5.0,
            '1': 3.0,
            '0': 0.0
        }
        return scores.get(str(risk_code), 5.0)

    def get_owasp_category(self, cwe_id: str) -> str:
        """Map CWE to OWASP Top 10 category"""
        # Simplified mapping
        cwe_to_owasp = {
            '79': 'A03:2021 - Injection (XSS)',
            '89': 'A03:2021 - Injection (SQL)',
            '352': 'A01:2021 - Broken Access Control (CSRF)',
            '22': 'A01:2021 - Broken Access Control (Path Traversal)',
            '78': 'A03:2021 - Injection (Command Injection)',
        }
        return cwe_to_owasp.get(cwe_id, 'A00:2021 - Security Misconfiguration')

    def timeout_result(self, target: str, scan_started: datetime) -> Dict:
        """Return result for timeout scenario"""
        scan_completed = datetime.now(timezone.utc)
        return {
            'tool_name': 'zap',
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
            'tool_name': 'zap',
            'tool_version': self.tool_version,
            'target': target,
            'scan_started_at': scan_started.isoformat(),
            'scan_completed_at': scan_completed.isoformat(),
            'scan_duration_seconds': int((scan_completed - scan_started).total_seconds()),
            'findings': [],
            'error': error
        }
