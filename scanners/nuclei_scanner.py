"""
Nuclei Scanner - Template-based vulnerability scanner
Uses ProjectDiscovery's Nuclei with 5000+ community templates
"""

import logging
import asyncio
import subprocess
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class NucleiScanner:
    """Wrapper for Nuclei template-based scanner"""

    def __init__(self):
        """Initialize Nuclei scanner"""
        self.tool_version = self.get_version()
        logger.info(f"Nuclei scanner initialized (version: {self.tool_version})")

    def get_version(self) -> str:
        """Get Nuclei version"""
        try:
            result = subprocess.run(
                ['nuclei', '-version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except:
            return "3.1.0"

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Run Nuclei scan on target

        Args:
            target: Target URL

        Returns:
            Dict containing scan results and findings
        """
        scan_started = datetime.now(timezone.utc)
        logger.info(f"Starting Nuclei scan on {target}")

        try:
            output_file = f'/tmp/nuclei_{int(time.time())}.json'

            # Run Nuclei with severity filtering (exclude info)
            cmd = [
                'nuclei',
                '-u', target,
                '-severity', 'low,medium,high,critical',
                '-json',
                '-output', output_file,
                '-timeout', '10',
                '-rate-limit', '150',  # Polite scanning
                '-no-interactsh',  # Disable interactsh for faster scans
                '-silent'
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # Parse JSON output
            findings = self.parse_json_output(output_file)

            scan_completed = datetime.now(timezone.utc)
            scan_duration = (scan_completed - scan_started).total_seconds()

            return {
                'tool_name': 'nuclei',
                'tool_version': self.tool_version,
                'target': target,
                'scan_started_at': scan_started.isoformat(),
                'scan_completed_at': scan_completed.isoformat(),
                'scan_duration_seconds': int(scan_duration),
                'findings': findings,
                'raw_output': result.stdout
            }

        except subprocess.TimeoutExpired:
            logger.warning("Nuclei scan timed out")
            return self.timeout_result(target, scan_started)
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}", exc_info=True)
            return self.error_result(target, scan_started, str(e))

    def parse_json_output(self, output_file: str) -> List[Dict[str, Any]]:
        """Parse Nuclei JSON output (JSONL format - one JSON per line)"""
        findings = []

        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue

                    try:
                        vuln = json.loads(line)

                        # Extract template info
                        template_id = vuln.get('template-id', '')
                        info = vuln.get('info', {})

                        finding = {
                            'category': info.get('tags', ['nuclei'])[0] if info.get('tags') else 'nuclei',
                            'title': info.get('name', 'Nuclei Detection'),
                            'description': info.get('description', ''),
                            'severity': vuln.get('severity', 'medium'),
                            'url': vuln.get('matched-at', vuln.get('host', '')),
                            'template_id': template_id,
                            'matcher_name': vuln.get('matcher-name', ''),
                            'extracted_results': vuln.get('extracted-results', []),
                            'cve_id': self.extract_cve(template_id),
                            'cwe_id': info.get('classification', {}).get('cwe-id', ''),
                            'remediation': info.get('remediation', self.get_default_remediation(template_id)),
                            'reference': info.get('reference', []),
                            'cvss_score': self.get_cvss_from_severity(vuln.get('severity', 'medium')),
                            'tags': info.get('tags', [])
                        }
                        findings.append(finding)

                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON line in Nuclei output: {line[:100]}")

        except FileNotFoundError:
            logger.warning(f"Nuclei output file not found: {output_file}")
        except Exception as e:
            logger.error(f"Error parsing Nuclei output: {e}")

        return findings

    def extract_cve(self, template_id: str) -> str:
        """Extract CVE ID from template ID if present"""
        if 'CVE-' in template_id.upper():
            parts = template_id.split('CVE-')
            if len(parts) > 1:
                cve_part = parts[1].split('-')
                if len(cve_part) >= 2:
                    return f"CVE-{cve_part[0]}-{cve_part[1]}"
        return ''

    def get_default_remediation(self, template_id: str) -> str:
        """Get default remediation based on template ID"""
        if 'cve' in template_id.lower():
            return 'Apply the latest security patches to address this CVE'
        elif 'exposed' in template_id.lower():
            return 'Restrict access to exposed services and implement proper authentication'
        elif 'misconfiguration' in template_id.lower():
            return 'Review and correct the identified misconfiguration'
        else:
            return 'Review the finding and apply appropriate security measures'

    def get_cvss_from_severity(self, severity: str) -> float:
        """Get CVSS score from severity level"""
        scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'info': 0.0
        }
        return scores.get(severity.lower(), 5.0)

    def timeout_result(self, target: str, scan_started: datetime) -> Dict:
        """Return result for timeout scenario"""
        scan_completed = datetime.now(timezone.utc)
        return {
            'tool_name': 'nuclei',
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
            'tool_name': 'nuclei',
            'tool_version': self.tool_version,
            'target': target,
            'scan_started_at': scan_started.isoformat(),
            'scan_completed_at': scan_completed.isoformat(),
            'scan_duration_seconds': int((scan_completed - scan_started).total_seconds()),
            'findings': [],
            'error': error
        }
