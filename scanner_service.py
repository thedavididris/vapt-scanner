"""
VAPT Scanner Service - Main Orchestrator
Polls Supabase for queued scan jobs and executes real security tools
"""

import asyncio
import json
import os
import sys
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from supabase import create_client, Client
from pydantic import BaseModel, Field

# Import tool scanners
from scanners.nmap_scanner import NmapScanner
from scanners.zap_scanner import ZapScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.sslyze_scanner import SSLyzeScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class ScanJobConfig(BaseModel):
    """Configuration for a scan job"""
    id: str
    organization_id: str
    target: str
    scan_type: str
    tools_enabled: List[str] = Field(default_factory=list)
    status: str
    created_at: str


class VAPTScannerService:
    """Main VAPT scanner service that orchestrates all security tools"""

    def __init__(self):
        """Initialize the scanner service"""
        self.supabase_url = os.getenv('SUPABASE_URL')
        self.supabase_key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')

        if not self.supabase_url or not self.supabase_key:
            raise ValueError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")

        self.supabase: Client = create_client(self.supabase_url, self.supabase_key)

        # Initialize scanners
        self.scanners = {
            'nmap': NmapScanner(),
            'zap': ZapScanner(),
            'nikto': NiktoScanner(),
            'nuclei': NucleiScanner(),
            'sslyze': SSLyzeScanner()
        }

        logger.info("VAPT Scanner Service initialized successfully")
        logger.info(f"Available scanners: {', '.join(self.scanners.keys())}")

    async def poll_jobs(self, poll_interval: int = 5):
        """
        Poll for queued scan jobs and process them

        Args:
            poll_interval: Seconds to wait between polls
        """
        logger.info(f"Starting job polling (interval: {poll_interval}s)")

        while True:
            try:
                # Get next queued job
                response = self.supabase.table('vapt_scan_jobs')\
                    .select('*')\
                    .eq('status', 'queued')\
                    .order('created_at')\
                    .limit(1)\
                    .execute()

                if response.data and len(response.data) > 0:
                    job_data = response.data[0]
                    job = ScanJobConfig(**job_data)
                    logger.info(f"Found queued job: {job.id} - Target: {job.target}")

                    await self.process_job(job)
                else:
                    logger.debug("No queued jobs found")

                await asyncio.sleep(poll_interval)

            except Exception as e:
                logger.error(f"Error in job polling loop: {e}", exc_info=True)
                await asyncio.sleep(poll_interval * 2)  # Back off on error

    async def process_job(self, job: ScanJobConfig):
        """
        Process a single scan job

        Args:
            job: Scan job configuration
        """
        job_id = job.id

        try:
            # Update status to running
            logger.info(f"Starting scan job {job_id}")
            self.update_job(job_id, {
                'status': 'running',
                'started_at': datetime.now(timezone.utc).isoformat(),
                'progress': 0
            })

            target = job.target
            tools_enabled = job.tools_enabled or list(self.scanners.keys())

            # Validate target
            if not self.is_valid_target(target):
                raise ValueError(f"Invalid target: {target}")

            all_findings = []
            tool_results = {}

            # Calculate progress increment per tool
            progress_per_tool = 80 // len(tools_enabled) if tools_enabled else 80
            current_progress = 0

            # Run each enabled scanner
            for tool_name in tools_enabled:
                if tool_name not in self.scanners:
                    logger.warning(f"Unknown scanner: {tool_name}, skipping")
                    continue

                try:
                    logger.info(f"Running {tool_name.upper()} scan on {target}")
                    self.update_job(job_id, {
                        'current_step': f'Running {tool_name.upper()} scan',
                        'progress': current_progress
                    })

                    scanner = self.scanners[tool_name]
                    tool_result = await scanner.scan(target)

                    # Store tool-specific results
                    self.store_tool_result(job_id, tool_name, tool_result)

                    # Extract findings
                    findings = tool_result.get('findings', [])
                    all_findings.extend(findings)
                    tool_results[tool_name] = {
                        'findings_count': len(findings),
                        'scan_duration': tool_result.get('scan_duration_seconds', 0),
                        'status': 'completed'
                    }

                    current_progress += progress_per_tool
                    logger.info(f"{tool_name.upper()} scan completed: {len(findings)} findings")

                except Exception as e:
                    logger.error(f"Error in {tool_name} scanner: {e}", exc_info=True)
                    tool_results[tool_name] = {
                        'status': 'failed',
                        'error': str(e)
                    }

            # Generate AI analysis
            logger.info("Generating AI analysis")
            self.update_job(job_id, {
                'current_step': 'Generating AI analysis',
                'progress': 90
            })

            try:
                ai_analysis = await self.generate_ai_analysis(target, all_findings)
            except Exception as e:
                logger.error(f"AI analysis failed: {e}", exc_info=True)
                ai_analysis = self.generate_fallback_analysis(all_findings)

            # Aggregate results
            final_results = {
                'target': target,
                'scan_completed_at': datetime.now(timezone.utc).isoformat(),
                'tools_used': tools_enabled,
                'total_findings': len(all_findings),
                'critical_count': sum(1 for f in all_findings if f.get('severity') == 'critical'),
                'high_count': sum(1 for f in all_findings if f.get('severity') == 'high'),
                'medium_count': sum(1 for f in all_findings if f.get('severity') == 'medium'),
                'low_count': sum(1 for f in all_findings if f.get('severity') == 'low'),
                'findings': all_findings,
                'ai_analysis': ai_analysis,
                'tool_results': tool_results
            }

            # Create security logs
            await self.create_security_logs(job, all_findings)

            # Create incidents for critical findings
            critical_findings = [f for f in all_findings if f.get('severity') == 'critical']
            if critical_findings:
                await self.create_incident(job, critical_findings, ai_analysis)

            # Mark job as completed
            self.update_job(job_id, {
                'status': 'completed',
                'progress': 100,
                'current_step': 'Scan completed',
                'results': final_results,
                'completed_at': datetime.now(timezone.utc).isoformat(),
                'total_findings': len(all_findings),
                'critical_count': final_results['critical_count'],
                'high_count': final_results['high_count'],
                'medium_count': final_results['medium_count'],
                'low_count': final_results['low_count']
            })

            logger.info(f"Scan job {job_id} completed successfully: {len(all_findings)} total findings")

        except Exception as e:
            logger.error(f"Error processing job {job_id}: {e}", exc_info=True)
            self.update_job(job_id, {
                'status': 'failed',
                'error_message': str(e),
                'completed_at': datetime.now(timezone.utc).isoformat()
            })

    def update_job(self, job_id: str, updates: Dict[str, Any]):
        """Update scan job in database"""
        try:
            updates['updated_at'] = datetime.now(timezone.utc).isoformat()
            self.supabase.table('vapt_scan_jobs')\
                .update(updates)\
                .eq('id', job_id)\
                .execute()
            logger.debug(f"Updated job {job_id}: {list(updates.keys())}")
        except Exception as e:
            logger.error(f"Failed to update job {job_id}: {e}")

    def store_tool_result(self, job_id: str, tool_name: str, result: Dict[str, Any]):
        """Store detailed tool results in database"""
        try:
            findings = result.get('findings', [])

            tool_result = {
                'scan_job_id': job_id,
                'tool_name': tool_name,
                'tool_version': result.get('tool_version', 'unknown'),
                'raw_output': result.get('raw_output', ''),
                'parsed_results': result,
                'findings_count': len(findings),
                'critical_count': sum(1 for f in findings if f.get('severity') == 'critical'),
                'high_count': sum(1 for f in findings if f.get('severity') == 'high'),
                'medium_count': sum(1 for f in findings if f.get('severity') == 'medium'),
                'low_count': sum(1 for f in findings if f.get('severity') == 'low'),
                'scan_duration_seconds': result.get('scan_duration_seconds', 0),
                'scan_started_at': result.get('scan_started_at'),
                'scan_completed_at': result.get('scan_completed_at')
            }

            self.supabase.table('vapt_tool_results').insert(tool_result).execute()
            logger.debug(f"Stored {tool_name} results for job {job_id}")

        except Exception as e:
            logger.error(f"Failed to store tool result: {e}")

    async def create_security_logs(self, job: ScanJobConfig, findings: List[Dict[str, Any]]):
        """Create security log entries for scan findings"""
        try:
            logs = []
            for finding in findings:
                log_entry = {
                    'organization_id': job.organization_id,
                    'log_source_id': None,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'severity': finding.get('severity', 'info'),
                    'log_type': 'vapt',
                    'raw_log': json.dumps(finding),
                    'parsed_data': finding,
                    'tags': ['vapt', job.scan_type, finding.get('category', 'general')],
                    'threat_detected': finding.get('severity') in ['critical', 'high'],
                    'threat_score': self.get_severity_score(finding.get('severity', 'info'))
                }
                logs.append(log_entry)

            if logs:
                # Insert in batches of 100
                for i in range(0, len(logs), 100):
                    batch = logs[i:i+100]
                    self.supabase.table('security_logs').insert(batch).execute()

                logger.info(f"Created {len(logs)} security log entries")

        except Exception as e:
            logger.error(f"Failed to create security logs: {e}")

    async def create_incident(self, job: ScanJobConfig, critical_findings: List[Dict], ai_analysis: Dict):
        """Create incident for critical findings"""
        try:
            incident = {
                'title': f'VAPT Scan: {len(critical_findings)} Critical Vulnerabilities Detected',
                'description': f'Automated VAPT scan on {job.target} detected critical security issues:\n\n' +
                              '\n'.join([f"- {f.get('title', 'Unknown')}: {f.get('description', '')}"
                                       for f in critical_findings[:5]]) +
                              f'\n\nAI Analysis:\n{ai_analysis.get("summary", "No summary available")}',
                'severity': 'critical',
                'status': 'open',
                'incident_id': f'VAPT-{job.id[:8]}-{int(datetime.now().timestamp())}',
                'organization_id': job.organization_id
            }

            self.supabase.table('incidents').insert(incident).execute()
            logger.info(f"Created incident for {len(critical_findings)} critical findings")

        except Exception as e:
            logger.error(f"Failed to create incident: {e}")

    async def generate_ai_analysis(self, target: str, findings: List[Dict]) -> Dict[str, Any]:
        """Generate AI-powered analysis of findings"""
        # Implementation would call AI service
        # For now, return structured analysis
        return self.generate_fallback_analysis(findings)

    def generate_fallback_analysis(self, findings: List[Dict]) -> Dict[str, Any]:
        """Generate basic analysis without AI"""
        critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
        high_count = sum(1 for f in findings if f.get('severity') == 'high')

        summary = f"Security scan found {len(findings)} issues"
        if critical_count > 0:
            summary += f" including {critical_count} critical vulnerabilities requiring immediate attention"
        if high_count > 0:
            summary += f" and {high_count} high-severity issues"

        recommendations = []
        for finding in findings:
            if finding.get('severity') in ['critical', 'high'] and finding.get('remediation'):
                recommendations.append(finding['remediation'])

        return {
            'summary': summary,
            'recommendations': recommendations[:5],
            'risk_score': min(100, critical_count * 25 + high_count * 15),
            'ai_insights': summary
        }

    @staticmethod
    def is_valid_target(target: str) -> bool:
        """Validate scan target"""
        if not target:
            return False
        # Add more validation as needed
        return target.startswith('http://') or target.startswith('https://') or '.' in target

    @staticmethod
    def get_severity_score(severity: str) -> float:
        """Convert severity to numeric score"""
        scores = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.3,
            'info': 0.1
        }
        return scores.get(severity.lower(), 0.5)


async def main():
    """Main entry point"""
    logger.info("="*60)
    logger.info("Starting VAPT Scanner Service")
    logger.info("="*60)

    try:
        service = VAPTScannerService()
        await service.poll_jobs(poll_interval=5)
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
