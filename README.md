# Dara Edge VAPT Scanner Service

Real-world vulnerability assessment and penetration testing service using industry-standard open source tools.

## 🛡️ Security Tools Included

| Tool | Purpose | Version |
|------|---------|---------|
| **Nmap** | Network discovery & port scanning | Latest |
| **OWASP ZAP** | Web application security testing | 2.14.0 |
| **Nikto** | Web server vulnerability scanning | 2.5.0 |
| **Nuclei** | Template-based vulnerability scanning | 3.1.0 |
| **SSLyze** | SSL/TLS configuration analysis | 5.2.0 |

## 🏗️ Architecture

```
┌─────────────────┐
│  Dara Edge UI   │
└────────┬────────┘
         │ HTTP POST /run-vapt
         ▼
┌──────────────────────────────┐
│  Supabase Edge Function      │
│  Creates job in queue        │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│    vapt_scan_jobs table      │
│    Status: queued            │
└────────┬─────────────────────┘
         │ Polling
         ▼
┌──────────────────────────────┐
│   VAPT Scanner Service       │
│  (This Docker Container)     │
│                              │
│  ┌────────────────────────┐  │
│  │ Nmap Scanner          │  │
│  │ ZAP Scanner           │  │
│  │ Nikto Scanner         │  │
│  │ Nuclei Scanner        │  │
│  │ SSLyze Scanner        │  │
│  └────────────────────────┘  │
└────────┬─────────────────────┘
         │ Updates results
         ▼
┌──────────────────────────────┐
│  vapt_scan_jobs table        │
│  Status: completed           │
│  Results: {...}              │
└──────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Supabase project with service role key
- Database migration applied

### 1. Apply Database Migration

First, run the migration on your Supabase project:

```bash
cd dara-guard-core
npx supabase db push
```

Or manually apply:
```sql
-- Run the migration file:
-- supabase/migrations/20251107_create_vapt_job_queue.sql
```

### 2. Configure Environment

```bash
cd vapt-scanner
cp .env.example .env
# Edit .env with your credentials
```

Required environment variables:
- `SUPABASE_URL`: Your Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY`: Service role key (not anon key!)
- `LOVABLE_API_KEY`: (Optional) For AI-powered analysis

### 3. Build and Run

```bash
# Build the Docker image
docker-compose build

# Start the scanner service
docker-compose up -d

# View logs
docker-compose logs -f vapt-scanner
```

## 📋 Usage

### From the UI

1. Navigate to VAPT page in Dara Edge
2. Enter target URL
3. Select scan type
4. Click "Start Scan"
5. Watch real-time progress
6. View results when complete

### Programmatically

```javascript
// Create a scan job via Supabase
const { data, error } = await supabase
  .table('vapt_scan_jobs')
  .insert({
    organization_id: 'your-org-id',
    created_by: userId,
    target: 'https://example.com',
    scan_type: 'full',
    tools_enabled: ['nmap', 'zap', 'nikto', 'nuclei', 'sslyze'],
    status: 'queued'
  });

// Scanner service will automatically pick it up!
```

### Monitoring Scans

```bash
# Watch scanner logs
docker-compose logs -f

# Check scan status in database
SELECT id, target, status, progress, current_step
FROM vapt_scan_jobs
WHERE status = 'running';
```

## 🔧 Configuration

### Scan Types

- `full`: Run all scanners
- `quick`: Fast scan (Nmap + Nikto)
- `web_app`: Web-focused (ZAP + Nikto + Nuclei)
- `network`: Network-focused (Nmap only)
- `ssl`: SSL/TLS only (SSLyze)

### Customize Tools

Edit `scanner_service.py` to adjust:
- Scan timeouts
- Tool-specific parameters
- Polling interval
- Concurrent scans

Example:
```python
# In scanner_service.py
await service.poll_jobs(poll_interval=10)  # Poll every 10 seconds
```

## 📊 Results Format

Scan results are stored in `vapt_scan_jobs.results`:

```json
{
  "target": "https://example.com",
  "scan_completed_at": "2025-01-07T10:30:00Z",
  "tools_used": ["nmap", "zap", "nikto", "nuclei", "sslyze"],
  "total_findings": 42,
  "critical_count": 3,
  "high_count": 8,
  "medium_count": 15,
  "low_count": 16,
  "findings": [
    {
      "category": "port_scan",
      "title": "Open Port: 3389/rdp",
      "description": "Port 3389 is open running Microsoft Terminal Services",
      "severity": "critical",
      "remediation": "Disable RDP if not needed...",
      "cvss_score": 9.8,
      "...": "..."
    }
  ],
  "ai_analysis": {
    "summary": "...",
    "recommendations": ["..."],
    "risk_score": 75
  }
}
```

## 🔍 Tool-Specific Results

Individual tool results are stored in `vapt_tool_results` table for detailed analysis:

```sql
SELECT tool_name, findings_count, critical_count, scan_duration_seconds
FROM vapt_tool_results
WHERE scan_job_id = 'your-job-id';
```

## 🐛 Troubleshooting

### Scanner not picking up jobs

```bash
# Check if service is running
docker-compose ps

# View logs
docker-compose logs vapt-scanner

# Verify database connection
docker-compose exec vapt-scanner python -c "from supabase import create_client; print('OK')"
```

### Scan timing out

Increase timeout in `scanner_service.py`:
```python
# In individual scanner files
timeout=600  # 10 minutes instead of 5
```

### Permission errors

```bash
# Fix output directory permissions
chmod 777 scan_outputs/

# Or run as root (not recommended)
docker-compose run --user root vapt-scanner /bin/bash
```

## 🔒 Security Considerations

1. **Target Validation**: Only scan domains you own or have permission to test
2. **Rate Limiting**: Implement rate limits to prevent abuse
3. **Network Isolation**: Consider running in isolated network
4. **Credentials**: Never commit `.env` file - use secrets management
5. **Results Storage**: Scan results may contain sensitive data - implement proper access controls

## 📈 Performance

Expected scan times (approximate):

| Scan Type | Duration | Tools Used |
|-----------|----------|------------|
| Quick | 2-5 min | Nmap, Nikto |
| Web App | 5-10 min | ZAP, Nikto, Nuclei |
| Full | 10-15 min | All tools |
| SSL Only | 1-2 min | SSLyze |

**Resource Usage:**
- CPU: 1-2 cores
- Memory: 2-4 GB
- Disk: <1 GB

## 🔄 Scaling

### Horizontal Scaling

Run multiple scanner instances:

```bash
docker-compose up -d --scale vapt-scanner=3
```

Each instance will poll for jobs independently.

### Vertical Scaling

Adjust resource limits in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '4'  # Increase from 2
      memory: 8G  # Increase from 4G
```

## 📚 API Reference

### Scanner Service Methods

```python
# Main orchestrator
class VAPTScannerService:
    async def poll_jobs(poll_interval: int)
    async def process_job(job: ScanJobConfig)
    def update_job(job_id: str, updates: Dict)
    def store_tool_result(job_id: str, tool_name: str, result: Dict)
```

### Individual Scanners

All scanners implement:

```python
async def scan(target: str) -> Dict[str, Any]:
    """
    Returns:
    {
        'tool_name': str,
        'tool_version': str,
        'target': str,
        'scan_started_at': str,
        'scan_completed_at': str,
        'scan_duration_seconds': int,
        'findings': List[Dict],
        'raw_output': str
    }
    """
```

## 🛠️ Development

### Adding New Scanners

1. Create scanner in `scanners/new_scanner.py`:

```python
class NewScanner:
    async def scan(self, target: str) -> Dict[str, Any]:
        # Implementation
        pass
```

2. Register in `scanner_service.py`:

```python
self.scanners = {
    ...
    'new_tool': NewScanner()
}
```

3. Add to database enum:

```sql
ALTER TABLE vapt_tool_results
DROP CONSTRAINT vapt_tool_results_tool_name_check;

ALTER TABLE vapt_tool_results
ADD CONSTRAINT vapt_tool_results_tool_name_check
CHECK (tool_name IN ('nmap', 'zap', 'nikto', 'nuclei', 'sslyze', 'new_tool'));
```

### Running Tests

```bash
# Install dev dependencies
pip install pytest pytest-asyncio pytest-cov

# Run tests
pytest tests/

# With coverage
pytest --cov=scanners tests/
```

## 📝 License

This project uses open source security tools:
- Nmap: GPL v2
- OWASP ZAP: Apache 2.0
- Nikto: GPL v2
- Nuclei: MIT
- SSLyze: AGPL v3

## 🤝 Contributing

Contributions welcome! Areas for improvement:

1. Add more scanners (OpenVAS, Metasploit, etc.)
2. Implement scan scheduling
3. Add webhook notifications
4. Create custom scan profiles
5. Improve AI analysis

## 📞 Support

- Documentation: `VAPT_ARCHITECTURE.md`
- Issues: GitHub Issues
- Email: support@dara-edge.com

## ⚠️ Disclaimer

This tool is for authorized security testing only. Unauthorized scanning of systems you don't own is illegal. Always obtain written permission before conducting security assessments.

---

**Built with ❤️ by the Dara Edge Security Team**
