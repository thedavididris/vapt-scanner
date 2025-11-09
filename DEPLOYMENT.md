# VAPT Scanner - Cloud Deployment

This is the standalone VAPT scanner service that can be deployed to any cloud platform.

## Quick Deploy to Railway.app

1. Create account at https://railway.app
2. Click "New Project" → "Deploy from GitHub repo"
3. Select this repository
4. Add these environment variables:
   ```
   SUPABASE_URL=https://pwqddjtnpzmdgifcsafh.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here
   LOG_LEVEL=INFO
   ```
5. Railway will automatically build and deploy!

## What This Does

- Polls Supabase database for queued VAPT scan jobs
- Runs real security tools: Nmap, OWASP ZAP, Nikto, Nuclei, SSLyze
- Stores results back in Supabase
- Creates incidents for critical findings

## Requirements

- Supabase project with vapt_scan_jobs and vapt_tool_results tables
- Service role key (not anon key!)

## Cost

- Railway: FREE tier available
- Render: FREE tier available
- Google Cloud Run: FREE tier (first 2M requests)

## Support

See main documentation in parent repository.
