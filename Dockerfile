FROM python:3.11-slim

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    # Essential build tools
    build-essential \
    git \
    wget \
    curl \
    unzip \
    ca-certificates \
    # Security scanning tool
    nmap \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (vulnerability scanner)
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip -q nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm nuclei_3.1.0_linux_amd64.zip

# Update Nuclei templates (allow failure since it needs internet)
RUN nuclei -update-templates || true

# Set working directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output directory for scan results
RUN mkdir -p /app/scan_outputs

# Run as non-root user for security
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app
USER scanner

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Start the scanner service
CMD ["python", "-u", "scanner_service.py"]
