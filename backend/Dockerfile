# Backend Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including Node.js for MCP servers and Chromium for Kaleido
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    git \
    chromium \
    chromium-driver \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Set Chromium path for Kaleido
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROME_PATH=/usr/bin/chromium

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install common MCP servers (Python-based)
RUN pip install --no-cache-dir \
    mcp-server-git \
    httpx \
    mcp \
    plotly \
    requests

# Install common MCP servers (Node.js-based)
RUN npm install -g \
    @modelcontextprotocol/server-filesystem \
    @modelcontextprotocol/server-github \
    @modelcontextprotocol/server-postgres

# Copy application
COPY . .

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app.main:socket_app", "--host", "0.0.0.0", "--port", "8000"]
