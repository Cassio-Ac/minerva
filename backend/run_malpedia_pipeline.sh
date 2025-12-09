#!/bin/bash
# Script para executar o Malpedia Pipeline dentro do container Docker

echo "🚀 Executando Malpedia Pipeline no container Docker..."
echo ""

# Copia o script para dentro do container
docker cp malpedia_pipeline.py intelligence-platform-backend:/app/malpedia_pipeline.py

# Executa o pipeline
docker exec -it intelligence-platform-backend bash -c "
cd /app && \
export PYTHONPATH=/app && \
python3 malpedia_pipeline.py
"
