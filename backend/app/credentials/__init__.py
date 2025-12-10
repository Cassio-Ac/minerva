"""
Credentials Module - Minerva Intelligence Platform

Este modulo gerencia:
- Consulta Externa: Busca de credenciais vazadas via bots do Telegram
- Data Lake: Armazenamento local de dados de vazamentos (futuro)

================================================================================
CONFIGURACAO DE CONTAS TELEGRAM
================================================================================

As sessoes do Telegram sao arquivos .session que contem as credenciais de
autenticacao da conta. Elas sao geradas automaticamente pelo Telethon na
primeira autenticacao.

LOCALIZACAO DAS SESSOES:
    backend/app/credentials/sessions/

CONTA PADRAO:
    Nome: angello
    Arquivo: session_angello.session
    Telefone: +55 51 98118-4847

CONFIGURACAO VIA .ENV:
    TELEGRAM_API_ID=29746479
    TELEGRAM_API_HASH=e9c6d52ad31d7233a2f9f323d5d0f500
    TELEGRAM_PHONE=+5551981184847
    TELEGRAM_SESSION_NAME=session_angello

PARA ADICIONAR NOVAS CONTAS:
    1. Crie um novo arquivo .session usando o script:
       python scripts/create_telegram_session.py

    2. O script vai solicitar:
       - API ID (obter em https://my.telegram.org)
       - API Hash
       - Numero de telefone
       - Codigo de verificacao (enviado por SMS/Telegram)

    3. Copie o arquivo .session gerado para:
       backend/app/credentials/sessions/

    4. Atualize o .env com as novas credenciais ou use
       as variaveis de ambiente para alternar entre contas

BOTS SUPORTADOS:
    - Database Lookup (ID: 6574456300)
      Tipos de consulta: email, cpf, phone, domain, username, ip

ESTRUTURA DO MODULO:
    app/credentials/
        __init__.py          - Esta documentacao
        api/
            external_query.py - Endpoints REST da API
        models/
            external_query.py - Modelo SQLAlchemy para historico
        services/
            telegram_bot_service.py - Servico de interacao com bots
        sessions/
            session_angello.session - Arquivo de sessao padrao

ENDPOINTS DA API:
    POST   /api/v1/credentials/query           - Executa consulta externa
    GET    /api/v1/credentials/query/{id}      - Obtem resultado
    GET    /api/v1/credentials/query/{id}/html - Visualiza HTML
    GET    /api/v1/credentials/query/{id}/download - Baixa arquivo
    GET    /api/v1/credentials/history         - Historico de consultas
    GET    /api/v1/credentials/stats           - Estatisticas
    GET    /api/v1/credentials/bots            - Bots disponiveis
    GET    /api/v1/credentials/session         - Info da sessao

DOWNLOADS:
    Os arquivos HTML baixados dos bots sao salvos em:
    backend/downloads/credentials/

================================================================================
"""
