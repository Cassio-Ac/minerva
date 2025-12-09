# Sistema de Blacklist para Mensagens do Telegram

## Visão Geral

Sistema completo de filtragem de mensagens indesejadas/repetitivas nos resultados de pesquisa do Telegram. O sistema permite adicionar padrões de texto ou regex que serão automaticamente filtrados dos resultados de busca.

## Componentes Implementados

### 1. Backend

#### Database (PostgreSQL)
- **Tabela**: `telegram_message_blacklist`
- **Campos**:
  - `id` (UUID) - Identificador único
  - `pattern` (VARCHAR 500) - Padrão de texto ou regex para filtrar
  - `description` (VARCHAR 1000) - Descrição opcional do motivo do filtro
  - `is_regex` (BOOLEAN) - Se o padrão é uma expressão regular
  - `case_sensitive` (BOOLEAN) - Se a correspondência é case-sensitive
  - `is_active` (BOOLEAN) - Se o filtro está ativo
  - `created_at` (TIMESTAMP) - Data de criação
  - `updated_at` (TIMESTAMP) - Data de atualização
  - `created_by` (UUID) - ID do usuário que criou

#### Modelos
- **Arquivo**: `backend/app/models/telegram_blacklist.py`
- **Model**: `TelegramMessageBlacklist`

#### Schemas (Pydantic)
- **Arquivo**: `backend/app/schemas/telegram_blacklist.py`
- **Schemas**:
  - `TelegramBlacklistCreateRequest` - Criação de entrada
  - `TelegramBlacklistUpdateRequest` - Atualização de entrada
  - `TelegramBlacklistResponse` - Resposta com dados da entrada
  - `TelegramBlacklistListResponse` - Lista de entradas

#### API Endpoints
- **Arquivo**: `backend/app/api/v1/telegram_blacklist.py`
- **Rotas** (prefixo: `/api/v1/telegram/blacklist`):
  - `POST /` - Criar nova entrada
  - `GET /` - Listar todas as entradas (com filtro opcional de inativas)
  - `GET /{entry_id}` - Obter entrada específica
  - `PUT /{entry_id}` - Atualizar entrada
  - `DELETE /{entry_id}` - Deletar entrada
  - `POST /{entry_id}/toggle` - Ativar/Desativar entrada

#### Serviço de Busca
- **Arquivo**: `backend/app/services/telegram_search_service.py`
- **Funções adicionadas**:
  - `get_active_blacklist_patterns()` - Carrega padrões ativos do banco
  - `message_matches_blacklist()` - Verifica se mensagem corresponde a algum padrão
- **Modificação**: `search_messages()` agora filtra automaticamente mensagens que correspondem aos padrões da blacklist

#### Database Migration
- **Arquivo**: `backend/alembic/versions/20251124_0000_add_telegram_blacklist_table.py`
- **Revision ID**: `20251124_0000`
- **Down Revision**: `ea1cc794c2ad`

### 2. Frontend

#### Componente de Gerenciamento
- **Arquivo**: `frontend/src/components/TelegramBlacklistManager.tsx`
- **Funcionalidades**:
  - Modal completo para gerenciar filtros
  - Formulário para adicionar/editar entradas
  - Lista de todas as entradas com status
  - Ações: Criar, Editar, Ativar/Desativar, Deletar
  - Suporte a padrões simples ou regex
  - Opção de case-sensitive
  - Descrição opcional para cada filtro

#### Integração na Página de Busca
- **Arquivo**: `frontend/src/pages/TelegramIntelligence.tsx`
- **Modificações**:
  - Botão "Filtros" adicionado ao lado do título de busca
  - Estado para controlar abertura do modal
  - Modal renderizado condicionalmente

## Como Usar

### 1. Adicionar um Filtro

1. Acesse a página de Telegram Intelligence
2. Clique no botão "🚫 Filtros" no canto superior direito da área de busca
3. Clique em "+ Add New Filter"
4. Preencha:
   - **Pattern**: Texto ou regex a ser filtrado (ex: "SPAM MESSAGE", "promo.*desconto")
   - **Description**: Opcional - explicação do motivo do filtro
   - **Regex Pattern**: Marque se o padrão é uma expressão regular
   - **Case Sensitive**: Marque se deve diferenciar maiúsculas/minúsculas
   - **Active**: Marque para ativar imediatamente
5. Clique em "Create"

### 2. Gerenciar Filtros Existentes

- **Ativar/Desativar**: Clique no botão ⏸/▶
- **Editar**: Clique no botão ✏️
- **Deletar**: Clique no botão 🗑️

### 3. Funcionamento Automático

Após adicionar filtros ativos:
- Todas as buscas de mensagens automaticamente filtrarão resultados que correspondem aos padrões
- As mensagens filtradas não aparecem nos resultados
- Um log é gerado no backend indicando quantas mensagens foram filtradas

## Exemplos de Padrões

### Padrões Simples (String)
```
"entre no grupo"
"link na bio"
"promoção imperdível"
"ganhe dinheiro"
```

### Padrões Regex
```
"promo.*desconto" - Corresponde a "promoção com desconto", "promo especial desconto", etc.
"http[s]?://.*" - Filtra todas as URLs
"(?i)telegram\.me/.*" - Filtra links do Telegram (case insensitive)
"\d{10,}" - Filtra mensagens com 10+ dígitos consecutivos
```

## Logs e Monitoramento

O sistema gera logs quando filtra mensagens:
```
🚫 Filtered out 15 messages matching blacklist patterns
```

## Segurança

- Todas as rotas requerem autenticação (token JWT)
- O ID do usuário que criou cada filtro é armazenado
- Padrões regex inválidos são capturados e logados sem quebrar a busca

## Performance

- Filtros são carregados apenas uma vez por requisição de busca
- A filtragem ocorre em memória após o Elasticsearch retornar os resultados
- Padrões regex são compilados sob demanda

## Arquitetura

```
Frontend (TelegramIntelligence.tsx)
    ↓ [Botão Filtros]
TelegramBlacklistManager.tsx (Modal)
    ↓ [API Calls]
/api/v1/telegram/blacklist (FastAPI)
    ↓
telegram_blacklist.py (CRUD Endpoints)
    ↓
TelegramMessageBlacklist (SQLAlchemy Model)
    ↓
PostgreSQL (telegram_message_blacklist table)

Search Flow:
Frontend Search Request
    ↓
/api/v1/telegram/search/messages
    ↓
telegram_search_service.py
    ↓ [Busca no ES]
Elasticsearch Results
    ↓ [Carrega blacklist]
get_active_blacklist_patterns()
    ↓ [Filtra]
message_matches_blacklist()
    ↓
Filtered Results → Frontend
```

## Testes

### Verificar Tabela
```bash
PYTHONPATH=$PWD venv/bin/python check_blacklist_table.py
```

### Testar API (Script de teste criado)
```bash
venv/bin/python test_blacklist.py
```

## Manutenção

### Adicionar Nova Funcionalidade
1. Atualizar model em `telegram_blacklist.py`
2. Criar migração: `alembic revision --autogenerate -m "description"`
3. Atualizar schemas em `telegram_blacklist.py`
4. Atualizar endpoints se necessário
5. Atualizar frontend

### Backup de Filtros
```sql
-- Export
COPY telegram_message_blacklist TO '/tmp/blacklist_backup.csv' CSV HEADER;

-- Import
COPY telegram_message_blacklist FROM '/tmp/blacklist_backup.csv' CSV HEADER;
```

## Troubleshooting

### Filtros não estão funcionando
1. Verifique se o filtro está ativo (`is_active = true`)
2. Verifique logs do backend para erros de regex
3. Teste o padrão isoladamente

### Performance lenta
1. Reduza número de filtros ativos
2. Simplifique padrões regex complexos
3. Use padrões de string simples quando possível

## Futuras Melhorias

- [ ] Estatísticas de quantas mensagens cada filtro bloqueou
- [ ] Importar/Exportar lista de filtros
- [ ] Categorias de filtros (spam, phishing, etc.)
- [ ] Filtros temporários com data de expiração
- [ ] Teste de padrões antes de salvar
- [ ] Compartilhamento de filtros entre usuários
- [ ] Aplicação de filtros no lado do Elasticsearch (mais eficiente)
