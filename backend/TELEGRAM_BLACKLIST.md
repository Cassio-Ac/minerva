# Sistema de Blacklist para Telegram

## Visão Geral

Sistema de filtragem de mensagens do Telegram que permite remover mensagens repetitivas ou indesejadas dos resultados de busca. Útil para limpar análises quando mensagens são enviadas múltiplas vezes em vários grupos.

## Funcionalidades

- ✅ Filtros com strings simples ou regex
- ✅ Case-sensitive ou case-insensitive
- ✅ Ativação/desativação de filtros sem deletar
- ✅ Interface web integrada na página de Telegram
- ✅ Aplicação automática durante buscas
- ✅ CRUD completo via API REST

## Arquitetura

### Backend

#### 1. Database Migration
**Arquivo:** `backend/alembic/versions/20251124_0000_add_telegram_blacklist_table.py`

Cria a tabela `telegram_message_blacklist`:
- `id` (UUID) - Primary key
- `pattern` (String) - Padrão a ser filtrado
- `description` (String) - Descrição opcional
- `is_regex` (Boolean) - Se é regex ou string literal
- `case_sensitive` (Boolean) - Se é case-sensitive
- `is_active` (Boolean) - Se o filtro está ativo
- `created_at`, `updated_at` (DateTime)
- `created_by` (UUID) - Usuário que criou

**Índices:**
- `ix_telegram_message_blacklist_pattern` (otimiza buscas)
- `ix_telegram_message_blacklist_is_active` (otimiza filtros ativos)

#### 2. SQLAlchemy Model
**Arquivo:** `backend/app/models/telegram_blacklist.py`

Modelo ORM com relacionamento ao usuário criador.

#### 3. Pydantic Schemas
**Arquivo:** `backend/app/schemas/telegram_blacklist.py`

- `TelegramBlacklistCreateRequest` - Criar nova entrada
- `TelegramBlacklistUpdateRequest` - Atualizar entrada (campos opcionais)
- `TelegramBlacklistResponse` - Resposta com entrada completa
- `TelegramBlacklistListResponse` - Lista com total e itens

#### 4. API Endpoints
**Arquivo:** `backend/app/api/v1/telegram_blacklist.py`

**Base URL:** `/api/v1/telegram/blacklist`

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/` | Criar nova entrada |
| GET | `/` | Listar todas (query: `include_inactive=bool`) |
| GET | `/{entry_id}` | Buscar por ID |
| PUT | `/{entry_id}` | Atualizar entrada |
| DELETE | `/{entry_id}` | Deletar permanentemente |
| POST | `/{entry_id}/toggle` | Ativar/desativar |

**Autenticação:** Todas as rotas requerem JWT token (header `Authorization: Bearer <token>`)

**Importante:** Usa `AsyncSession` com `await` em todas operações de banco:
```python
async def create_blacklist_entry(
    request: TelegramBlacklistCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    entry = TelegramMessageBlacklist(...)
    db.add(entry)
    await db.flush()
    await db.commit()
    await db.refresh(entry)
    return entry
```

#### 5. Integração no Telegram Search
**Arquivo:** `backend/app/services/telegram_search_service.py`

**Funções adicionadas:**

1. `get_active_blacklist_patterns()` - Carrega padrões ativos do banco
```python
async def get_active_blacklist_patterns() -> List[Dict[str, Any]]:
    async with AsyncSessionLocal() as session:
        stmt = select(TelegramMessageBlacklist).where(
            TelegramMessageBlacklist.is_active == True
        )
        result = await session.execute(stmt)
        patterns = result.scalars().all()
        return [
            {
                "pattern": p.pattern,
                "is_regex": p.is_regex,
                "case_sensitive": p.case_sensitive
            }
            for p in patterns
        ]
```

2. `message_matches_blacklist()` - Verifica se mensagem bate com algum padrão
```python
def message_matches_blacklist(message: str, patterns: List[Dict]) -> bool:
    for p in patterns:
        if p["is_regex"]:
            flags = 0 if p["case_sensitive"] else re.IGNORECASE
            if re.search(p["pattern"], message, flags):
                return True
        else:
            if p["case_sensitive"]:
                if p["pattern"] in message:
                    return True
            else:
                if p["pattern"].lower() in message.lower():
                    return True
    return False
```

3. **Aplicação na busca** (dentro de `search_messages()`):
```python
# Buscar no Elasticsearch
response = es.search(index=index_pattern, body=search_body)
hits = response["body"]["hits"]["hits"]

# Aplicar blacklist filtering
blacklist_patterns = await get_active_blacklist_patterns()
if blacklist_patterns:
    filtered_hits = []
    filtered_count = 0
    for hit in hits:
        message_text = hit['_source'].get('message', '')
        if not message_matches_blacklist(message_text, blacklist_patterns):
            filtered_hits.append(hit)
        else:
            filtered_count += 1
    
    logger.info(f"🚫 Filtered out {filtered_count} messages")
    hits = filtered_hits
    total = len(filtered_hits)
```

**Ordem de execução:**
1. Elasticsearch retorna resultados
2. Blacklist filtra os resultados
3. Retorna apenas mensagens que NÃO bateram com nenhum padrão

#### 6. Registro no Main
**Arquivo:** `backend/app/main.py`

```python
from app.api.v1 import telegram_blacklist

app.include_router(
    telegram_blacklist.router,
    prefix="/api/v1",
    tags=["telegram"]
)
```

### Frontend

#### 1. Componente de Gerenciamento
**Arquivo:** `frontend/src/components/TelegramBlacklistManager.tsx`

Interface completa para:
- Listar entradas (ativas/inativas)
- Criar nova entrada com formulário
- Editar entrada existente
- Ativar/desativar (toggle)
- Deletar entrada
- Badges visuais (Regex, Case-sensitive, Ativo/Inativo)

**Cores corrigidas para tema:**
```typescript
backgroundColor: currentColors.bg.primary,
color: currentColors.text.primary,
border: `1px solid ${currentColors.border.default}`,
```

#### 2. Integração na Página Telegram
**Arquivo:** `frontend/src/pages/TelegramIntelligence.tsx`

**Botão adicionado:**
```typescript
<button
  onClick={() => setShowBlacklistManager(true)}
  style={{...}}
  title="Manage message filters"
>
  <span>🚫</span>
  <span>Filtros</span>
</button>
```

**Modal:**
```typescript
{showBlacklistManager && (
  <TelegramBlacklistManager
    onClose={() => setShowBlacklistManager(false)}
  />
)}
```

## Exemplos de Uso

### 1. Filtrar mensagem exata
```json
POST /api/v1/telegram/blacklist
{
  "pattern": "COMPRE AGORA!",
  "description": "Spam de vendas",
  "is_regex": false,
  "case_sensitive": false,
  "is_active": true
}
```

### 2. Filtrar com regex
```json
POST /api/v1/telegram/blacklist
{
  "pattern": "\\b(bitcoin|crypto)\\s+(giveaway|airdrop)\\b",
  "description": "Golpes de cripto",
  "is_regex": true,
  "case_sensitive": false,
  "is_active": true
}
```

### 3. Filtrar URLs
```json
POST /api/v1/telegram/blacklist
{
  "pattern": "https?://bit\\.ly/\\w+",
  "description": "Links encurtados suspeitos",
  "is_regex": true,
  "case_sensitive": false,
  "is_active": true
}
```

## Correções Aplicadas

### 1. AsyncSession Fix
**Problema:** `RuntimeWarning: coroutine 'AsyncSession.commit' was never awaited`

**Solução:** Mudou de `Session` para `AsyncSession` com `await`:
```python
# Antes
db: Session = Depends(get_db)
db.commit()

# Depois
db: AsyncSession = Depends(get_db)
await db.commit()
```

### 2. User ID Fix
**Problema:** `'User' object has no attribute 'get'`

**Solução:**
```python
# Antes
created_by=current_user.get("sub")

# Depois
created_by=current_user.id if current_user else None
```

### 3. Theme Colors Fix
**Problema:** Modal transparente

**Solução:** Usar estrutura correta de cores:
```typescript
// Antes
backgroundColor: currentColors.background

// Depois
backgroundColor: currentColors.bg.primary
```

### 4. SSO Removed
**Problema:** Frontend tentava buscar SSO providers (não existe neste projeto)

**Solução:** Removido useEffect que buscava `/auth/sso/providers`

## Performance

**Telegram Search com Blacklist:**
- Tempo adicional: ~5-50ms dependendo do número de padrões
- Não impacta query Elasticsearch (filtra após retorno)
- Regex patterns são mais lentos que string matching

**Recomendações:**
- Manter número de padrões abaixo de 100
- Preferir string matching quando possível
- Usar regex apenas quando necessário
- Desativar filtros não usados (não deletar, apenas toggle)

## Troubleshooting

### Filtros não aplicados
1. Verificar se filtro está `is_active: true`
2. Verificar logs: `🚫 Filtered out X messages`
3. Testar padrão isoladamente

### Regex não funciona
1. Escapar caracteres especiais: `\\.`, `\\(`, `\\[`
2. Usar tool online para testar: regex101.com
3. Verificar flag case_sensitive

### Performance lenta
1. Verificar número de padrões ativos
2. Otimizar regex (evitar backtracking)
3. Considerar cache de padrões (TODO)

## TODO / Melhorias Futuras

- [ ] Cache de padrões em memória (Redis)
- [ ] Estatísticas de filtros (quantas mensagens cada padrão filtrou)
- [ ] Import/export de blacklists
- [ ] Templates de blacklists (spam comum, golpes, etc)
- [ ] Preview de resultados antes de ativar filtro
- [ ] Histórico de modificações
- [ ] Compartilhamento de blacklists entre usuários
