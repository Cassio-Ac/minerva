# 🔧 Fix: Telegram Context Modal - Mensagem Errada Destacada

**Data**: 2025-11-19
**Problema**: Ao clicar em uma mensagem de busca, o modal de contexto mostrava uma mensagem diferente destacada.

---

## 📋 Resumo do Problema

### Sintomas
- Usuário buscava "nubank"
- Clicava na mensagem "Alguem com nubank fake??" (ID: 1576555)
- Modal abria mostrando mensagem "Coragem" (ID: 1576555) destacada
- Mensagens eram de grupos diferentes (Consultas2025 vs SurvivorRPG)

### Root Cause

**Múltiplas mensagens com mesmo ID em grupos diferentes compartilhando o mesmo índice Elasticsearch.**

#### Contexto Técnico

O sistema refatorado de coleta do Telegram usa uma arquitetura diferente:

**Sistema Antigo** (por grupo):
```
telegram_messages_consultas2025/
telegram_messages_survivorrpg/
telegram_messages_puxadasgratis/
```

**Sistema Novo** (índice único compartilhado):
```
telegram_messages_v2/  ← TODOS os grupos aqui!
  ├─ Consultas2025 (group_id: 2656776524)
  ├─ SurvivorRPG (group_id: 1234567890)
  └─ ...
```

**Por que mensagens têm mesmo ID?**
- IDs de mensagens são únicos **por grupo** no Telegram
- Grupos diferentes podem ter mensagens com mesmo ID
- Exemplo: Grupo A e Grupo B podem ter mensagem ID 1576555

---

## 🔍 Investigação

### Logs de Diagnóstico

**Mensagem Clicada**:
```javascript
{
  id: 1576555,
  message: "Alguem com nubank fake??",
  group_info: {
    group_id: 2656776524,
    group_title: "Consultas2025",
    group_username: "puxadasgratis"
  }
}
```

**Contexto Retornado** (ERRADO):
```javascript
{
  selected_message_id: 1576555,
  messages: [
    {
      id: 1576555,
      message: "Coragem",  // ❌ MENSAGEM ERRADA!
      group_info: {
        group_id: 1234567890,  // ❌ GRUPO ERRADO!
        group_title: "Role Playing Game de Turnos - Harry Potter"
      }
    }
  ]
}
```

### Query Elasticsearch Original (PROBLEMA)

```python
# ❌ BUSCA APENAS POR ID - IGNORA O GRUPO!
query = {
    "range": {
        "id": {
            "gte": msg_id - before * 2,
            "lte": msg_id + after * 2
        }
    }
}
```

**Resultado**: Elasticsearch retorna a **primeira** mensagem que encontrar com ID 1576555, independente do grupo.

---

## ✅ Solução Implementada

### 1. Frontend: Enviar group_id na Request

**Arquivo**: `frontend/src/pages/TelegramIntelligence.tsx`

```typescript
const handleMessageClick = async (message: TelegramMessage) => {
  const groupId = message.group_info?.group_id;  // ✅ Extrair group_id

  const response = await api.get('/telegram/messages/context', {
    params: {
      index_name: indexName,
      msg_id: messageId,
      group_id: groupId,  // ✅ ENVIAR group_id
      before: contextSize.before,
      after: contextSize.after
    }
  });
};
```

### 2. Backend API: Aceitar group_id como Parâmetro

**Arquivo**: `backend/app/api/v1/telegram.py`

```python
@router.get("/messages/context")
async def get_message_context(
    index_name: str = Query(...),
    msg_id: int = Query(...),
    group_id: Optional[int] = Query(None),  # ✅ NOVO parâmetro
    before: int = Query(10, ge=0, le=50),
    after: int = Query(10, ge=0, le=50),
    server_id: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    result = await service.get_message_context(
        index_name=index_name,
        msg_id=msg_id,
        group_id=group_id,  # ✅ Passar para service
        before=before,
        after=after,
        server_id=server_id
    )
```

### 3. Backend Service: Filtrar por group_id

**Arquivo**: `backend/app/services/telegram_search_service.py`

```python
async def get_message_context(
    self,
    index_name: str,
    msg_id: int,
    group_id: Optional[int] = None,  # ✅ NOVO parâmetro
    before: int = 10,
    after: int = 10,
    server_id: Optional[str] = None
) -> Dict[str, Any]:

    # ✅ Query com filtro de grupo
    query = {
        "bool": {
            "must": [
                {
                    "range": {
                        "id": {
                            "gte": msg_id - before * 2,
                            "lte": msg_id + after * 2
                        }
                    }
                }
            ]
        }
    }

    # ✅ FILTRAR POR GRUPO se fornecido
    if group_id is not None:
        query["bool"]["must"].append({
            "term": {"group_info.group_id": group_id}
        })
        logger.info(f"📍 Filtering by group_id: {group_id}")

    response = await es.search(
        index=index_name,
        body={
            "query": query,
            "size": 500,
            "sort": [{"date": "asc"}]
        }
    )
```

---

## 🎯 Resultado Final

### Antes ❌
```
Clicou: "Alguem com nubank fake??" (Consultas2025)
  ↓
Modal: "Coragem" destacada (SurvivorRPG) ← ERRADO!
```

### Depois ✅
```
Clicou: "Alguem com nubank fake??" (Consultas2025, group_id: 2656776524)
  ↓
Query ES: msg_id=1576555 AND group_id=2656776524
  ↓
Modal: "Alguem com nubank fake??" destacada (Consultas2025) ← CORRETO!
```

---

## 📚 Aprendizados Importantes

### 1. Elasticsearch Index Architecture

**Índices compartilhados exigem filtros adicionais**:
- Quando múltiplos grupos compartilham o mesmo índice
- IDs deixam de ser únicos globalmente
- **Sempre filtrar por group_id + message_id**

### 2. Diferenças entre Sistemas Antigo e Novo

| Aspecto | Sistema Antigo | Sistema Novo (Refatorado) |
|---------|---------------|---------------------------|
| **Índices** | Um por grupo | Único compartilhado (`v2`) |
| **Localização** | Index name = grupo | Campo `group_info` |
| **Unicidade ID** | Por índice | Por grupo (campo) |
| **Filtro necessário** | Apenas msg_id | msg_id + group_id |

### 3. Fonte de Verdade para Índice

**Sempre usar `_index` do hit do Elasticsearch**:

```python
# ✅ CORRETO - Python script
index_name = msg_selecionada['_index']

# ✅ CORRETO - Backend atual
for hit in result['hits']:
    msg['_index'] = hit['_index']  # Nome completo do índice
```

**Nunca confiar apenas em `group_info.group_username`**:
- Pode estar errado em mensagens forwarded
- Use apenas para display/UI
- Para queries, use `group_id` (mais confiável)

### 4. Frontend: Priorização de Dados

```typescript
// Hierarquia de confiabilidade:
const indexName =
  message._index ||                    // 1º: Do ES hit (100% confiável)
  message._actual_group_username ||    // 2º: Extraído do índice
  message.group_info?.group_username   // 3º: Metadata (pode estar errado)
```

### 5. Group Title vs Group Username

**Para exibição no modal**:
```typescript
// Título: do group_info da mensagem (display name)
group_title: message.group_info?.group_title || null

// Username: do índice ES (localização física)
group_username: response.data.group_username  // ex: "v2"
```

**Resultado no UI**:
```
Grupo: Consultas2025 (@v2)
       ↑ título        ↑ índice físico
```

---

## 🔧 Arquivos Modificados

### Backend (3 arquivos)

1. **`backend/app/api/v1/telegram.py`**
   - Adicionado parâmetro `group_id` no endpoint `/messages/context`
   - Adicionado `_index` às mensagens retornadas em buscas

2. **`backend/app/services/telegram_search_service.py`**
   - Adicionado parâmetro `group_id` no método `get_message_context()`
   - Implementado filtro `term: group_info.group_id` na query ES
   - Adicionado logging para debug

3. **`backend/app/schemas/telegram.py`**
   - Adicionado campos `group_title` e `group_username` em `TelegramMessageContextResponse`

### Frontend (1 arquivo)

4. **`frontend/src/pages/TelegramIntelligence.tsx`**
   - Extrai `group_id` da mensagem clicada
   - Envia `group_id` no request de contexto
   - Usa `_index` do ES hit para construir index_name
   - Override de `group_title` com dados da mensagem
   - Logging detalhado para debug

---

## ✅ Checklist de Testes

- [x] Buscar "nubank"
- [x] Clicar na mensagem "Alguem com nubank fake??"
- [x] Verificar mensagem correta destacada no modal
- [x] Verificar título do grupo exibido corretamente
- [x] Logs do backend mostram filtro por `group_id`
- [x] Logs do frontend mostram todas as mensagens do contexto
- [x] Mensagem destacada tem emoji 🎯 no console
- [x] Testar com mensagens de grupos diferentes com mesmo ID

---

## 🚀 Impacto

### Performance
- ✅ Query mais eficiente (filtra por grupo logo na query)
- ✅ Reduz resultados retornados do ES
- ✅ Menos processamento no backend

### Precisão
- ✅ 100% de precisão na seleção de mensagem
- ✅ Contexto sempre do grupo correto
- ✅ Funciona com índices compartilhados

### Manutenibilidade
- ✅ Código alinhado com arquitetura refatorada
- ✅ Compatível com sistema antigo e novo
- ✅ Preparado para futuros índices compartilhados

---

## 📝 Notas de Implementação

### Retrocompatibilidade

O parâmetro `group_id` é **opcional** (`Optional[int]`):

```python
if group_id is not None:  # ✅ Só filtra se fornecido
    query["bool"]["must"].append(...)
```

**Vantagens**:
- Sistema continua funcionando sem `group_id`
- Suporta índices antigos (um por grupo)
- Suporta índices novos (compartilhados)

### Decisões de Design

1. **Por que group_id e não group_username?**
   - `group_id` é numérico e indexado como `long`
   - `group_username` é string e pode mudar
   - `group_id` é mais performático para filtros

2. **Por que extrair `_index` no backend?**
   - É a única fonte 100% confiável
   - Vem direto do Elasticsearch hit
   - Não depende de metadata da mensagem

3. **Por que manter group_title override no frontend?**
   - Backend pode não encontrar título em mensagens forwarded
   - Frontend tem acesso ao `group_info` da mensagem clicada
   - Garante sempre exibir nome do grupo correto

---

**Documentado com ❤️ para ADINT**
