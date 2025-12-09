# 🔌 Múltiplos Elasticsearch - Configuração

Dashboard AI v2.0 suporta conexão com **múltiplos servidores Elasticsearch** configurados via interface web.

---

## 📝 Conceito

Diferente do v1 (que usava um único ES configurado), o v2 permite:

✅ **Cadastrar múltiplos servidores** (produção, dev, staging, etc)
✅ **Alternar entre servidores** dinamicamente
✅ **Conectar ES externos** (não roda ES no Docker)
✅ **Salvar credenciais** por servidor

---

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│              Dashboard AI v2.0 (Backend)                │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │        Elasticsearch Manager                    │   │
│  │  (gerencia múltiplas conexões)                  │   │
│  └─────────────┬───────────────┬──────────────────┘   │
│                │               │                        │
└────────────────┼───────────────┼────────────────────────┘
                 │               │
        ┌────────┴────────┐     ┌┴────────────────┐
        │                 │     │                  │
    ES Produção       ES Dev        ES Staging
 (host:9200)    (host:9201)     (cloud)
```

---

## 🚀 Como Usar

### 1. **Não precisa de ES no Docker**

O `docker-compose.yml` **NÃO** inclui Elasticsearch.

Você usa seus ES externos:
- ES local na porta 9200
- ES remoto na cloud
- Múltiplos ES em diferentes portas

### 2. **Configurar via UI (Futuro)**

Na página **Configurações** do Dashboard:

1. Clique em "Adicionar Servidor"
2. Preencha:
   - Nome: `producao`
   - URL: `http://localhost:9200`
   - Username: `elastic`
   - Password: `senha`
3. Clique em "Testar Conexão"
4. Salvar

### 3. **Acessar ES do Host via Docker**

Se você rodar o backend via Docker e quiser acessar ES do host:

**URL do ES**: `http://host.docker.internal:9200`

O `docker-compose.yml` já está configurado com:
```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Isso permite que containers Docker acessem serviços do host (seu Mac).

---

## 📁 Onde são Salvos?

Os servidores configurados são salvos no **próprio Elasticsearch**, no índice `dashboard_servers`:

```json
{
  "index": "dashboard_servers",
  "document": {
    "name": "producao",
    "url": "http://localhost:9200",
    "username": "elastic",
    "password": "encrypted_password",
    "created_at": "2025-11-05T10:00:00Z",
    "is_active": true
  }
}
```

---

## 🔐 Segurança

**Passwords são criptografados** antes de salvar no ES.

- Usa `JWT_SECRET_KEY` do `.env` como chave de criptografia
- Senhas nunca são expostas na API
- Apenas o backend tem acesso às credenciais

---

## 🌐 Exemplo: Múltiplos ES

Você pode ter:

```
┌─────────────────────────────────────────────────────┐
│ Servidores Cadastrados:                             │
├─────────────────────────────────────────────────────┤
│                                                     │
│ 1. 📍 producao                                      │
│    URL: http://localhost:9200                      │
│    Status: ✅ Conectado                            │
│    Índices: 150                                     │
│                                                     │
│ 2. 📍 desenvolvimento                               │
│    URL: http://localhost:9201                      │
│    Status: ✅ Conectado                            │
│    Índices: 45                                      │
│                                                     │
│ 3. 📍 elastic-cloud                                 │
│    URL: https://xxx.es.cloud:9243                  │
│    Status: ✅ Conectado                            │
│    Índices: 200                                     │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuração Manual (Backend)

Se preferir configurar via código:

**backend/app/core/config.py:**
```python
# Opcional: ES padrão via .env
ES_URL: Optional[str] = "http://localhost:9200"
ES_USERNAME: Optional[str] = "elastic"
ES_PASSWORD: Optional[str] = "changeme"
```

**backend/.env:**
```bash
# Opcional: Servidor ES padrão
ES_URL=http://localhost:9200
ES_USERNAME=elastic
ES_PASSWORD=changeme

# OU deixar vazio e configurar via UI
ES_URL=
ES_USERNAME=
ES_PASSWORD=
```

---

## 🔄 Migração do v1

No v1, você configurava ES assim:

**v1 (config/es_servers/):**
```
config/es_servers/
├── producao.json
└── dev.json
```

**v2 (Elasticsearch index: dashboard_servers):**
```json
GET dashboard_servers/_search
{
  "hits": [
    {"_source": {"name": "producao", "url": "..."}},
    {"_source": {"name": "dev", "url": "..."}}
  ]
}
```

Para migrar:
1. Leia seus arquivos JSON do v1
2. Cadastre via API do v2:
   ```bash
   curl -X POST http://localhost:8000/api/v1/servers \
     -H "Content-Type: application/json" \
     -d @producao.json
   ```

---

## 🧪 Teste de Conexão

**API Endpoint:**
```bash
POST /api/v1/servers/test
{
  "url": "http://localhost:9200",
  "username": "elastic",
  "password": "changeme"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Conexão estabelecida com sucesso",
  "cluster_info": {
    "name": "docker-cluster",
    "version": "8.12.0",
    "cluster_name": "docker-cluster"
  }
}
```

---

## 📊 Status dos Servidores

Dashboard mostra status em tempo real:

```
┌──────────────────────────────────────────────────┐
│ Servidor: producao                               │
│ ✅ Conectado                                     │
│ 📊 Índices: 150                                  │
│ 💾 Tamanho: 45.2 GB                              │
│ 🔥 Nodes: 3                                      │
│ ⚡ Shards: 450                                    │
└──────────────────────────────────────────────────┘
```

---

## ❓ FAQ

### P: Preciso rodar Elasticsearch no Docker?

**R:** Não! Use seu ES existente. O projeto se conecta a ES externos.

### P: Posso usar ES na nuvem (Elastic Cloud)?

**R:** Sim! Basta cadastrar a URL da cloud com credenciais.

### P: Como o Docker acessa meu ES local?

**R:** Via `host.docker.internal:9200` que aponta para o host (seu Mac).

### P: Posso ter ES em diferentes redes?

**R:** Sim! Desde que o backend consiga acessar via rede.

### P: As senhas são seguras?

**R:** Sim, são criptografadas com JWT_SECRET_KEY antes de salvar.

---

## 🎯 Resumo

✅ **Sem ES no Docker** - Usa seus ES externos
✅ **Múltiplos servidores** - Cadastre quantos quiser
✅ **Configuração via UI** - Interface amigável
✅ **Senhas seguras** - Criptografadas
✅ **Teste de conexão** - Valida antes de salvar
✅ **Status em tempo real** - Monitora conectividade

---

**Dashboard AI v2.0** | Suporte a Múltiplos Elasticsearch 🚀
