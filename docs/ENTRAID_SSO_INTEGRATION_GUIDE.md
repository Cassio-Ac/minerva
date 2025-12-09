# 🔐 Guia Completo de Integração com Microsoft Entra ID (Azure AD)

## 📋 Índice

1. [Visão Geral](#visão-geral)
2. [Responsabilidades](#responsabilidades)
3. [Pré-requisitos](#pré-requisitos)
4. [Parte 1: Configuração no Azure (Empresa Parceira)](#parte-1-configuração-no-azure)
5. [Parte 2: Configuração na Plataforma (Nós)](#parte-2-configuração-na-plataforma)
6. [Parte 3: Testando a Integração](#parte-3-testando-a-integração)
7. [Troubleshooting](#troubleshooting)
8. [Segurança e Boas Práticas](#segurança-e-boas-práticas)
9. [FAQ](#faq)

---

## 🎯 Visão Geral

Este documento explica como integrar a autenticação da plataforma com o **Microsoft Entra ID** (antigo Azure Active Directory) da empresa parceira.

### O que é Microsoft Entra ID?

Microsoft Entra ID é o serviço de gerenciamento de identidade e acesso da Microsoft. Permite que empresas:
- Gerenciem usuários centralmente
- Controlem acesso a aplicações
- Implementem Single Sign-On (SSO)
- Apliquem políticas de segurança (MFA, acesso condicional)

### Como Funciona o SSO com OAuth2/OIDC?

```
┌─────────────┐                 ┌──────────────────┐                 ┌────────────────┐
│   Usuário   │                 │   Entra ID       │                 │  Plataforma    │
│  (Browser)  │                 │  (Azure AD)      │                 │  (Backend)     │
└──────┬──────┘                 └────────┬─────────┘                 └────────┬───────┘
       │                                 │                                    │
       │ 1. Clicar "Login com Microsoft"│                                    │
       │────────────────────────────────────────────────────────────────────>│
       │                                 │                                    │
       │ 2. Redirecionar para Entra ID   │                                    │
       │<────────────────────────────────────────────────────────────────────│
       │                                 │                                    │
       │ 3. Fazer login (email/senha + MFA)                                  │
       │────────────────────────────────>│                                    │
       │                                 │                                    │
       │ 4. Autorizar aplicação          │                                    │
       │────────────────────────────────>│                                    │
       │                                 │                                    │
       │ 5. Redirecionar com code        │                                    │
       │<────────────────────────────────│                                    │
       │                                 │                                    │
       │ 6. Enviar code para plataforma  │                                    │
       │────────────────────────────────────────────────────────────────────>│
       │                                 │                                    │
       │                                 │ 7. Trocar code por token           │
       │                                 │<───────────────────────────────────│
       │                                 │                                    │
       │                                 │ 8. Retornar access_token + id_token│
       │                                 │────────────────────────────────────>│
       │                                 │                                    │
       │                                 │ 9. Buscar dados do usuário         │
       │                                 │<───────────────────────────────────│
       │                                 │                                    │
       │                                 │ 10. Retornar email, nome, etc      │
       │                                 │────────────────────────────────────>│
       │                                 │                                    │
       │ 11. Login bem-sucedido + JWT    │                                    │
       │<────────────────────────────────────────────────────────────────────│
       │                                 │                                    │
```

---

## 🤝 Responsabilidades

### 👥 Empresa Parceira (Vocês)

- ✅ Ter uma conta Azure com Entra ID configurado
- ✅ Registrar a aplicação no portal Azure
- ✅ Gerar e compartilhar credenciais (Client ID, Client Secret, Tenant ID)
- ✅ Configurar permissões API (User.Read)
- ✅ Adicionar Redirect URI fornecido por nós
- ✅ Gerenciar usuários que podem acessar a plataforma

### 🔧 Nossa Equipe (Nós)

- ✅ Configurar SSO provider na plataforma
- ✅ Implementar fluxo OAuth2/OIDC
- ✅ Implementar auto-provisioning de usuários
- ✅ Fornecer Redirect URI
- ✅ Testar integração
- ✅ Suporte técnico pós-integração

---

## 📦 Pré-requisitos

### Empresa Parceira Precisa Ter:

1. **Conta Azure** com Microsoft Entra ID
   - Pode ser conta gratuita, empresarial ou educacional
   - Necessário permissões de **Application Administrator** ou **Global Administrator**

2. **Usuários no Entra ID**
   - Usuários que acessarão a plataforma devem estar cadastrados no Entra ID
   - Podem ser usuários locais ou sincronizados do Active Directory local

3. **Acesso ao Portal Azure**
   - URL: https://portal.azure.com

### Nossa Plataforma Precisa Ter:

1. **Endpoint público acessível**
   - Exemplo: `https://dashboard.empresa.com`
   - Ou `http://localhost:8000` para desenvolvimento

2. **Certificado SSL válido** (produção)
   - HTTPS obrigatório em produção
   - HTTP permitido apenas em desenvolvimento

---

## 🔧 Parte 1: Configuração no Azure (Empresa Parceira)

### Passo 1: Acessar o Portal Azure

1. Acesse https://portal.azure.com
2. Faça login com conta administrativa
3. No menu lateral, busque por **"Microsoft Entra ID"** ou **"Azure Active Directory"**

### Passo 2: Registrar Nova Aplicação

1. No Entra ID, clique em **"App registrations"** (Registros de aplicativo)
2. Clique em **"+ New registration"** (+ Novo registro)
3. Preencha o formulário:

```
Nome: Dashboard AI - [Nome da Empresa]
Tipos de conta com suporte:
  ☑ Contas somente neste diretório organizacional (Locatário único)
Redirect URI (opcional):
  Tipo: Web
  URL: [FORNECIDO POR NÓS - Exemplo: http://localhost:8000/api/v1/auth/sso/callback/entra_id]
```

4. Clique em **"Register"** (Registrar)

### Passo 3: Anotar Credenciais Importantes

Após o registro, você verá a tela **"Overview"** (Visão geral). Anote:

1. **Application (client) ID**
   - UUID único da aplicação
   - Exemplo: `12345678-1234-1234-1234-123456789abc`
   - ⚠️ Compartilhar com nossa equipe

2. **Directory (tenant) ID**
   - UUID do tenant Azure
   - Exemplo: `98765432-4321-4321-4321-cba987654321`
   - ⚠️ Compartilhar com nossa equipe

3. **Object ID**
   - Apenas para referência interna (não compartilhar)

### Passo 4: Gerar Client Secret

1. No menu lateral da aplicação, clique em **"Certificates & secrets"** (Certificados e segredos)
2. Na aba **"Client secrets"**, clique em **"+ New client secret"**
3. Preencha:
   ```
   Description: Dashboard AI Integration
   Expires: 24 months (recomendado) ou Custom
   ```
4. Clique em **"Add"**
5. ⚠️ **IMPORTANTE**: Copie o **Value** (não o Secret ID) IMEDIATAMENTE
   - Exemplo: `abC123~xYz456.789aBc~DeFgHiJkLmN`
   - **Este valor só aparece uma vez!**
   - Se perder, precisará gerar um novo secret
   - ⚠️ Compartilhar com nossa equipe via canal seguro

### Passo 5: Configurar Permissões de API

1. No menu lateral, clique em **"API permissions"** (Permissões de API)
2. Você verá **"Microsoft Graph"** → **"User.Read"** já adicionado (padrão)
3. **Verificar se possui**:
   - ✅ `Microsoft Graph` → `User.Read` (Delegated)
   - ✅ `Microsoft Graph` → `openid` (Delegated)
   - ✅ `Microsoft Graph` → `profile` (Delegated)
   - ✅ `Microsoft Graph` → `email` (Delegated)

4. **Se faltarem permissões**, clique em **"+ Add a permission"**:
   - Selecione **"Microsoft Graph"**
   - Selecione **"Delegated permissions"**
   - Busque e adicione:
     - `openid`
     - `profile`
     - `email`
     - `User.Read`

5. ⚠️ **IMPORTANTE**: Clique em **"Grant admin consent for [Nome da Empresa]"**
   - Isso evita que cada usuário precise autorizar manualmente
   - Necessário permissões de admin

### Passo 6: Adicionar Redirect URI Adicional (Se Necessário)

Se nossa equipe fornecer URLs adicionais (ex: produção + homologação):

1. Vá em **"Authentication"** (Autenticação)
2. Em **"Platform configurations"** → **"Web"**, clique em **"Add URI"**
3. Adicione cada URL fornecida por nós:
   ```
   http://localhost:8000/api/v1/auth/sso/callback/entra_id  (Desenvolvimento)
   https://dashboard-homolog.empresa.com/api/v1/auth/sso/callback/entra_id  (Homologação)
   https://dashboard.empresa.com/api/v1/auth/sso/callback/entra_id  (Produção)
   ```
4. Clique em **"Save"**

### Passo 7: Configurar Token Configuration (Opcional mas Recomendado)

Para incluir claims adicionais no token:

1. Vá em **"Token configuration"** (Configuração de token)
2. Clique em **"+ Add optional claim"**
3. Token type: **ID**
4. Adicione:
   - `email`
   - `family_name`
   - `given_name`
   - `preferred_username`
5. Clique em **"Add"**

### Passo 8: Configurar Usuários (Controle de Acesso)

**Opção A: Todos os usuários do Entra ID podem acessar (padrão)**
- Não precisa fazer nada adicional
- Qualquer usuário do tenant pode fazer login

**Opção B: Apenas usuários/grupos específicos podem acessar**

1. Vá em **"Enterprise applications"** (Aplicativos empresariais)
2. Busque pelo nome da aplicação registrada
3. Clique em **"Properties"** (Propriedades)
4. Ative **"Assignment required?"** → **Yes**
5. Salve
6. Vá em **"Users and groups"**
7. Clique em **"+ Add user/group"**
8. Selecione usuários ou grupos que podem acessar
9. Clique em **"Assign"**

### 📋 Checklist de Informações para Compartilhar

Após concluir os passos acima, compartilhe com nossa equipe:

```yaml
# Credenciais Microsoft Entra ID
Client ID: 12345678-1234-1234-1234-123456789abc
Client Secret: abC123~xYz456.789aBc~DeFgHiJkLmN  # ⚠️ Canal seguro!
Tenant ID: 98765432-4321-4321-4321-cba987654321

# Informações Adicionais
Nome da Aplicação: Dashboard AI - Empresa X
Redirect URIs configuradas:
  - http://localhost:8000/api/v1/auth/sso/callback/entra_id
  - https://dashboard.empresa.com/api/v1/auth/sso/callback/entra_id

# Permissões Concedidas
- openid (Delegated, Admin consent granted)
- profile (Delegated, Admin consent granted)
- email (Delegated, Admin consent granted)
- User.Read (Delegated, Admin consent granted)

# Controle de Acesso
Assignment required: No  # ou "Yes" se restrito
```

---

## ⚙️ Parte 2: Configuração na Plataforma (Nós)

### Passo 1: Criar SSO Provider via API

Usando as credenciais fornecidas pela empresa parceira, executar:

```bash
# 1. Fazer login como admin
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "sua-senha-admin"
  }'

# Resposta:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "token_type": "bearer",
#   ...
# }

# 2. Criar SSO Provider
export ADMIN_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X POST http://localhost:8000/api/v1/sso-providers/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Microsoft Entra ID - Empresa X",
    "provider_type": "entra_id",
    "client_id": "12345678-1234-1234-1234-123456789abc",
    "client_secret": "abC123~xYz456.789aBc~DeFgHiJkLmN",
    "tenant_id": "98765432-4321-4321-4321-cba987654321",
    "redirect_uri": "http://localhost:8000/api/v1/auth/sso/callback/entra_id",
    "scopes": ["openid", "profile", "email", "User.Read"],
    "default_role": "reader",
    "auto_provision": true,
    "is_active": true
  }'
```

**Resposta de sucesso:**
```json
{
  "id": "uuid-do-provider",
  "name": "Microsoft Entra ID - Empresa X",
  "provider_type": "entra_id",
  "client_id": "12345678-1234-1234-1234-123456789abc",
  "tenant_id": "98765432-4321-4321-4321-cba987654321",
  "redirect_uri": "http://localhost:8000/api/v1/auth/sso/callback/entra_id",
  "scopes": ["openid", "profile", "email", "User.Read"],
  "default_role": "reader",
  "auto_provision": true,
  "is_active": true,
  "created_at": "2025-11-13T20:00:00Z",
  "updated_at": "2025-11-13T20:00:00Z",
  "user_count": 0
}
```

### Passo 2: Verificar Provider Criado

```bash
# Listar todos os providers
curl -X GET http://localhost:8000/api/v1/sso-providers/ \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Buscar provider específico
curl -X GET http://localhost:8000/api/v1/sso-providers/{provider_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Passo 3: Atualizar Provider (Se Necessário)

```bash
# Atualizar apenas campos específicos
curl -X PATCH http://localhost:8000/api/v1/sso-providers/{provider_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "default_role": "operator",
    "auto_provision": false
  }'
```

### Passo 4: Configurar Frontend

Adicionar botão de login SSO na página de login:

```typescript
// frontend/src/pages/LoginPage.tsx

import { api } from '@services/api';

const LoginPage = () => {
  const handleSSOLogin = async (providerType: string) => {
    try {
      // 1. Buscar providers disponíveis
      const providers = await api.listSSOProviders(); // Endpoint público

      const provider = providers.find(p =>
        p.provider_type === providerType && p.is_active
      );

      if (!provider) {
        alert('Provider SSO não encontrado ou inativo');
        return;
      }

      // 2. Gerar state e nonce (CSRF protection)
      const state = generateRandomString(32);
      const nonce = generateRandomString(32);

      // 3. Salvar state no sessionStorage
      sessionStorage.setItem('oauth_state', state);
      sessionStorage.setItem('oauth_nonce', nonce);

      // 4. Redirecionar para Entra ID
      const authUrl = buildAuthUrl(provider, state, nonce);
      window.location.href = authUrl;

    } catch (error) {
      console.error('Erro ao iniciar SSO:', error);
      alert('Erro ao iniciar login SSO');
    }
  };

  const buildAuthUrl = (provider, state, nonce) => {
    const baseUrl = `https://login.microsoftonline.com/${provider.tenant_id}/oauth2/v2.0/authorize`;
    const params = new URLSearchParams({
      client_id: provider.client_id,
      response_type: 'code',
      redirect_uri: provider.redirect_uri,
      response_mode: 'query',
      scope: provider.scopes.join(' '),
      state: state,
      nonce: nonce,
      prompt: 'select_account',
    });
    return `${baseUrl}?${params}`;
  };

  return (
    <div className="login-page">
      {/* Login tradicional */}
      <form onSubmit={handleLogin}>
        {/* ... */}
      </form>

      {/* Divisor */}
      <div className="divider">ou</div>

      {/* Login SSO */}
      <button
        onClick={() => handleSSOLogin('entra_id')}
        className="sso-button microsoft"
      >
        <MicrosoftIcon />
        Entrar com Microsoft
      </button>
    </div>
  );
};
```

### Passo 5: Implementar Callback Handler

```python
# backend/app/api/v1/auth.py (já implementado)

@router.get("/sso/callback/{provider_type}")
async def sso_callback(
    provider_type: str,
    code: str,
    state: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Callback do OAuth2 SSO

    1. Valida state (CSRF protection)
    2. Troca code por access_token
    3. Busca informações do usuário
    4. Cria ou atualiza usuário local (auto-provisioning)
    5. Retorna JWT token
    """
    # 1. Buscar provider
    result = await db.execute(
        select(SSOProvider).where(
            SSOProvider.provider_type == provider_type,
            SSOProvider.is_active == True
        )
    )
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(404, "SSO Provider not found")

    # 2. Trocar code por token
    sso_service = get_sso_auth_service(provider)

    token_response = await sso_service.exchange_code_for_token(
        code=code,
        redirect_uri=provider.redirect_uri
    )

    access_token = token_response["access_token"]

    # 3. Buscar informações do usuário
    user_info = await sso_service.get_user_info(access_token)

    # 4. Auto-provisioning ou atualização de usuário
    user = await sso_service.provision_or_update_user(
        db=db,
        user_info=user_info,
        check_ad_status=True  # Verifica se conta está ativa no AD
    )

    # 5. Gerar JWT token
    jwt_token = create_access_token(
        data={"sub": str(user.id), "username": user.username, "role": user.role}
    )

    return {
        "access_token": jwt_token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "full_name": user.full_name,
        }
    }
```

---

## 🧪 Parte 3: Testando a Integração

### Teste 1: Verificar Provider Configurado

```bash
curl -X GET http://localhost:8000/api/v1/sso-providers/ \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Deve retornar:**
- ✅ Provider com `is_active: true`
- ✅ Client ID correto
- ✅ Tenant ID correto
- ✅ Scopes corretas

### Teste 2: Fluxo Completo de Login

1. **Acessar página de login**
   - http://localhost:3000/login

2. **Clicar em "Entrar com Microsoft"**
   - Deve redirecionar para `login.microsoftonline.com`

3. **Fazer login no Microsoft**
   - Usar email corporativo (@empresa.com)
   - Digitar senha
   - Completar MFA se habilitado

4. **Autorizar aplicação (se primeira vez)**
   - Aceitar permissões solicitadas
   - (Se admin consent foi dado, este passo é pulado)

5. **Redirecionar de volta para plataforma**
   - Deve voltar para `/api/v1/auth/sso/callback/entra_id?code=...&state=...`
   - Deve processar code
   - Deve criar/atualizar usuário
   - Deve retornar JWT token
   - Deve redirecionar para dashboard

6. **Verificar usuário criado**
   ```bash
   curl -X GET http://localhost:8000/api/v1/sso-providers/{provider_id}/users \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

**Deve mostrar:**
```json
[
  {
    "id": "uuid-do-usuario",
    "username": "joao.silva",
    "email": "joao.silva@empresa.com",
    "sso_email": "joao.silva@empresa.com",
    "external_id": "azure-object-id",
    "role": "reader",
    "is_active": true,
    "ad_account_enabled": true,
    "sync_status": "synced",
    "last_sso_login": "2025-11-13T20:15:00Z",
    "last_ad_sync": "2025-11-13T20:15:00Z",
    "created_at": "2025-11-13T20:15:00Z"
  }
]
```

### Teste 3: Verificar Auto-Provisioning

**Cenário**: Usuário nunca logou na plataforma antes

1. Fazer login via SSO
2. Sistema deve:
   - ✅ Criar novo usuário automaticamente
   - ✅ Atribuir role padrão (`reader`)
   - ✅ Gerar username a partir do email
   - ✅ Sincronizar foto do perfil (se disponível)
   - ✅ Permitir acesso imediato

3. Verificar logs:
   ```bash
   docker compose logs backend | grep "Auto-provisioned user"
   ```

### Teste 4: Verificar Sincronização com AD

**Cenário**: Usuário foi desativado no Azure

1. Desativar usuário no portal Azure (ou deletar)
2. Tentar fazer login via SSO
3. Sistema deve:
   - ✅ Verificar status no AD antes de permitir login
   - ✅ Negar acesso se conta desativada
   - ✅ Mostrar mensagem: "Sua conta foi desativada no sistema corporativo"

4. Executar sincronização manual:
   ```bash
   curl -X POST http://localhost:8000/api/v1/sso-providers/{provider_id}/sync \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

**Resposta esperada:**
```json
{
  "total_checked": 10,
  "deactivated": 1,
  "activated": 0,
  "errors": 0,
  "details": [
    {
      "user_id": "uuid",
      "email": "joao.silva@empresa.com",
      "action": "deactivated",
      "reason": "Account disabled in Azure AD"
    }
  ]
}
```

### Teste 5: Verificar Renovação de Token

**Cenário**: Usuário já logado faz logout e login novamente

1. Fazer login via SSO
2. Fazer logout
3. Fazer login novamente via SSO
4. Sistema deve:
   - ✅ Reconhecer usuário existente
   - ✅ Atualizar `last_sso_login`
   - ✅ Atualizar `last_ad_sync`
   - ✅ Verificar se conta ainda está ativa
   - ✅ Emitir novo JWT token

---

## 🐛 Troubleshooting

### Erro: "redirect_uri mismatch"

**Causa**: Redirect URI configurada no Azure não corresponde à enviada na requisição

**Solução**:
1. Verificar no Azure Portal → App registration → Authentication
2. Garantir que a URI está EXATAMENTE igual (case-sensitive)
3. Verificar protocolo (http vs https)
4. Verificar porta (se aplicável)

```
❌ Errado: http://localhost:8000/api/v1/auth/sso/callback
✅ Correto: http://localhost:8000/api/v1/auth/sso/callback/entra_id
```

### Erro: "invalid_client"

**Causa**: Client ID ou Client Secret incorretos

**Solução**:
1. Verificar Client ID no portal Azure
2. Regenerar Client Secret se necessário
3. Atualizar provider na plataforma com novas credenciais

```bash
curl -X PATCH http://localhost:8000/api/v1/sso-providers/{provider_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "novo-client-id",
    "client_secret": "novo-client-secret"
  }'
```

### Erro: "AADSTS50020: User account from identity provider does not exist in tenant"

**Causa**: Usuário não pertence ao tenant configurado

**Solução**:
1. Verificar se o tenant ID está correto
2. Verificar se o usuário é um guest account
3. Convidar usuário para o tenant se necessário

### Erro: "AADSTS65001: The user or administrator has not consented"

**Causa**: Admin consent não foi dado para as permissões

**Solução**:
1. No Azure Portal → App registration → API permissions
2. Clicar em "Grant admin consent for [Tenant Name]"
3. Confirmar como admin

### Erro: "Auto-provisioning está desativado"

**Causa**: `auto_provision` está `false` no provider

**Solução**:

**Opção A**: Ativar auto-provisioning
```bash
curl -X PATCH http://localhost:8000/api/v1/sso-providers/{provider_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auto_provision": true
  }'
```

**Opção B**: Criar usuário manualmente antes do login SSO
```bash
curl -X POST http://localhost:8000/api/v1/users/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "joao.silva",
    "email": "joao.silva@empresa.com",
    "full_name": "João Silva",
    "role": "operator",
    "sso_provider_id": "{provider_id}",
    "external_id": "{azure_object_id}"
  }'
```

### Erro: "Sua conta foi desativada no sistema corporativo"

**Causa**: Conta foi desativada no Azure AD

**Solução**:
1. Verificar no portal Azure se usuário está ativo
2. Reativar usuário no Azure
3. Tentar login novamente

### Logs Úteis para Debug

```bash
# Logs do backend
docker compose logs backend --tail=100 --follow | grep -E "SSO|OAuth|Entra"

# Logs de criação de usuário
docker compose logs backend | grep "Auto-provisioned user"

# Logs de sincronização AD
docker compose logs backend | grep "AD sync"

# Logs de erros
docker compose logs backend | grep -E "ERROR|Exception"
```

---

## 🔒 Segurança e Boas Práticas

### 1. Proteção de Secrets

**❌ NÃO faça:**
```python
# Hardcoded secrets no código
CLIENT_SECRET = "abC123~xYz456.789aBc~DeFgHiJkLmN"
```

**✅ FAÇA:**
```python
# Secrets criptografados no banco de dados
provider.set_client_secret(client_secret)  # Criptografa automaticamente
```

**Nossa implementação:**
- Client secrets são criptografados com **Fernet** (AES-128)
- Key derivation com **PBKDF2HMAC** (100k iterations)
- Secrets nunca aparecem em logs ou responses HTTP
- Apenas descriptografados internamente quando necessário

### 2. State Parameter (CSRF Protection)

**Sempre validar o state parameter:**

```typescript
// Frontend: Gerar state antes de redirecionar
const state = crypto.randomBytes(32).toString('hex');
sessionStorage.setItem('oauth_state', state);

// Frontend: Validar state no callback
const savedState = sessionStorage.getItem('oauth_state');
if (state !== savedState) {
  throw new Error('Invalid state - possible CSRF attack');
}
sessionStorage.removeItem('oauth_state');
```

### 3. HTTPS Obrigatório em Produção

```yaml
# ❌ Produção
redirect_uri: http://dashboard.empresa.com/...  # INSEGURO!

# ✅ Produção
redirect_uri: https://dashboard.empresa.com/...  # SEGURO

# ✅ Desenvolvimento
redirect_uri: http://localhost:8000/...  # OK apenas em dev
```

### 4. Expiração de Tokens

**Client Secrets:**
- Configurar expiração no Azure (12-24 meses recomendado)
- Configurar alertas 30 dias antes da expiração
- Renovar secrets de forma planejada

**JWT Tokens:**
```python
# Nossa configuração
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutos

# Usuários SSO podem fazer re-login sem digitar senha
# (SSO session no Azure dura horas/dias)
```

### 5. Auditoria e Logging

**Eventos logados:**
- ✅ Criação de provider SSO (quem, quando)
- ✅ Login via SSO bem-sucedido (usuário, IP, timestamp)
- ✅ Falha de login SSO (motivo)
- ✅ Auto-provisioning de novo usuário
- ✅ Sincronização com AD (resultados)
- ✅ Desativação de conta (motivo)

**Logs NÃO contêm:**
- ❌ Client secrets
- ❌ Access tokens
- ❌ Senhas
- ❌ Outros dados sensíveis

### 6. Permissões Mínimas Necessárias

**Scopes recomendadas:**
```json
[
  "openid",      // Identificação básica
  "profile",     // Nome, sobrenome
  "email",       // Email do usuário
  "User.Read"    // Ler perfil completo do Microsoft Graph
]
```

**❌ NÃO pedir permissões desnecessárias:**
- `User.ReadWrite.All` (alterar todos os usuários)
- `Directory.Read.All` (ler todo o diretório)
- `Mail.Read` (ler emails do usuário)

### 7. Controle de Acesso

**Opção A: Aberto (todos do tenant podem acessar)**
- Bom para ambientes corporativos pequenos
- Menos overhead administrativo

**Opção B: Restrito (apenas usuários/grupos específicos)**
- Recomendado para produção
- Configurar no Azure: Properties → Assignment required → Yes
- Criar grupo "Dashboard AI Users" e adicionar membros

### 8. Monitoramento

**Verificações periódicas:**
- [ ] Certificar que client secrets não expiraram
- [ ] Auditar usuários SSO ativos
- [ ] Verificar logs de tentativas de login falhadas
- [ ] Sincronizar status com AD regularmente
- [ ] Revisar permissões concedidas

**Sincronização automática (recomendado):**
```python
# Cron job diário para sincronizar usuários com AD
# Verifica se contas foram desativadas/deletadas no Azure
0 2 * * * curl -X POST http://localhost:8000/api/v1/sso-providers/{provider_id}/sync \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## ❓ FAQ

### 1. Usuários precisam criar conta separada na plataforma?

**Não!** Com auto-provisioning habilitado:
- Usuário faz login pela primeira vez via Microsoft
- Sistema cria conta automaticamente
- Usuário já tem acesso imediato

### 2. O que acontece se um usuário for desativado no Azure?

Quando sincronização é executada:
- Usuário é marcado como `is_active: false` na plataforma
- Não consegue mais fazer login
- Dados históricos são preservados

### 3. Posso ter múltiplos providers SSO?

**Sim!** Você pode configurar:
- Microsoft Entra ID (Azure AD)
- Google Workspace
- Okta
- Outros provedores OAuth2/OIDC

Cada provider é independente.

### 4. Como gerenciar roles de usuários SSO?

**Opção A: Role padrão** (mais simples)
- Configurar `default_role: "reader"` no provider
- Todos novos usuários recebem esta role

**Opção B: Role mapping** (avançado)
- Mapear grupos do Azure AD para roles da plataforma
- Exemplo:
  ```json
  {
    "role_mapping": {
      "Dashboard-Admins": "admin",
      "Dashboard-Operators": "operator",
      "Dashboard-Viewers": "reader"
    }
  }
  ```

**Opção C: Manual** (mais controle)
- Desativar auto-provisioning
- Criar usuários manualmente com role desejada
- Vincular ao provider SSO

### 5. Client secret expirou, o que fazer?

1. **Gerar novo secret no Azure:**
   - Portal Azure → App registration → Certificates & secrets
   - New client secret → Anotar value

2. **Atualizar na plataforma:**
   ```bash
   curl -X PATCH http://localhost:8000/api/v1/sso-providers/{provider_id} \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "client_secret": "novo-secret-aqui"
     }'
   ```

3. **Testar login novamente**

### 6. Posso usar o mesmo App Registration para múltiplos ambientes?

**Não recomendado.** Melhor prática:
- 1 App Registration para Desenvolvimento
- 1 App Registration para Homologação
- 1 App Registration para Produção

Cada um com suas próprias credenciais e redirect URIs.

### 7. Quanto custa usar Microsoft Entra ID?

**Microsoft Entra ID Free** (incluído no Microsoft 365):
- ✅ SSO ilimitado
- ✅ OAuth2/OIDC
- ✅ 50.000 usuários
- ✅ Suficiente para esta integração

**Não há custo adicional** para usar SSO nesta plataforma.

### 8. Como funciona o MFA (autenticação de 2 fatores)?

MFA é configurado **no Azure**, não na plataforma:
- Administrador Azure habilita MFA para usuários/grupos
- Ao fazer login via SSO, Azure solicita segundo fator
- Plataforma não precisa implementar nada
- Funciona automaticamente

### 9. Usuários podem ter login tradicional E SSO?

**Sim**, mas não recomendado:
- Usuários SSO têm `hashed_password: ""` (vazio)
- Não podem fazer login tradicional
- Apenas via Microsoft

Se precisar de ambos, criar 2 contas separadas (não recomendado).

### 10. Como fazer backup/migração de providers SSO?

**Export:**
```bash
curl -X GET http://localhost:8000/api/v1/sso-providers/{provider_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" > provider-backup.json
```

**Import em outro ambiente:**
```bash
# Editar provider-backup.json (remover id, created_at, updated_at)
# Recriar no novo ambiente
curl -X POST http://localhost:8000/api/v1/sso-providers/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @provider-backup.json
```

---

## 📚 Recursos Adicionais

### Documentação Oficial Microsoft

- **Microsoft identity platform**: https://learn.microsoft.com/en-us/azure/active-directory/develop/
- **OAuth 2.0 and OpenID Connect**: https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols
- **Microsoft Graph API**: https://learn.microsoft.com/en-us/graph/overview

### Ferramentas Úteis

- **JWT Debugger**: https://jwt.io
- **OAuth 2.0 Debugger**: https://oauthdebugger.com
- **Microsoft Graph Explorer**: https://developer.microsoft.com/en-us/graph/graph-explorer

### Contato

Para dúvidas técnicas sobre a integração:
- Email: suporte@empresa.com
- Slack: #dashboard-ai-suporte
- Documentação: https://docs.dashboard.empresa.com

---

## 📝 Changelog

| Versão | Data       | Alterações                                   |
|--------|------------|----------------------------------------------|
| 1.0.0  | 2025-11-13 | Versão inicial do documento                  |

---

**Documento gerado por:** Dashboard AI Team
**Última atualização:** 13 de Novembro de 2025
**Versão da plataforma:** 2.0.0
