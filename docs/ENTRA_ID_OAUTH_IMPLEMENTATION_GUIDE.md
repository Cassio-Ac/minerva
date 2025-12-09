# Guia de Implementação: Autenticação com Microsoft Entra ID (Azure AD)

> **Objetivo**: Este documento explica como implementar autenticação OAuth2/OIDC usando Microsoft Entra ID (anteriormente Azure AD) em qualquer plataforma web. É um guia técnico agnóstico para desenvolvedores que precisam permitir que clientes corporativos façam login usando suas contas Microsoft.

---

## Índice

1. [Visão Geral](#visão-geral)
2. [Pré-requisitos](#pré-requisitos)
3. [Fluxo de Autenticação](#fluxo-de-autenticação)
4. [Responsabilidades](#responsabilidades)
5. [Configuração no Azure (Cliente)](#configuração-no-azure-cliente)
6. [Implementação Backend (Desenvolvedor)](#implementação-backend-desenvolvedor)
7. [Implementação Frontend (Desenvolvedor)](#implementação-frontend-desenvolvedor)
8. [Segurança](#segurança)
9. [Testes](#testes)
10. [Troubleshooting](#troubleshooting)
11. [Referências](#referências)

---

## Visão Geral

### O que é Microsoft Entra ID?

Microsoft Entra ID (Azure Active Directory) é o serviço de gerenciamento de identidades e acessos da Microsoft. Empresas usam o Entra ID para:

- Centralizar autenticação de funcionários
- Aplicar políticas de segurança (MFA, acesso condicional)
- Gerenciar permissões e grupos
- Integrar aplicações corporativas via SSO (Single Sign-On)

### Por que usar OAuth2/OIDC?

OAuth2 é um protocolo de **autorização** que permite que aplicações acessem recursos em nome do usuário, sem expor credenciais.

OIDC (OpenID Connect) é uma camada de **autenticação** sobre OAuth2, que adiciona informações de identidade do usuário (nome, email, foto).

**Fluxo típico**:
1. Usuário clica em "Entrar com Microsoft" na sua aplicação
2. É redirecionado para login.microsoftonline.com
3. Faz login com credenciais corporativas (email/senha + MFA se configurado)
4. Microsoft redireciona de volta para sua aplicação com um **código de autorização**
5. Sua aplicação troca o código por um **access token** e **ID token**
6. Usa o access token para buscar informações do usuário (Microsoft Graph API)
7. Cria sessão do usuário na sua aplicação

---

## Pré-requisitos

### Cliente (Empresa que possui Entra ID)
- ✅ Tenant do Microsoft Entra ID (Azure AD)
- ✅ Permissões de administrador para registrar aplicações
- ✅ Usuários no diretório que precisam acessar a aplicação

### Desenvolvedor (Você)
- ✅ Aplicação web com backend capaz de fazer chamadas HTTP
- ✅ HTTPS configurado (obrigatório para produção)
- ✅ Capacidade de armazenar secrets de forma segura
- ✅ Endpoint de callback acessível publicamente

---

## Fluxo de Autenticação

### Diagrama: Authorization Code Flow

```
┌─────────┐                                       ┌──────────────┐
│ Usuário │                                       │ Entra ID     │
│ Browser │                                       │ (Microsoft)  │
└────┬────┘                                       └──────┬───────┘
     │                                                   │
     │  1. Clica "Entrar com Microsoft"                 │
     ├──────────────────────────────────────────────────▶
     │                                                   │
     │  2. Redireciona para login.microsoftonline.com   │
     │     com client_id, redirect_uri, scope, state    │
     ◀──────────────────────────────────────────────────┤
     │                                                   │
     │  3. Usuário faz login (email/senha + MFA)        │
     ├──────────────────────────────────────────────────▶
     │                                                   │
     │  4. Usuário consente permissões (se necessário)  │
     ├──────────────────────────────────────────────────▶
     │                                                   │
     │  5. Redireciona para redirect_uri com code       │
     │     https://app.com/callback?code=xxx&state=yyy  │
     ◀──────────────────────────────────────────────────┤
     │                                                   │
     ▼                                                   │
┌─────────────┐                                         │
│ Seu Backend │                                         │
└──────┬──────┘                                         │
       │  6. Troca code por access_token                │
       ├────────────────────────────────────────────────▶
       │    POST /oauth2/v2.0/token                     │
       │    { code, client_id, client_secret, ... }     │
       │                                                 │
       │  7. Retorna tokens                             │
       │     { access_token, id_token, refresh_token }  │
       ◀────────────────────────────────────────────────┤
       │                                                 │
       │  8. Usa access_token para buscar perfil        │
       ├────────────────────────────────────────────────▶
       │    GET https://graph.microsoft.com/v1.0/me     │
       │                                                 │
       │  9. Retorna dados do usuário                   │
       │     { id, displayName, mail, ... }             │
       ◀────────────────────────────────────────────────┤
       │                                                 │
       │  10. Cria sessão local (JWT, cookie, etc)      │
       ├────────────────────────────────────────────────▶
       │                                                 │
     ┌─┴─┐
     │ ✓ │  Usuário autenticado!
     └───┘
```

---

## Responsabilidades

### O que o CLIENTE precisa fazer (Empresa com Entra ID)

| Tarefa | Descrição | Onde fazer |
|--------|-----------|------------|
| **Registrar aplicação** | Criar App Registration no Azure Portal | [Azure Portal](https://portal.azure.com) → Azure Active Directory → App registrations |
| **Fornecer credenciais** | Compartilhar Client ID, Tenant ID e Client Secret | Copiar do Azure Portal e enviar de forma segura |
| **Configurar redirect URI** | Adicionar URL de callback na lista de URIs permitidas | App Registration → Authentication → Redirect URIs |
| **Conceder permissões** | Aprovar permissões (openid, profile, email, User.Read) | App Registration → API permissions → Grant admin consent |
| **Configurar usuários** | Definir quem pode acessar (todos ou grupos específicos) | Enterprise Applications → Users and groups |

### O que o DESENVOLVEDOR precisa fazer (Você)

| Tarefa | Descrição |
|--------|-----------|
| **Armazenar credenciais** | Salvar client_id, client_secret, tenant_id de forma criptografada |
| **Implementar /login** | Endpoint que redireciona para Entra ID com parâmetros OAuth2 |
| **Implementar /callback** | Endpoint que recebe o código de autorização |
| **Trocar código por token** | Fazer POST para /oauth2/v2.0/token |
| **Validar ID token** | Verificar assinatura JWT, issuer, audience, expiration |
| **Buscar perfil do usuário** | Chamar Microsoft Graph API com access_token |
| **Auto-provisionar usuário** | Criar usuário local se não existir |
| **Gerenciar sessão** | Emitir JWT/cookie para manter usuário logado |
| **Implementar logout** | Invalidar sessão local e redirecionar para logout do Entra ID |

---

## Configuração no Azure (Cliente)

### Passo 1: Registrar Aplicação

1. Acesse [Azure Portal](https://portal.azure.com)
2. Navegue para **Azure Active Directory** → **App registrations**
3. Clique em **New registration**
4. Preencha:
   - **Name**: Nome da sua aplicação (ex: "Plataforma XYZ - SSO")
   - **Supported account types**: "Accounts in this organizational directory only"
   - **Redirect URI**:
     - Type: **Web**
     - URL: `https://sua-aplicacao.com/auth/callback` (substitua pelo seu domínio)

### Passo 2: Obter Credenciais

Após criar a aplicação:

**Client ID (Application ID)**:
- Na página **Overview** do App Registration
- Exemplo: `12345678-1234-1234-1234-123456789abc`

**Tenant ID (Directory ID)**:
- Na página **Overview** do App Registration
- Exemplo: `98765432-4321-4321-4321-cba987654321`

**Client Secret**:
1. Vá em **Certificates & secrets**
2. Clique em **New client secret**
3. Defina descrição (ex: "Prod Secret") e validade (recomendado: 24 meses)
4. **COPIE O VALOR IMEDIATAMENTE** - ele só aparece uma vez!
5. Exemplo: `abC123~xYz456.789aBc~DeFgHiJkLmN`

⚠️ **IMPORTANTE**: Compartilhe essas credenciais de forma segura (nunca por email ou chat desprotegido). Use ferramentas como:
- Azure Key Vault
- 1Password / LastPass (compartilhamento seguro)
- PGP/GPG encryption
- Reunião presencial ou ligação segura

### Passo 3: Configurar Permissões (API Permissions)

1. Vá em **API permissions**
2. Clique em **Add a permission** → **Microsoft Graph** → **Delegated permissions**
3. Adicione:
   - ✅ `openid` - Necessário para OIDC
   - ✅ `profile` - Informações básicas (nome, foto)
   - ✅ `email` - Endereço de email
   - ✅ `User.Read` - Ler perfil do usuário
4. Clique em **Grant admin consent for [Organização]** (requer admin)

### Passo 4: Configurar Redirect URIs

1. Vá em **Authentication**
2. Em **Platform configurations** → **Web**
3. Adicione todas as URLs de callback necessárias:
   - Produção: `https://app.com/auth/callback`
   - Staging: `https://staging.app.com/auth/callback`
   - Desenvolvimento: `http://localhost:3000/auth/callback` (opcional)
4. Em **Implicit grant and hybrid flows**, deixe DESMARCADO (usaremos Authorization Code Flow)

### Passo 5: Configurar Acesso de Usuários

**Opção A: Todos os usuários do diretório**
- Por padrão, todos os usuários do tenant podem acessar

**Opção B: Apenas usuários/grupos específicos**
1. Vá em **Azure Active Directory** → **Enterprise applications**
2. Encontre sua aplicação
3. Vá em **Properties** → Defina **User assignment required** = **Yes**
4. Vá em **Users and groups** → Adicione usuários ou grupos específicos

### Passo 6: Compartilhar Informações com Desenvolvedor

Envie de forma segura:

```json
{
  "client_id": "12345678-1234-1234-1234-123456789abc",
  "tenant_id": "98765432-4321-4321-4321-cba987654321",
  "client_secret": "abC123~xYz456.789aBc~DeFgHiJkLmN",
  "redirect_uri": "https://sua-aplicacao.com/auth/callback",
  "scopes": ["openid", "profile", "email", "User.Read"]
}
```

---

## Implementação Backend (Desenvolvedor)

### Tecnologias e Bibliotecas Recomendadas

**Node.js**:
- `passport-azure-ad` - Estratégia pronta para Entra ID
- `msal-node` - Microsoft Authentication Library oficial

**Python**:
- `msal` - Microsoft Authentication Library oficial
- `authlib` - OAuth2/OIDC client genérico

**.NET**:
- `Microsoft.Identity.Web` - Biblioteca oficial da Microsoft

**Java**:
- `msal4j` - Microsoft Authentication Library para Java

### Exemplo 1: Python (Flask) - Implementação Manual

```python
import requests
import secrets
from flask import Flask, redirect, request, session, jsonify
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

# Configuração (obter do cliente)
TENANT_ID = "98765432-4321-4321-4321-cba987654321"
CLIENT_ID = "12345678-1234-1234-1234-123456789abc"
CLIENT_SECRET = "abC123~xYz456.789aBc~DeFgHiJkLmN"
REDIRECT_URI = "https://sua-aplicacao.com/auth/callback"
SCOPES = ["openid", "profile", "email", "User.Read"]

# Endpoints do Entra ID
AUTHORIZE_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"

@app.route('/login')
def login():
    """
    Inicia o fluxo OAuth2 redirecionando para Entra ID
    """
    # Gerar state aleatório para proteção CSRF
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    # Gerar nonce para validação do ID token
    nonce = secrets.token_urlsafe(32)
    session['oauth_nonce'] = nonce

    # Construir URL de autorização
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': ' '.join(SCOPES),
        'state': state,
        'nonce': nonce,
        'prompt': 'select_account',  # Força seleção de conta
        'response_mode': 'query'
    }

    auth_url = f"{AUTHORIZE_URL}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/auth/callback')
def callback():
    """
    Recebe o código de autorização e troca por tokens
    """
    # 1. Validar state (proteção CSRF)
    received_state = request.args.get('state')
    expected_state = session.pop('oauth_state', None)

    if not received_state or received_state != expected_state:
        return jsonify({'error': 'Invalid state parameter'}), 400

    # 2. Verificar se há erro na resposta
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        return jsonify({
            'error': error,
            'description': error_description
        }), 400

    # 3. Obter código de autorização
    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'No authorization code received'}), 400

    # 4. Trocar código por tokens
    token_data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
        'scope': ' '.join(SCOPES)
    }

    try:
        token_response = requests.post(TOKEN_URL, data=token_data, timeout=10)
        token_response.raise_for_status()
        tokens = token_response.json()
    except requests.RequestException as e:
        return jsonify({'error': f'Token exchange failed: {str(e)}'}), 500

    access_token = tokens.get('access_token')
    id_token = tokens.get('id_token')
    refresh_token = tokens.get('refresh_token')

    # 5. Buscar informações do usuário (Microsoft Graph)
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        user_response = requests.get(GRAPH_ME_URL, headers=headers, timeout=10)
        user_response.raise_for_status()
        user_info = user_response.json()
    except requests.RequestException as e:
        return jsonify({'error': f'Failed to fetch user info: {str(e)}'}), 500

    # 6. Extrair dados do usuário
    user_data = {
        'id': user_info.get('id'),  # Azure AD Object ID
        'email': user_info.get('mail') or user_info.get('userPrincipalName'),
        'name': user_info.get('displayName'),
        'first_name': user_info.get('givenName'),
        'last_name': user_info.get('surname'),
        'job_title': user_info.get('jobTitle'),
        'department': user_info.get('department'),
        'office_location': user_info.get('officeLocation'),
    }

    # 7. Auto-provisionar ou atualizar usuário no banco local
    user = create_or_update_user(user_data)

    # 8. Criar sessão local (exemplo simplificado - use JWT em produção)
    session['user_id'] = user['id']
    session['user_email'] = user['email']
    session['user_name'] = user['name']

    # 9. Redirecionar para página principal
    return redirect('/dashboard')

def create_or_update_user(user_data):
    """
    Auto-provisionar usuário na aplicação

    Em produção, você deve:
    - Verificar se o usuário já existe (por email ou Azure AD Object ID)
    - Criar novo registro se não existir
    - Atualizar informações se já existir
    - Atribuir role padrão (ex: 'reader')
    - Registrar timestamp de último login
    """
    # Exemplo simplificado - implementar com seu ORM/banco
    # user = db.users.find_one({'entra_id': user_data['id']})
    # if not user:
    #     user = db.users.insert({
    #         'entra_id': user_data['id'],
    #         'email': user_data['email'],
    #         'name': user_data['name'],
    #         'role': 'reader',
    #         'created_at': datetime.utcnow(),
    #         'auth_provider': 'entra_id'
    #     })
    # else:
    #     db.users.update({'_id': user['_id']}, {
    #         '$set': {
    #             'name': user_data['name'],
    #             'last_login': datetime.utcnow()
    #         }
    #     })

    return user_data  # Retornar usuário criado/atualizado

@app.route('/logout')
def logout():
    """
    Logout: invalida sessão local e redireciona para logout do Entra ID
    """
    # Limpar sessão local
    session.clear()

    # Redirecionar para logout do Entra ID (opcional mas recomendado)
    logout_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/logout"
    post_logout_redirect = "https://sua-aplicacao.com"

    return redirect(f"{logout_url}?post_logout_redirect_uri={post_logout_redirect}")

@app.route('/user')
def get_user():
    """
    Endpoint protegido - retorna dados do usuário logado
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    return jsonify({
        'id': session.get('user_id'),
        'email': session.get('user_email'),
        'name': session.get('user_name')
    })

if __name__ == '__main__':
    # NUNCA use debug=True em produção!
    app.run(debug=True, port=5000)
```

### Exemplo 2: Node.js (Express) - Usando MSAL

```javascript
const express = require('express');
const session = require('express-session');
const msal = require('@azure/msal-node');
const axios = require('axios');

const app = express();

// Configuração da sessão
app.use(session({
  secret: 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // HTTPS obrigatório em produção
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 horas
  }
}));

// Configuração MSAL
const msalConfig = {
  auth: {
    clientId: '12345678-1234-1234-1234-123456789abc',
    authority: 'https://login.microsoftonline.com/98765432-4321-4321-4321-cba987654321',
    clientSecret: 'abC123~xYz456.789aBc~DeFgHiJkLmN'
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return;
        console.log(message);
      },
      piiLoggingEnabled: false,
      logLevel: msal.LogLevel.Verbose
    }
  }
};

const pca = new msal.ConfidentialClientApplication(msalConfig);

const REDIRECT_URI = 'https://sua-aplicacao.com/auth/callback';
const SCOPES = ['openid', 'profile', 'email', 'User.Read'];

// Rota de login
app.get('/login', (req, res) => {
  const authCodeUrlParameters = {
    scopes: SCOPES,
    redirectUri: REDIRECT_URI,
    prompt: 'select_account'
  };

  pca.getAuthCodeUrl(authCodeUrlParameters)
    .then((authUrl) => {
      res.redirect(authUrl);
    })
    .catch((error) => {
      console.error('Error generating auth URL:', error);
      res.status(500).json({ error: 'Failed to generate auth URL' });
    });
});

// Callback
app.get('/auth/callback', async (req, res) => {
  const tokenRequest = {
    code: req.query.code,
    scopes: SCOPES,
    redirectUri: REDIRECT_URI
  };

  try {
    // Trocar código por token
    const response = await pca.acquireTokenByCode(tokenRequest);

    // Buscar informações do usuário
    const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${response.accessToken}` }
    });

    const user = userInfo.data;

    // Criar sessão
    req.session.userId = user.id;
    req.session.userEmail = user.mail || user.userPrincipalName;
    req.session.userName = user.displayName;

    // Auto-provisionar usuário (implementar com seu banco de dados)
    // await createOrUpdateUser(user);

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  const logoutUrl = `https://login.microsoftonline.com/98765432-4321-4321-4321-cba987654321/oauth2/v2.0/logout`;
  req.session.destroy();
  res.redirect(logoutUrl);
});

// Middleware de autenticação
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// Rota protegida
app.get('/user', requireAuth, (req, res) => {
  res.json({
    id: req.session.userId,
    email: req.session.userEmail,
    name: req.session.userName
  });
});

app.listen(3000, () => {
  console.log('Server running on https://sua-aplicacao.com');
});
```

---

## Implementação Frontend (Desenvolvedor)

### Exemplo: React/TypeScript

```typescript
import React, { useState, useEffect } from 'react';

interface User {
  id: string;
  email: string;
  name: string;
}

const LoginPage: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Verificar se já está autenticado
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const response = await fetch('/user', {
        credentials: 'include' // Incluir cookies de sessão
      });

      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLoginWithMicrosoft = () => {
    // Simplesmente redirecionar para o endpoint de login do backend
    // O backend vai iniciar o fluxo OAuth2
    window.location.href = '/login';
  };

  const handleLogout = () => {
    window.location.href = '/logout';
  };

  if (loading) {
    return <div>Carregando...</div>;
  }

  if (user) {
    return (
      <div>
        <h1>Bem-vindo, {user.name}!</h1>
        <p>Email: {user.email}</p>
        <button onClick={handleLogout}>Sair</button>
      </div>
    );
  }

  return (
    <div className="login-container">
      <h1>Entrar na Aplicação</h1>

      <button
        onClick={handleLoginWithMicrosoft}
        className="btn-microsoft"
      >
        <img
          src="/icons/microsoft.svg"
          alt="Microsoft"
          width="20"
          height="20"
        />
        Entrar com Microsoft
      </button>

      <p className="help-text">
        Use sua conta corporativa (@suaempresa.com)
      </p>
    </div>
  );
};

export default LoginPage;
```

### CSS para botão Microsoft (opcional)

```css
.btn-microsoft {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 24px;
  background-color: #2F2F2F;
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 16px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s;
}

.btn-microsoft:hover {
  background-color: #1F1F1F;
}

.btn-microsoft img {
  margin-right: 8px;
}
```

---

## Segurança

### 1. Proteção do Client Secret

❌ **NUNCA**:
- Commitar client_secret no Git
- Expor no frontend (JavaScript)
- Enviar por email ou chat desprotegido
- Logar em arquivos de log
- Armazenar em texto plano

✅ **SEMPRE**:
- Armazenar em variáveis de ambiente (`.env`)
- Usar serviços de secrets (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
- Criptografar no banco de dados se necessário armazenar
- Rotacionar periodicamente (a cada 6-12 meses)
- Revogar imediatamente se comprometido

**Exemplo .env**:
```bash
ENTRA_CLIENT_ID=12345678-1234-1234-1234-123456789abc
ENTRA_TENANT_ID=98765432-4321-4321-4321-cba987654321
ENTRA_CLIENT_SECRET=abC123~xYz456.789aBc~DeFgHiJkLmN
ENTRA_REDIRECT_URI=https://app.com/auth/callback
```

### 2. Validação do State Parameter (CSRF Protection)

O parâmetro `state` protege contra ataques CSRF:

```python
# Ao iniciar login
state = secrets.token_urlsafe(32)  # Gerar aleatório
session['oauth_state'] = state     # Armazenar em sessão

# No callback
received_state = request.args.get('state')
expected_state = session.pop('oauth_state')

if received_state != expected_state:
    raise SecurityError('CSRF attack detected')
```

### 3. Validação do ID Token

O ID token é um JWT assinado pelo Entra ID. Você deve validar:

✅ **Assinatura**: Verificar que foi assinado pelo Entra ID
✅ **Issuer**: Confirmar que `iss` é `https://login.microsoftonline.com/{tenant_id}/v2.0`
✅ **Audience**: Verificar que `aud` corresponde ao seu `client_id`
✅ **Expiration**: Confirmar que `exp` não passou
✅ **Nonce**: Validar que corresponde ao nonce enviado

```python
import jwt
from jwt import PyJWKClient

def validate_id_token(id_token: str, nonce: str) -> dict:
    # 1. Buscar chaves públicas do Entra ID
    jwks_uri = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
    jwks_client = PyJWKClient(jwks_uri)

    # 2. Obter chave pública para verificar assinatura
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    # 3. Decodificar e validar
    decoded_token = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": True
        }
    )

    # 4. Validar nonce
    if decoded_token.get('nonce') != nonce:
        raise ValueError('Invalid nonce')

    return decoded_token
```

### 4. HTTPS Obrigatório

⚠️ **Em produção, HTTPS é obrigatório**:
- OAuth2 exige HTTPS para proteger tokens em trânsito
- Microsoft pode rejeitar redirect_uri sem HTTPS
- Use certificados válidos (Let's Encrypt é gratuito)

### 5. Escopo Mínimo Necessário

Solicite apenas as permissões necessárias:

```python
# Mínimo para autenticação
SCOPES = ["openid", "profile", "email"]

# Se precisa ler perfil completo
SCOPES = ["openid", "profile", "email", "User.Read"]

# Se precisa ler calendário (exemplo - adicionar apenas se necessário)
SCOPES = ["openid", "profile", "email", "User.Read", "Calendars.Read"]
```

### 6. Rate Limiting

Implemente rate limiting em endpoints críticos:

```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/login')
@limiter.limit("10 per minute")  # Máximo 10 tentativas por minuto
def login():
    # ...
```

### 7. Logging e Auditoria

Registre eventos de segurança (sem expor secrets):

```python
import logging

logger = logging.getLogger(__name__)

# ✅ BOM
logger.info(f"User {user_email} logged in successfully via Entra ID")
logger.warning(f"Failed login attempt from IP {request.remote_addr}")

# ❌ RUIM - NUNCA LOGAR TOKENS OU SECRETS
logger.info(f"Access token: {access_token}")  # ❌ PERIGOSO!
logger.debug(f"Client secret: {CLIENT_SECRET}")  # ❌ NUNCA FAZER ISSO!
```

---

## Testes

### Cenário 1: Login com sucesso

1. Acesse `https://sua-aplicacao.com/login`
2. Deve redirecionar para `login.microsoftonline.com`
3. Faça login com credenciais corporativas válidas
4. Deve redirecionar de volta para `/auth/callback`
5. Deve criar sessão e redirecionar para `/dashboard`
6. Verifique que o usuário foi criado no banco de dados

### Cenário 2: Usuário cancela login

1. Inicie o fluxo de login
2. Na tela do Entra ID, clique em "Cancelar"
3. Deve retornar para `/auth/callback` com `error=access_denied`
4. Aplicação deve exibir mensagem amigável de erro

### Cenário 3: Token expirado

1. Faça login com sucesso
2. Aguarde até o token expirar (geralmente 1 hora)
3. Tente acessar recurso protegido
4. Deve retornar 401 Unauthorized
5. Frontend deve redirecionar para login novamente

### Cenário 4: CSRF Attack Simulation

1. Inicie login e copie a URL de callback com `code` e `state`
2. Limpe a sessão (ou use outra aba anônima)
3. Tente acessar a URL de callback copiada
4. Deve retornar erro "Invalid state parameter"

### Cenário 5: MFA (se configurado pelo cliente)

1. Inicie o fluxo de login
2. Após inserir email/senha, Entra ID solicita segundo fator
3. Complete MFA (SMS, app authenticator, etc)
4. Login deve completar normalmente
5. Aplicação não precisa fazer nada especial - MFA é transparente

---

## Troubleshooting

### Erro: `redirect_uri_mismatch`

**Sintoma**: "AADSTS50011: The redirect URI specified in the request does not match the redirect URIs configured for the application."

**Causa**: O `redirect_uri` enviado no request não corresponde exatamente aos URIs configurados no Azure.

**Solução**:
1. Verifique que o redirect_uri no código é **exatamente igual** ao configurado no Azure
2. Atenção: diferenças de maiúsculas/minúsculas, http vs https, trailing slash fazem diferença
3. No Azure Portal: App Registration → Authentication → Redirect URIs

**Exemplo de mismatch**:
```
Código:     https://app.com/auth/callback
Configurado: https://app.com/auth/callback/   ← Barra extra!
```

### Erro: `invalid_client`

**Sintoma**: "AADSTS7000215: Invalid client secret provided."

**Causa**: Client secret incorreto, expirado ou não está sendo enviado.

**Solução**:
1. Verifique que o client_secret está correto (copie novamente do Azure)
2. Confirme que o secret não expirou (Azure Portal → Certificates & secrets)
3. Gere um novo secret se necessário
4. Verifique que não há espaços extras ou caracteres invisíveis

### Erro: `invalid_grant`

**Sintoma**: "AADSTS70000: The provided authorization code has expired or is invalid."

**Causa**: O authorization code já foi usado ou expirou (validade de ~10 minutos).

**Solução**:
1. Authorization codes são de uso único - não tente reutilizar
2. Implemente o fluxo completo: gerar novo code a cada login
3. Verifique que não há delays entre receber o code e trocá-lo por token

### Erro: `consent_required`

**Sintoma**: "AADSTS65001: The user or administrator has not consented to use the application."

**Causa**: Admin não concedeu consentimento para as permissões solicitadas.

**Solução**:
1. No Azure Portal: App Registration → API permissions
2. Clique em "Grant admin consent for [Organização]"
3. Se o botão estiver desabilitado, peça para um Global Administrator fazer

### Erro: CORS (no frontend)

**Sintoma**: "Access to fetch at '...' from origin '...' has been blocked by CORS policy"

**Causa**: Chamadas diretas do JavaScript para endpoints do Entra ID são bloqueadas.

**Solução**:
- **NÃO** faça chamadas OAuth2 direto do frontend
- Sempre use o backend como intermediário
- Frontend → chama `/login` do seu backend → backend redireciona para Entra ID

### Erro: Usuário não consegue acessar

**Sintoma**: Usuário faz login com sucesso no Entra ID, mas não consegue acessar a aplicação.

**Causa**: User assignment está ativado e o usuário não foi adicionado.

**Solução**:
1. Azure Portal → Enterprise applications → Sua aplicação
2. Vá em "Users and groups"
3. Adicione o usuário ou grupo necessário

### Erro: Token não contém claims esperadas

**Sintoma**: ID token ou access token não contém `email`, `name`, ou outras claims.

**Causa**: Scopes não foram solicitados corretamente.

**Solução**:
1. Verifique que solicitou os scopes corretos: `["openid", "profile", "email"]`
2. Confirme que as permissões foram concedidas no Azure
3. Verifique a configuração de "Optional claims" no App Registration

---

## Referências

### Documentação Oficial Microsoft

- **Visão geral do OAuth2**: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- **Microsoft Graph API**: https://learn.microsoft.com/en-us/graph/api/overview
- **MSAL (biblioteca oficial)**: https://learn.microsoft.com/en-us/entra/identity-platform/msal-overview
- **Permissões do Graph**: https://learn.microsoft.com/en-us/graph/permissions-reference

### Ferramentas Úteis

- **JWT Debugger**: https://jwt.io (para decodificar e validar ID tokens)
- **OAuth2 Debugger**: https://oauthdebugger.com (testar fluxo OAuth2)
- **Microsoft Graph Explorer**: https://developer.microsoft.com/graph/graph-explorer (testar chamadas à Graph API)

### Especificações

- **OAuth2 RFC 6749**: https://datatracker.ietf.org/doc/html/rfc6749
- **OpenID Connect Core**: https://openid.net/specs/openid-connect-core-1_0.html

---

## Perguntas Frequentes (FAQ)

### 1. Preciso pagar para usar Entra ID?

Para autenticação básica (login com OAuth2), o **Azure AD Free** é suficiente e está incluído em qualquer assinatura Microsoft 365. Recursos avançados (Conditional Access, Identity Protection) exigem licenças premium (P1/P2).

### 2. O que acontece se o cliente mudar a senha no Entra ID?

A senha é gerenciada pelo Entra ID, não pela sua aplicação. Se o usuário mudar a senha, ele simplesmente usará a nova senha no próximo login. Nenhuma ação é necessária na sua aplicação.

### 3. Como funciona o MFA (Multi-Factor Authentication)?

MFA é configurado e gerenciado pelo cliente no Entra ID. Quando habilitado, após o usuário inserir email/senha, o Entra ID solicita o segundo fator (SMS, app, etc). Para sua aplicação, é **transparente** - você não precisa implementar nada especial.

### 4. Posso usar o mesmo App Registration para múltiplos ambientes?

**Não é recomendado**. Crie App Registrations separados para:
- Desenvolvimento (dev.app.com)
- Staging (staging.app.com)
- Produção (app.com)

Isso permite isolamento de secrets e melhor rastreabilidade.

### 5. O access token expira? Como renovar?

Sim, access tokens expiram (geralmente em 1 hora). Você pode:
- **Opção A**: Usar o `refresh_token` para obter novo access token sem re-autenticação
- **Opção B**: Forçar re-login (mais simples, mas pior UX)

**Exemplo de refresh**:
```python
refresh_data = {
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'refresh_token': stored_refresh_token,
    'grant_type': 'refresh_token',
    'scope': ' '.join(SCOPES)
}
response = requests.post(TOKEN_URL, data=refresh_data)
new_tokens = response.json()
```

### 6. Como desabilitar um usuário?

Existem duas formas:
- **No Entra ID (cliente)**: Desabilitar a conta do usuário no Azure AD - ele não conseguirá fazer login
- **Na aplicação (você)**: Adicionar flag `is_active` no banco e verificar em cada request

### 7. Posso obter foto do perfil do usuário?

Sim! Use o Microsoft Graph:

```python
headers = {'Authorization': f'Bearer {access_token}'}
photo_response = requests.get(
    'https://graph.microsoft.com/v1.0/me/photo/$value',
    headers=headers
)

if photo_response.status_code == 200:
    with open('profile.jpg', 'wb') as f:
        f.write(photo_response.content)
```

### 8. Como testar localmente sem HTTPS?

Para desenvolvimento local, você pode usar `http://localhost:3000` como redirect_uri. Configure no Azure:
- Redirect URI: `http://localhost:3000/auth/callback` (apenas para dev)

⚠️ **IMPORTANTE**: Remova redirect_uris localhost antes de ir para produção!

### 9. Suporta login com contas pessoais Microsoft (@outlook.com)?

Depende da configuração do App Registration:
- **Accounts in this organizational directory only**: Apenas contas corporativas do tenant específico
- **Accounts in any organizational directory**: Contas corporativas de qualquer tenant
- **Accounts in any organizational directory and personal Microsoft accounts**: Inclui @outlook.com, @hotmail.com

Para maioria dos casos B2B, use a primeira opção.

### 10. Como fazer logout global (Entra ID + Aplicação)?

```python
@app.route('/logout')
def logout():
    # 1. Limpar sessão local
    session.clear()

    # 2. Construir URL de logout do Entra ID
    logout_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/logout"
    post_logout_uri = "https://sua-aplicacao.com"

    # 3. Redirecionar
    return redirect(f"{logout_url}?post_logout_redirect_uri={post_logout_uri}")
```

Isso faz logout tanto na sua aplicação quanto no Entra ID, garantindo que o usuário precise fazer login novamente.

---

## Resumo Executivo

### Para o Cliente (Empresa com Entra ID)

1. Registrar aplicação no Azure Portal
2. Gerar e compartilhar credenciais (Client ID, Tenant ID, Client Secret)
3. Configurar redirect URIs
4. Conceder permissões (admin consent)
5. Configurar acesso de usuários

**Tempo estimado**: 15-30 minutos

### Para o Desenvolvedor (Você)

1. Armazenar credenciais de forma segura
2. Implementar endpoint `/login` (redireciona para Entra ID)
3. Implementar endpoint `/callback` (recebe código, troca por token, busca perfil)
4. Implementar auto-provisioning de usuários
5. Implementar gerenciamento de sessão
6. Implementar logout
7. Testar todos os fluxos

**Tempo estimado**: 4-8 horas (primeira implementação), 1-2 horas (com biblioteca pronta)

---

## Conclusão

A integração com Microsoft Entra ID via OAuth2/OIDC é um padrão bem estabelecido e seguro para autenticação corporativa. Com este guia, você tem todos os elementos necessários para implementar SSO em qualquer aplicação web, independentemente da stack tecnológica.

**Pontos-chave para lembrar**:
- ✅ Use Authorization Code Flow (não Implicit Flow)
- ✅ Sempre valide o state parameter (CSRF protection)
- ✅ Valide tokens JWT (assinatura, expiration, audience, issuer)
- ✅ Proteja o client_secret como se fosse uma senha root
- ✅ Use HTTPS em produção (obrigatório)
- ✅ Solicite apenas os scopes necessários
- ✅ Implemente rate limiting e logging

Se você seguir este guia e as boas práticas de segurança, terá uma integração robusta, segura e pronta para produção.

---

**Versão**: 1.0
**Última atualização**: Janeiro 2025
**Autor**: Documentação Técnica - Integração OAuth2/OIDC
