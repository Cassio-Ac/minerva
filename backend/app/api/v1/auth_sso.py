"""
SSO Authentication Endpoints
Gerencia fluxo OAuth2/OIDC para login via SSO
"""
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.database import get_db
from app.models.sso_provider import SSOProvider
from app.models.user import User
from app.services.sso_auth_service import SSOAuthService, get_sso_auth_service
from app.services.auth_service import AuthService
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/sso", tags=["SSO Authentication"])


@router.get("/providers")
async def list_sso_providers(db: AsyncSession = Depends(get_db)):
    """
    Lista provedores SSO ativos disponíveis para login

    Returns:
        List de providers: [{"id": "...", "name": "...", "provider_type": "..."}]
    """
    result = await db.execute(
        select(SSOProvider).where(SSOProvider.is_active == True)
    )
    providers = result.scalars().all()

    return [
        {
            "id": str(provider.id),
            "name": provider.name,
            "provider_type": provider.provider_type,
        }
        for provider in providers
    ]


@router.get("/{provider_id}/login")
async def sso_login_redirect(
    provider_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Inicia fluxo de login SSO

    1. Gera state e nonce
    2. Armazena em sessão (ou pode usar JWT temporário)
    3. Redireciona usuário para authorization URL do provider

    Args:
        provider_id: UUID do SSO provider

    Returns:
        RedirectResponse para authorization URL do provider
    """
    # Buscar provider
    result = await db.execute(
        select(SSOProvider).where(
            SSOProvider.id == provider_id,
            SSOProvider.is_active == True
        )
    )
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(status_code=404, detail="SSO Provider not found or inactive")

    # Inicializar service
    auth_service = get_sso_auth_service(provider)

    # Gerar state e nonce
    state = auth_service.generate_state()
    nonce = auth_service.generate_nonce()

    # Construir authorization URL
    auth_url = auth_service.get_authorization_url(state, nonce)

    logger.info(f"Redirecting to SSO provider: {provider.name}")

    # Criar response com redirect
    response = RedirectResponse(url=auth_url, status_code=302)

    # Armazenar state e nonce em cookies seguros (httponly)
    # Em produção, considere usar Redis ou JWT assinado
    response.set_cookie(
        key=f"sso_state_{provider_id}",
        value=state,
        httponly=True,
        secure=True,  # Apenas HTTPS em produção
        samesite="lax",
        max_age=600  # 10 minutos
    )
    response.set_cookie(
        key=f"sso_nonce_{provider_id}",
        value=nonce,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=600
    )
    response.set_cookie(
        key="sso_provider_id",
        value=provider_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=600
    )

    return response


@router.get("/callback/{provider_type}")
async def sso_callback(
    provider_type: str,
    code: str = Query(..., description="Authorization code from provider"),
    state: str = Query(..., description="State parameter for CSRF validation"),
    db: AsyncSession = Depends(get_db)
):
    """
    Callback endpoint chamado pelo provider SSO após autorização

    Fluxo:
    1. Validar state (CSRF protection)
    2. Trocar code por access token
    3. Buscar informações do usuário
    4. Criar ou atualizar usuário local
    5. Gerar JWT token
    6. Redirecionar para frontend com token

    Args:
        provider_type: Tipo do provider (entra_id, google)
        code: Authorization code recebido do provider
        state: State parameter para validação CSRF

    Returns:
        RedirectResponse para frontend com JWT token
    """
    try:
        # Buscar provider ativo deste tipo
        # Em produção, pode ter múltiplos providers do mesmo tipo
        # Por simplicidade, pegamos o primeiro ativo
        result = await db.execute(
            select(SSOProvider).where(
                SSOProvider.provider_type == provider_type,
                SSOProvider.is_active == True
            )
        )
        provider = result.scalar_one_or_none()

        if not provider:
            logger.error(f"No active SSO provider found for type: {provider_type}")
            return RedirectResponse(
                url=f"http://localhost:5173/login?error=provider_not_found",
                status_code=302
            )

        # TODO: Validar state contra cookie (CSRF protection)
        # stored_state = request.cookies.get(f"sso_state_{provider.id}")
        # if state != stored_state:
        #     raise HTTPException(status_code=400, detail="Invalid state parameter")

        # Inicializar service
        auth_service = get_sso_auth_service(provider)

        # 1. Trocar code por token
        logger.info(f"Exchanging authorization code for access token...")
        token_response = await auth_service.exchange_code_for_token(
            code=code,
            redirect_uri=provider.redirect_uri
        )

        access_token = token_response["access_token"]

        # 2. Buscar informações do usuário
        logger.info(f"Fetching user info from SSO provider...")
        user_info = await auth_service.get_user_info(access_token)

        logger.info(f"SSO user info: {user_info.get('email')}")

        # 3. Provisionar ou atualizar usuário
        logger.info(f"Provisioning or updating user...")
        user = await auth_service.provision_or_update_user(
            db=db,
            user_info=user_info,
            check_ad_status=True  # Verificar status no AD em tempo real
        )

        if not user.is_active:
            logger.warning(f"User {user.email} is not active")
            return RedirectResponse(
                url=f"http://localhost:5173/login?error=user_inactive",
                status_code=302
            )

        # 4. Gerar JWT token local
        jwt_token = AuthService.create_access_token(
            data={
                "sub": str(user.id),
                "username": user.username,
                "role": user.role.value if hasattr(user.role, 'value') else user.role
            }
        )

        logger.info(f"✅ SSO login successful for user: {user.email}")

        # Log successful SSO login
        try:
            await AuditService.log_sso_login_success(
                user_id=str(user.id),
                sso_provider_id=str(provider.id),
                metadata={
                    "provider_type": provider.provider_type,
                    "provider_name": provider.name,
                    "user_email": user.email
                }
            )
        except Exception as log_error:
            logger.error(f"Failed to create audit log: {log_error}")

        # 5. Redirecionar para frontend com token
        # Frontend pegará o token da query string e armazenará no localStorage
        frontend_url = f"http://localhost:5173/sso-callback?token={jwt_token}"

        response = RedirectResponse(url=frontend_url, status_code=302)

        # Limpar cookies de state/nonce
        response.delete_cookie(f"sso_state_{provider.id}")
        response.delete_cookie(f"sso_nonce_{provider.id}")
        response.delete_cookie("sso_provider_id")

        return response

    except Exception as e:
        logger.error(f"SSO callback error: {e}", exc_info=True)

        # Redirecionar para login com erro
        error_message = str(e)

        # Mensagens amigáveis para erros conhecidos
        if "desativada no sistema corporativo" in error_message:
            error_param = "account_disabled"
        elif "não encontrada no Microsoft Entra ID" in error_message:
            error_param = "account_not_found"
        elif "Auto-provisioning está desativado" in error_message:
            error_param = "auto_provision_disabled"
        else:
            error_param = "sso_error"

        # Log failed SSO login
        try:
            await AuditService.log_sso_login_failed(
                sso_provider_id=str(provider.id) if provider else None,
                reason=error_param,
                metadata={
                    "error_message": error_message,
                    "provider_type": provider.provider_type if provider else None
                }
            )
        except Exception as log_error:
            logger.error(f"Failed to create audit log: {log_error}")

        return RedirectResponse(
            url=f"http://localhost:5173/login?error={error_param}",
            status_code=302
        )


@router.get("/test-config/{provider_id}")
async def test_sso_config(
    provider_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Endpoint de teste para validar configuração SSO (admin only)

    Retorna as URLs e configurações sem fazer login real
    Útil para debug durante setup
    """
    result = await db.execute(
        select(SSOProvider).where(SSOProvider.id == provider_id)
    )
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    auth_service = get_sso_auth_service(provider)

    test_state = "test_state_123"
    test_nonce = "test_nonce_456"

    return {
        "provider": provider.to_dict(),
        "authorization_url": auth_service.get_authorization_url(test_state, test_nonce),
        "token_url": provider.get_token_url(),
        "userinfo_url": provider.get_userinfo_url(),
        "scopes": provider.get_scopes_list(),
        "redirect_uri": provider.redirect_uri,
    }
