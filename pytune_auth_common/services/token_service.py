# token service
import re
import asyncio
from datetime import datetime, timedelta, timezone
import random
from typing import Dict, Optional
from fastapi import HTTPException, Request, Response, status
from typing import cast
from pytune_auth_common.models.schema import UserOut
from pytune_data.models import User
from pytune_data.crud import get_user_by_email
from pytune_data.db import init as init_db
from pytune_auth_common.services.key_management_service import KeyManagementService
from pytune_configuration.sync_config_singleton import config, SimpleConfig
from simple_logger.logger import SimpleLogger, get_logger
from redis import RedisError
from pytune_configuration.redis_config import get_redis_client, init_redis


logger:SimpleLogger = get_logger("auth_common")

if config is None:
    config = SimpleConfig()
key_service = KeyManagementService()

def redis_retry(fn):
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except RedisError as e:
            logger.warning(f"[Redis/token_service] ⚠️ Retry after error: {e}")
            # On tente de réinitialiser la connexion globale
            await init_redis(config.REDIS_URL)
            return await fn(*args, **kwargs)
    return wrapper

def token_user_data(user: UserOut):
    return {
        "sub": user.email,
        "user_type": user.user_type,
        "id": user.id,
        "first_name": user.first_name,
        "status": user.status,
        "client_status": user.client_status,
        "oauth_provider": user.oauth_provider,
    }

def generate_token(data: dict, expires_delta: Optional[timedelta] = None, token_type="access"):
    """
    Generates a JWT token signed with the appropriate private key.
    
    :param data: The data to encode in the JWT.
    :param expires_delta: The duration before the token expires.
    :param token_type: The type of token ("access" or "refresh").
    :return: The signed JWT token.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})

    if token_type == "access":
        # Use the service to sign the access token
        return key_service.sign_jwt(to_encode, key_type="access")
    elif token_type == "refresh":
        # Use the service to sign the refresh token
        return key_service.sign_jwt(to_encode, key_type="refresh")
    elif token_type == "email_verification":
        return key_service.sign_jwt(to_encode, key_type="email_verification")
    elif token_type == "reset_password":
        return key_service.sign_jwt(to_encode, key_type="reset_password")

@redis_retry
async def get_user_token(user_email: str) -> Optional[str]:
    redis_client = await get_redis_client()
    return await redis_client.get(f"{config.REDIS_USER_TOKEN_STORAGE}{user_email}")

@redis_retry
async def is_token_revoked(token: str) -> bool:
    redis_client = await get_redis_client()
    key: str = config.REDIS_TOKEN_BLACKLIST_KEY
    return bool(await redis_client.sismember(key, token))  # type: ignore

@redis_retry
async def remove_user_token(user_email: str):
    redis_client = await get_redis_client()
    await redis_client.delete(f"{config.REDIS_USER_TOKEN_STORAGE}{user_email}")


def should_check_db() -> bool:
    return random.random() < config.DB_PROBABILITY_QUERY_THRESHOLD


async def get_user_from_db_or_token(payload: dict, force_db = False) -> Optional[UserOut]:
    """
    Retrieves the user from the database if necessary, 
    or uses the JWT (cookie) data otherwise.
    """
    if force_db or should_check_db():
        await init_db()
        user = await get_user_by_email(payload.get("sub")) # type: ignore
        if user:
            return UserOut(
                id=user.id,
                last_name=user.last_name,
                email=user.email,
                first_name=user.first_name,
                user_type=user.user_type,
                status=user.status,
                client_status=user.client_status,
                oauth_provider=user.oauth_provider
            )
        else:
            return None
    else:
        # Return the token information directly
        sub = str(payload.get("sub") or "")
        first_name = str(payload.get("first_name") or "")
        user_type = payload.get("user_type") or ""
        status = payload.get("status") or ""
        client_status = payload.get("client_status") or ""
        oauth_provider = payload.get("oauth_provider")

        return UserOut(
            id=payload.get("id"), # type: ignore
            email=sub,
            first_name=first_name,
            user_type=user_type, # type: ignore
            status=status, # type: ignore
            client_status=client_status, # type: ignore
            oauth_provider=oauth_provider,
        )
            
@redis_retry
async def revoke_token(token: str):
    redis_client = await get_redis_client()
    key: str = config.REDIS_TOKEN_BLACKLIST_KEY   
    await redis_client.sadd(key, token) # type: ignore


@redis_retry
async def store_user_token(user_email: str, token: str):
    redis_client = await get_redis_client()
    # si ACCESS_TOKEN_EXPIRE_MINUTES est bien en minutes, je recommande :
    ttl_seconds = config.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    await redis_client.set(
        f"{config.REDIS_USER_TOKEN_STORAGE}{user_email}",
        token,
        ex=ttl_seconds,
    )
def get_root_domain(hostname: str) -> str:
    # Vérifie si le hostname est une adresse IP (ex: 127.0.0.1, 192.168.1.1)
    ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if ip_pattern.match(hostname) or hostname == "localhost":
        return hostname  # Utiliser l'adresse IP ou localhost directement en environnement local
    
    # Divise le domaine en parties et conserve les deux dernières parties (ex: "pytune.com")
    parts = hostname.split(".")
    if len(parts) > 2:
        # On utilise les deux dernières parties pour obtenir le domaine principal
        return f".{parts[-2]}.{parts[-1]}"
    return hostname  # Si c'est déjà un domaine de niveau supérieur, on le retourne tel quel

def delete_tokens_from_response(response: Response, request: Request):
    # Déterminer le domaine principal si nécessaire
    # Si lors de la création du cookie, aucun domaine n'a été spécifié, laissez 'domain=None'.
    domain = None
    if request.url.hostname not in ["127.0.0.1", "localhost"] and not request.url.hostname.startswith("192.168."):
        domain = request.url.hostname

    # Suppression des cookies sans préciser le domaine
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")

    # Si un domaine avait été spécifié lors de la création
    if domain:
        response.delete_cookie(key="access_token", path="/", domain=domain)
        response.delete_cookie(key="refresh_token", path="/", domain=domain)

    return {"message": "Cookies have been removed"}

def respond_with_tokens(
    response: Response,
    request: Request,
    platform: str,
    access_token: str,
    refresh_token: Optional[str] = None,
) -> None:
    both_tokens: bool = bool(refresh_token)
    hostname = request.url.hostname or ""
    is_local = request.url.hostname in ["127.0.0.1", "localhost"] or hostname.startswith("192.168.")
    domain = None if is_local else get_root_domain(hostname)
    secure_cookie = not is_local
    samesite_policy = "none" if domain else "lax"
    force_bearer = config.INCLUDE_BEARER_TOKENS_FOR_WEB

    logger.info(
        "token_service.respond_with_tokens | "
        f"platform={platform} | is_local={is_local} | scheme={request.url.scheme} | "
        f"domain={domain} | secure_cookie={secure_cookie} | samesite={samesite_policy} | "
        f"force_bearer={force_bearer} | both_tokens={both_tokens}"
    )

    # Cookies web
    if platform == "web":
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=secure_cookie,
            path="/",
            domain=domain,
            samesite=samesite_policy,
        )
        if both_tokens:
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=secure_cookie,
                path="/",
                domain=domain,
                samesite=samesite_policy,
            )
        response.headers["Access-Control-Allow-Credentials"] = "true"

    # Headers Bearer pour dev web + autres plateformes
    if force_bearer or platform != "web":
        response.headers["Authorization"] = f"Bearer {access_token}"
        if refresh_token:
            response.headers["X-Refresh-Token"] = refresh_token
            
def raise_revoked_user_error(username: str):
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"{username} has been revoked. {config.REVOKED_USER_MESSAGE}"
    )

def raise_email_not_confirmed(username: str):
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"{username} is not authorized - Email not confirmed"
    )