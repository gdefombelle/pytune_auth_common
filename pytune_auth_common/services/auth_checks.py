# Manage the current user and tokens (verification and renewal)
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, Request, Response, status
from jose import jwt, ExpiredSignatureError, JWTError
from passlib.context import CryptContext
import asyncio
from pytune_auth_common.services.key_management_service import KeyManagementService
from pytune_auth_common.services.real_time_on_line_users import update_last_connection
from pytune_data.crud import get_user_by_id
from pytune_data.db import init as init_db
from pytune_data.models import UserTypeEnum, UserStatusEnum , ClientStatusEnum 
from pytune_auth_common.models.schema import UserOut
from pytune_auth_common.services.real_time_on_line_users import add_user_online, get_last_activity, update_last_activity
from pytune_auth_common.services.token_service import (generate_token, get_user_from_db_or_token, is_token_revoked, raise_revoked_user_error,
                                                       raise_email_not_confirmed,respond_with_tokens, token_user_data, remove_user_token, delete_tokens_from_response)

from pytune_auth_common.utils.user_agent import get_platform_from_user_agent
from simple_logger.logger import get_logger, SimpleLogger 
from pytune_configuration.sync_config_singleton import config, SimpleConfig


if config is None:
    config = SimpleConfig()

key_service = KeyManagementService()

pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    default="argon2",
    deprecated="auto"
)

logger :SimpleLogger = get_logger("auth_common") 
logger.info("🎉 Logger pytune_auth_ok initialisé: pytune_auth_common")
# --- Helper Functions --- #

def validate_token(token: str, key: str, token_type: str) -> dict:
    """
    Validates and decodes a JWT token based on its type.
    """
    try:
        return jwt.decode(token, key, algorithms=[config.ALGORITHM])
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid {token_type} token: {str(e)}")

async def handle_user_validation(payload: dict, response: Response, request: Request) -> UserOut:
    """
    Validate the user from the token payload and ensure all checks pass.
    """
    user = await get_user_from_db_or_token(payload, force_db=True)
    if not user:
        await remove_user_token(payload.get("sub"))
        delete_tokens_from_response(response, request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User {payload.get('sub')} was removed"
        )

    # Check user status
    if user.status == UserStatusEnum.REVOKED:
        await logger.acritical("Revoked user attempted to connect")
        raise_revoked_user_error(user.email)

    if user.status == UserStatusEnum.PENDING:
        await logger.acritical(
            f"{user.email} with unconfirmed email attempted to connect user"
        )
        raise_email_not_confirmed(user.email)

    # Update user activity
    platform = get_platform_from_user_agent(request.headers.get("User-Agent", ""))
    await add_user_online(user.id, platform)
    await update_last_activity(user.id)

    return user

async def handle_expired_access_token(refresh_token: str, response: Response, request: Request) -> UserOut:
    """
    Handle the case where the access token has expired and validate the refresh token.
    """
    try:
        refresh_payload = jwt.decode(
            refresh_token,
            key_service.PUBLIC_REFRESH_KEY,
            algorithms=[config.ALGORITHM]
        )
        user = await get_user_from_db_or_token(refresh_payload, force_db=True)
        if not user:
            await remove_user_token(refresh_payload.get("sub")) # type: ignore
            delete_tokens_from_response(response, request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"User {refresh_payload.get('sub')} was removed" 
            )

        # Generate new tokens and update response
        new_access_token = generate_token(
            token_user_data(user),
            timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
            token_type="access"
        )
        new_refresh_token = generate_token(
            token_user_data(user),
            timedelta(minutes=30),
            token_type="refresh"
        )

        platform = get_platform_from_user_agent(request.headers.get("User-Agent", ""))
        respond_with_tokens(response, request, platform, new_access_token, new_refresh_token) # type: ignore

        await add_user_online(user.id, platform)
        await update_last_activity(user.id)
        await update_last_connection(user.id)


        return user

    except ExpiredSignatureError:
        # If the refresh token has expired, force a re-login
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired, please log in again"
        )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

async def handle_active_user(payload: dict, response: Response, request: Request) -> UserOut:
    """
    Handle scenarios where the access token is valid.
    """
    user = await get_user_from_db_or_token(payload, force_db=config.FORCE_RETRIEVING_USER_FROM_DB)
    if not user:
        await remove_user_token(payload.get("sub")) # type: ignore
        delete_tokens_from_response(response, request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User {payload.get('sub')} was removed"
        )

    # Check user status
    if user.status == UserStatusEnum.REVOKED:
        await logger.acritical(f"Revoked user attempted to connect {user.email}")
        raise_revoked_user_error(user.email)

    if user.status == UserStatusEnum.PENDING:
        raise_email_not_confirmed(user.email)

    # Update user activity
    platform = get_platform_from_user_agent(request.headers.get("User-Agent", ""))
    await add_user_online(user.id, platform)
    await update_last_activity(user.id)

    return user

async def handle_inactive_user(refresh_token: str, response: Response, request: Request) -> UserOut:
    """
    Handle scenarios where the access token is expired but a refresh token is provided.
    """
    try:
        refresh_payload = jwt.decode(
            refresh_token,
            key_service.PUBLIC_REFRESH_KEY,
            algorithms=[config.ALGORITHM]
        )
        user = await get_user_from_db_or_token(refresh_payload, force_db=True)
        if not user:
            await remove_user_token(refresh_payload.get("sub"))
            delete_tokens_from_response(response, request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"User {refresh_payload.get('sub')} was removed"
            )

        # Generate new tokens and update response
        new_access_token = generate_token(
            token_user_data(user),
            timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
            token_type="access"
        )
        new_refresh_token = generate_token(
            token_user_data(user),
            timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS),
            token_type="refresh"
        )

        platform = get_platform_from_user_agent(request.headers.get("User-Agent", ""))
        respond_with_tokens(response, request, platform, new_access_token, new_refresh_token)

        await add_user_online(user.id, platform)
        await update_last_activity(user.id)
        await update_last_connection(user.id)
        

        return user

    except ExpiredSignatureError:
        # If the refresh token has expired, force a re-login
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired, please log in again"
        )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

async def get_current_user(
    response: Response,
    request: Request,
    access_token: str = None,
    refresh_token: str = None
) -> Optional[UserOut]:
    """
    Authenticate and retrieve the current user using access and refresh tokens.
    Handles token validation, rotation, user activity, and token expiration.
    """

    # Step 0 : Debug hhtponly cookie en prod
    # Diagnostic complet pour debug cookies + headers
    logger.info(f"[get_current_user] Host={request.headers.get('host')} | Origin={request.headers.get('origin')}")
    logger.info(f"[get_current_user] Cookie access_token={request.cookies.get('access_token')}")
    logger.info(f"[get_current_user] Header Authorization={request.headers.get('authorization')}")
    logger.info(f"[get_current_user] Header X-Refresh-Token={request.headers.get('x-refresh-token')}")
    logger.info(f"[get_current_user] Query access_token={request.query_params.get('access_token')}")
    logger.info(f"[get_current_user] Query refresh_token={request.query_params.get('refresh_token')}")


    # Step 1: Retrieve the access token from cookies, headers, or query params

    access_token = (
        request.cookies.get("access_token")
        or request.headers.get("Authorization", "").replace("Bearer ", "")
        or request.query_params.get("access_token")
    ) # type: ignore

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token missing"
        )

    # Step 2: Check if the token has been revoked
    if await is_token_revoked(access_token):
        await logger.acritical("Revoked user attempted to connect")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked"
        )

    # Step 3: Retrieve the refresh token if necessary
    refresh_token = (
        refresh_token or
        request.headers.get("X-Refresh-Token") or
        request.cookies.get("refresh_token") or
        request.query_params.get("refresh_token")
    )

    # Step 4: Decode the access token with the current or old public key
    for key in [key_service.PUBLIC_ACCESS_KEY, key_service.PUBLIC_ACCESS_KEY_OLD]:
        try:
            payload = jwt.decode(access_token, key, algorithms=[config.ALGORITHM])
            user = await handle_active_user(payload, response, request)
            return user
        except ExpiredSignatureError:
            continue  # Try the next key if expired
        except JWTError:
            continue  # Try the next key if invalid

    # Step 5: Handle expired access token with refresh token
    if refresh_token:
        return await handle_inactive_user(refresh_token, response, request)
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token, and no valid refresh token provided"
    )


async def get_current_admin_user(
    current_user: UserOut = Depends(get_current_user),
) -> UserOut:
    """
    Dependency function to get the currently logged-in admin user.

    This function checks if the current user has admin privileges.
    If not, it raises an HTTPException.

    Args:
        current_user (UserOut): The current user obtained from the `get_current_user` dependency.

    Returns:
        UserOut: The UserOut object representing the authenticated admin user.

    Raises:
        HTTPException: If the current user does not have admin privileges.
    """
    if current_user.user_type != UserTypeEnum.ADMIN:
        await logger.acritical(f"Non admin user: {current_user.email} ({current_user.first_name} {current_user.last_name}) attemmpt to reach admin protected end-point")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges"
        )
    return current_user


