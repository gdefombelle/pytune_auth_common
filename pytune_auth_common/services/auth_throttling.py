import asyncio
from pytune_configuration.redis_config import get_redis_client
from simple_logger.logger import get_logger
from pytune_configuration.sync_config_singleton import config, SimpleConfig

logger = get_logger("auth_throttling")
config = config or SimpleConfig()

async def register_failed_login(email: str) -> int:
    redis = await get_redis_client()
    key = f"{config.FAILED_LOGIN_KEY_PREFIX}:{email.lower()}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, config.FAILED_LOGIN_TTL_SECONDS)
    await logger.ainfo(f"Failed login attempt {count} for {email}")
    return count

async def reset_failed_logins(email: str):
    redis = await get_redis_client()
    key = f"{config.FAILED_LOGIN_KEY_PREFIX}:{email.lower()}"
    await redis.delete(key)
    await logger.ainfo(f"Reset failed login attempts for {email}")

async def is_login_blocked(email: str) -> bool:
    redis = await get_redis_client()
    key = f"{config.FAILED_LOGIN_KEY_PREFIX}:{email.lower()}"
    count = await redis.get(key)
    if count is None:
        return False
    return int(count) >= config.FAILED_LOGIN_ATTEMPT_LIMIT

async def apply_login_delay(email: str):
    redis = await get_redis_client()
    key = f"{config.FAILED_LOGIN_KEY_PREFIX}:{email.lower()}"
    count = await redis.get(key)
    if count:
        delay = min(int(count) * 0.5, 5)  # 0.5s de retard par tentative, max 5s
        await asyncio.sleep(delay)
