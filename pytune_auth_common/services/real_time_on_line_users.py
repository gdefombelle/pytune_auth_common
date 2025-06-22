import asyncio
from datetime import datetime
from typing import Dict, Optional
from redis import RedisError

from pytune_configuration.redis_config import get_redis_client, init_redis
from pytune_auth_common.utils.user_agent import platforms
from pytune_data.crud import update_user_last_connection
from pytune_data.models import User
from pytune_data.db import init as db_init
from pytune_configuration.sync_config_singleton import config, SimpleConfig
from simple_logger.logger import SimpleLogger, get_logger

logger: SimpleLogger = get_logger("auth_common")

if config is None:
    config = SimpleConfig()

def redis_retry(fn):
    async def wrapper(*args, **kwargs):
        try:
            redis = await get_redis_client()
            return await fn(*args, redis=redis, **kwargs)
        except RedisError as e:
            logger.warning(f"[Redis] ⚠️ Retry after error: {e}")
            redis = await init_redis(config.REDIS_URL)
            return await fn(*args, redis=redis, **kwargs)
    return wrapper

@redis_retry
async def add_user_online(user_id: int, platform: str, redis):
    key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
    await redis.sadd(key, user_id)
    await redis.expire(key, config.USER_ONLINE_TTL)

@redis_retry
async def remove_user_online(user_id: int, platform: str, redis):
    key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
    await redis.srem(key, user_id)

@redis_retry
async def update_last_activity(user_id: int, redis):
    current_time = datetime.now()
    await redis.set(f"{config.REDIS_USER_LAST_ACTIVITY}{user_id}", current_time.timestamp())

@redis_retry
async def get_last_activity(user_id: int, redis) -> Optional[datetime]:
    last_activity = await redis.get(f"{config.REDIS_USER_LAST_ACTIVITY}{user_id}")
    if last_activity:
        return datetime.fromtimestamp(float(last_activity))
    return None

@redis_retry
async def get_online_users_count_for_platform(platform: str = 'all', redis=None) -> int:
    if platform == 'all':
        total_count = 0
        for plat in platforms:
            key = f"{config.REDIS_ON_LINE_USERS}:{plat}"
            count = await redis.scard(key)
            total_count += count
        return total_count

    key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
    return await redis.scard(key)

@redis_retry
async def reset_online_users(platform: Optional[str] = 'all', redis=None) -> dict[str, list[Dict]]:
    removed_users = await get_online_users(platform)

    if platform == 'all':
        for plat in platforms:
            key = f"{config.REDIS_ON_LINE_USERS}:{plat}"
            await redis.delete(key)
        logger.warning("All online users cleared from Redis.")
    else:
        if platform in platforms:
            key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
            await redis.delete(key)
            logger.warning(f"Online users for platform '{platform}' cleared from Redis.")
        else:
            raise ValueError(f"Invalid platform: {platform}. Available: {', '.join(platforms)}")

    return removed_users

@redis_retry
async def get_online_users(platform: str = 'all', redis=None) -> dict[str, list[dict]]:
    online_users = {}
    targets = platforms if platform == 'all' else [platform]

    for plat in targets:
        if plat not in platforms:
            raise ValueError(f"Invalid platform: {plat}. Available: {', '.join(platforms)}")

        key = f"{config.REDIS_ON_LINE_USERS}:{plat}"
        user_ids = await redis.smembers(key)
        user_ids = [int(uid) for uid in user_ids]

        if user_ids:
            users_details = await User.filter(id__in=user_ids).values("id", "email", "first_name", "last_name")
            online_users[plat] = users_details
        else:
            online_users[plat] = []

    return online_users

async def update_last_connection(user_id):
    await update_user_last_connection(user_id)