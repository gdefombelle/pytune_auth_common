from ipaddress import ip_address, ip_network
import asyncio
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from pytune_auth_common.services.auth_checks import get_current_user
from pytune_data.models import UserTypeEnum
from pytune_configuration.redis_config import get_redis_client, init_redis
from simple_logger.logger import get_logger
from pytune_configuration.sync_config_singleton import config as _config, SimpleConfig
from redis import RedisError

_config = _config or SimpleConfig()
logger = get_logger("auth_common")

def redis_retry(fn):
    async def wrapper(*args, **kwargs):
        try:
            redis = await get_redis_client()
            return await fn(*args, redis=redis, **kwargs)
        except RedisError as e:
            logger.warning(f"[Redis] ⚠️ Retry after error: {e}")
            redis = await init_redis(_config.REDIS_URL)
            return await fn(*args, redis=redis, **kwargs)
    return wrapper

class RateLimitConfig:
    def __init__(self, rate_limit: int, time_window: int, block_time: int):
        self._lock = asyncio.Lock()
        self.rate_limit = rate_limit
        self.time_window = time_window
        self.block_time = block_time

    async def update(self, rate_limit: int, time_window: int, block_time: int):
        async with self._lock:
            self.rate_limit = rate_limit
            self.time_window = time_window
            self.block_time = block_time

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: RateLimitConfig):
        super().__init__(app)
        self.app = app
        self.config = config
        self.local_networks = [
            ip_network("127.0.0.0/8"),
            ip_network("192.168.0.0/16"),
            ip_network("10.0.0.0/8"),
            ip_network("172.16.0.0/12")
        ]

    def is_local_ip(self, client_ip: str) -> bool:
        ip = ip_address(client_ip)
        return any(ip in network for network in self.local_networks)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host

        if self.is_local_ip(client_ip):
            return await call_next(request)

        try:
            response = await self._handle_rate_limit(client_ip, call_next, request)
            return response
        except Exception as e:
            logger.error(f"RateLimiter error: {e}")
            return Response("Internal Server Error (rate limit)", status_code=500)

    @redis_retry
    async def _handle_rate_limit(self, client_ip: str, call_next, request: Request):
        redis = await get_redis_client()
        is_blocked = await redis.get(f"blocked_{client_ip}")
        if is_blocked:
            await logger.awarning(f"⛔ IP bloquée: {client_ip} tente encore.")
            return Response("Too many requests, you are temporarily blocked.", status_code=429)

        async with self.config._lock:
            requests = await redis.incr(f"rate_limit_{client_ip}")
            if requests == 1:
                await redis.expire(f"rate_limit_{client_ip}", self.config.time_window)

            if requests > self.config.rate_limit:
                await redis.set(f"blocked_{client_ip}", "1", ex=self.config.block_time)
                await logger.awarning(f"🚫 IP {client_ip} bloquée (trop de requêtes)")
                return Response("Too many requests, you are temporarily blocked.", status_code=429)

        return await call_next(request)
