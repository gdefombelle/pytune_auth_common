# services/middleware.py

from ipaddress import ip_address, ip_network
import asyncio
import os
from fastapi import Request, Response
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware
from pytune_auth_common.services.auth_checks import get_current_user
from pytune_data.models import UserTypeEnum
from pytune_configuration.redis_config import get_redis_client, redis_client
from simple_logger.logger import get_logger, SimpleLogger
from pytune_configuration.sync_config_singleton import config as _config, SimpleConfig

_config = _config or SimpleConfig()

logger = get_logger("auth_common")

class RateLimitConfig:
    def __init__(self, rate_limit: int, time_window: int, block_time: int):
        self._lock = asyncio.Lock()  # Assurez-vous que cette ligne est présente
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
        self.redis_client = Redis.from_url(os.getenv("REDIS_URL"), decode_responses=True)
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
        try:
            if not await self.redis_client.ping():
                raise RuntimeError("Redis client n'est pas connecté")
        except Exception as e:
            print(f"Erreur dans RateLimitMiddleware : {e}")
            raise

        client_ip = request.client.host
        if self.is_local_ip(client_ip):
            return await call_next(request)

        #redis_client = await get_redis_client() --> obtain redis_client
        is_blocked = await self.redis_client.get(f"blocked_{client_ip}")
        if is_blocked:
            await logger.awarning(f"blocked user - ip: {client_ip} still trying to make new requests")
            return Response("Too many requests, you are temporarily blocked.", status_code=429)

        async with self.config._lock:
            requests = await self.redis_client.incr(f"rate_limit_{client_ip}")
            if requests == 1:
                await self.redis_client.expire(f"rate_limit_{client_ip}", self.config.time_window)

            if requests > self.config.rate_limit:
                await self.redis_client.set(f"blocked_{client_ip}", "1", ex=self.config.block_time)
                await logger.awarning(f"user ip: {client_ip} has been blocked (too many requests)")
                return Response("Too many requests, you are temporarily blocked.", status_code=429)

        response = await call_next(request)
        return response
    
    ## custom CORS Middleware
    
