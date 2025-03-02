# Fonction pour ajouter un utilisateur en ligne dans Redis et PostgreSQL
import asyncio
from datetime import datetime
from typing import Dict, Optional
from redis import RedisError
from pytune_configuration.redis_config import get_redis_client
from pytune_auth_common.utils.user_agent import platforms
from pytune_auth_common.models.schema import User
from pytune_configuration.sync_config_singleton import config, SimpleConfig

if config is None:
    config = SimpleConfig()

async def add_user_online(user_id: int, platform: str):
    redis_client = await get_redis_client()
    key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
    
    # Ajouter à Redis
    await redis_client.sadd(key, user_id)
    await redis_client.expire(key, config.USER_ONLINE_TTL)

# Fonction pour retirer un utilisateur en ligne de Redis et PostgreSQL
async def remove_user_online(user_id: int, platform: str):
    redis_client = await get_redis_client()
    key = f"{config.REDIS_ON_LINE_USERS}:{platform}"

    # Retirer de Redis
    await redis_client.srem(key, user_id)

async def reset_online_users(platform: Optional[str] = 'all') -> dict[str, list[Dict]]:
    """
    Réinitialiser la liste des utilisateurs en ligne dans Redis et PostgreSQL.
    Retourne la liste des utilisateurs retirés avec leurs détails (ID, email, prénom, nom).

    :param platform: La plateforme à réinitialiser ('web', 'ios', 'android', 'macos', 'windows', 'linux' ou 'all').
    :return: Un dictionnaire avec les plateformes et les utilisateurs retirés pour chacune.
    """
    removed_users = await get_online_users(platform)
    redis_client = await get_redis_client()
    try:
        if platform == 'all':
            # Supprimer les utilisateurs dans Redis pour toutes les plateformes
            for platform in platforms:
                key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
                await redis_client.delete(key)
            print("All online users cleared from Redis.")

        else:
            # Supprimer les utilisateurs dans Redis pour une plateforme spécifique
            if platform in platforms:
                key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
                await redis_client.delete(key)
                print(f"Online users for platform '{platform}' cleared from Redis.")
            else:
                raise ValueError(f"Invalid platform: {platform}. Available platforms: {', '.join(platforms)}")

    except RedisError as e:
        print(f"Redis Error: {e}")
        raise

    return removed_users

# Fonction pour vérifier si un utilisateur est en ligne en vérifiant Redis et PostgreSQL
async def is_user_online(user_id: int, platform: str) -> bool:
    redis_client = await get_redis_client()
    key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
    # Vérifier dans Redis
    in_redis = await redis_client.sismember(key, user_id)
    if in_redis:
        return True

async def add_user_online(user_id: int, platform: str):
    redis_client = await get_redis_client()
    key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
    
    # Ajouter à Redis
    await redis_client.sadd(key, user_id)
    await redis_client.expire(key, config.USER_ONLINE_TTL)

# Fonction pour récupérer la liste des utilisateurs en ligne pour une plateforme donnée
async def get_online_users(platform: str = 'all') -> dict[str, list[dict]]:
    """
    Récupère la liste des utilisateurs en ligne avec leurs détails (ID, email, prénom, nom)
    pour une plateforme donnée ou toutes les plateformes.
    
    :param platform: La plateforme pour laquelle récupérer les utilisateurs en ligne ('web', 'ios', 'android', etc. ou 'all').
    :return: Un dictionnaire avec les plateformes et les utilisateurs en ligne pour chacune.
    """
    redis_client = await get_redis_client()
    online_users = {}

    if platform == 'all':
        for platform in platforms:
            key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
            
            # Récupérer les IDs des utilisateurs en ligne depuis Redis
            user_ids = await redis_client.smembers(key)
            user_ids = [int(user_id) for user_id in user_ids]
            
            # Récupérer les détails des utilisateurs depuis la base de données
            if user_ids:
                users_details = await User.filter(id__in=user_ids).values("id", "email", "first_name", "last_name")
                online_users[platform] = users_details
            else:
                online_users[platform] = []
    else:
        # Récupérer les utilisateurs pour une plateforme spécifique
        if platform in platforms:
            key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
            
            # Récupérer les IDs des utilisateurs en ligne depuis Redis
            user_ids = await redis_client.smembers(key)
            user_ids = [int(user_id) for user_id in user_ids]
            
            # Récupérer les détails des utilisateurs depuis la base de données
            if user_ids:
                users_details = await User.filter(id__in=user_ids).values("id", "email", "first_name", "last_name")
                online_users[platform] = users_details
            else:
                online_users[platform] = []
        else:
            raise ValueError(f"Invalid platform: {platform}. Available platforms: {', '.join(platforms)}")

    return online_users

async def get_online_users_count_for_platform(platform: str='all') -> int:
    redis_client = await get_redis_client()
    if platform=='all':
        total_count = 0
        for platform in platforms:
            key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
            count = await redis_client.scard(key)
            total_count += count

        return total_count

    key = f"{config.REDIS_ON_LINE_USERS}:{platform}"
    count = await redis_client.scard(key)
    return count

# Mettre à jour la dernière activité de l'utilisateur dans Redis
async def update_last_activity(user_id: int):
    redis_client = await get_redis_client()
    current_time = datetime.now()
    await redis_client.set(f"{config.REDIS_USER_LAST_ACTIVITY}{user_id}", current_time.timestamp())

# Récupérer la dernière activité de l'utilisateur
async def get_last_activity(user_id: int) -> Optional[datetime]:
    redis_client = await get_redis_client()
    last_activity = await redis_client.get(f"{config.REDIS_USER_LAST_ACTIVITY}{user_id}")
    if last_activity:
        return datetime.fromtimestamp(float(last_activity))
    return None