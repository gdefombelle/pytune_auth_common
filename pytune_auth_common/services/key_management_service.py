# services.key_management_service.py
import asyncio
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import secrets
import string
from jose import jwt
from pytune_configuration.redis_config import redis_client, get_redis_client
from pytune_configuration.postgres_service import PostgresService
from simple_logger.logger import get_logger, SimpleLogger
from pytune_configuration.sync_config_singleton import config, SimpleConfig

if config is None:
    config = SimpleConfig()

logger : SimpleLogger = get_logger()

# Singleton class
class KeyManagementService:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    async def initialize(self):
        # Récupère le pool de connexions du service Postgres
        await logger.ainfo("Iinitialize PostgressServie Connextion Pool")
        if PostgresService.get_config_manager_pool() is None:
            await PostgresService.create_pools()
        self._config_manager_pool = PostgresService.get_config_manager_pool()

        self._async_lock = asyncio.Lock()  # Verrou asynchrone pour la gestion de concurrence
        # Charger les clés lors de l'initialisation
        await self._initialize_keys()


    async def _initialize_keys(self):
        """
        Initialise les clés en les chargeant depuis la base de données.
        """
        try:
            await self.load_keys_from_db()
        except Exception as e:
            await logger.acritical(f"Failed to initialize keys: {e}")
            raise RuntimeError("Key initialization failed.")
        
    async def load_keys_from_db(self):
        """
        Charger les clés RSA et passphrases depuis la base de données PostgreSQL.
        """
        try:

            async with self._config_manager_pool.acquire() as conn:
                async with conn.transaction():
                    # Charger les clés actuelles
                    current_access_key = await conn.fetchrow(
                        "SELECT private_key, public_key, passphrase FROM rsa_keys WHERE key_name = 'current_access'"
                    )
                    current_refresh_key = await conn.fetchrow(
                        "SELECT private_key, public_key, passphrase FROM rsa_keys WHERE key_name = 'current_refresh'"
                    )

                    # Charger les anciennes clés publiques
                    old_access_key = await conn.fetchrow(
                        "SELECT public_key FROM rsa_keys WHERE key_name = 'old_access'"
                    )
                    old_refresh_key = await conn.fetchrow(
                        "SELECT public_key FROM rsa_keys WHERE key_name = 'old_refresh'"
                    )

                    # Mettre à jour les clés et passphrases dans la configuration
                    self.PRIVATE_ACCESS_KEY = current_access_key["private_key"]
                    self.PUBLIC_ACCESS_KEY = current_access_key["public_key"]
                    self.PASS_PHRASE_ACCESS_KEY = current_access_key["passphrase"]

                    self.PRIVATE_REFRESH_KEY = current_refresh_key["private_key"]
                    self.PUBLIC_REFRESH_KEY = current_refresh_key["public_key"]
                    self.PASS_PHRASE_REFRESH_KEY = current_refresh_key["passphrase"]

                    # Mettre à jour seulement les anciennes clés publiques
                    self.PUBLIC_ACCESS_KEY_OLD = old_access_key["public_key"]
                    self.PUBLIC_REFRESH_KEY_OLD = old_refresh_key["public_key"]
            
            await logger.ainfo("Keys have been successfully loaded")
        except Exception as e:
            await logger.acritical(f"Could not load Keys: {e}")
            raise RuntimeError(f"Error loading keys from database: {e}")
    
    def _generate_passphrase(self, length: int = 32) -> str:
        """
        Génère une phrase secrète aléatoire pour protéger les clés privées.
        """
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def _decrypt_private_key(self, private_key_pem: str, passphrase: str):
        """
        Déchiffre une clé privée protégée par une passphrase.
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),  # Clé privée encodée en bytes
            password=passphrase.encode(),  # Passphrase encodée en bytes
            backend=default_backend()
        )
        return private_key

    def sign_jwt(self, payload: dict, key_type: str = "access") -> str:
        """
        Génère un JWT signé en utilisant une clé privée chargée depuis la base de données.
        """

        if key_type == "access":
            private_key_pem = self.PRIVATE_ACCESS_KEY
            passphrase = self.PASS_PHRASE_ACCESS_KEY
        elif key_type == "refresh":
            private_key_pem = self.PRIVATE_REFRESH_KEY
            passphrase = self.PASS_PHRASE_REFRESH_KEY
        else:
            raise ValueError("Type de clé invalide pour la signature.")

        # Déchiffrer la clé privée avec la passphrase
        private_key = self._decrypt_private_key(private_key_pem, passphrase)

        # Convertir la clé privée déchiffrée au format PEM
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Signer le JWT
        token = jwt.encode(payload, pem_private_key, algorithm=config.ALGORITHM)
        return token

    async def rotate_keys(self):
        """
        Rotate the RSA keys in the database.
        """

        async with self._async_lock:  # Acquérir le verrou avant d'exécuter la fonction
            async with PostgresService.get_config_manager_pool().acquire() as conn:
                async with conn.transaction():
                    # Supprimer les anciennes clés (seules les clés publiques sont gardées)
                    await conn.execute("""
                        DELETE FROM rsa_keys
                        WHERE key_name = 'old_access' OR key_name = 'old_refresh'
                    """)

                    # Renommer les clés actuelles en anciennes (mettre à blanc les champs privés)
                    await conn.execute("""
                        UPDATE rsa_keys
                        SET key_name = CASE 
                            WHEN key_name = 'current_access' THEN 'old_access'
                            WHEN key_name = 'current_refresh' THEN 'old_refresh'
                        END,
                        private_key = '', passphrase = '' -- Mettre à blanc la clé privée et la passphrase pour les anciennes clés
                        WHERE key_name = 'current_access' OR key_name = 'current_refresh'
                    """)

                    # Générer de nouvelles clés
                    new_private_access_key, new_public_access_key, new_passphrase_access = self._generate_key_pair()
                    new_private_refresh_key, new_public_refresh_key, new_passphrase_refresh = self._generate_key_pair()

                    # Insérer les nouvelles clés dans la base de données
                    await conn.execute("""
                        INSERT INTO rsa_keys (key_name, private_key, public_key, passphrase)
                        VALUES 
                        ('current_access', $1, $2, $3),
                        ('current_refresh', $4, $5, $6)
                    """, new_private_access_key, new_public_access_key, new_passphrase_access,
                         new_private_refresh_key, new_public_refresh_key, new_passphrase_refresh)

                    # Notifier toutes les instances de l'API que les clés ont été rotatées
                    await redis_client.publish("config_change", "keys_rotated")
            return new_passphrase_access, new_passphrase_refresh

    def _generate_key_pair(self):
        """
        Génère une paire de clés RSA et une passphrase associée.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        passphrase = self._generate_passphrase()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        ).decode('utf-8')
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return private_key_pem, public_key_pem, passphrase

    async def _get_key(self, key_name: str) -> dict:
        """
        Récupère les informations d'une clé par son nom dans la base de données.
        """
        async with self._config_manager_pool.acquire() as conn:
            result = await conn.fetchrow("""
                SELECT private_key, public_key, passphrase FROM rsa_keys WHERE key_name = $1
            """, key_name)

            if result:
                return {
                    "private_key": result["private_key"],
                    "public_key": result["public_key"],
                    "passphrase": result["passphrase"]
                }
            else:
                raise ValueError(f"Key {key_name} not found in the database.")

    async def _delete_key(self, key_name: str):
        """
        Supprime une clé par son nom de la base de données.
        """
        async with self._config_manager_pool.acquire() as conn:
            await conn.execute("DELETE FROM rsa_keys WHERE key_name = $1", key_name)

    async def close(self):
        """
        Ferme les ressources associées, si nécessaire.
        """
        pass



#### Key rotation non web clients notification
connected_clients = {}
async def notify_key_rotation(user_id: int, access_token: str, refresh_token: str):
    """
    Notify the user via WebSocket about key rotation and send the new tokens.
    """
    if user_id in connected_clients:
        for websocket in connected_clients[user_id]:
            await websocket.send_json({
                "event": "key_rotation",
                "access_token": access_token,
                "refresh_token": refresh_token
            })


key_service = KeyManagementService()
# Au bas du fichier services/key_management_service.py

key_service = KeyManagementService()

async def initialize_key_service():
    """
    Initialisation implicite lors de l'importation.
    """
    await key_service.initialize()

