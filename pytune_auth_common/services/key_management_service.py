import threading
import secrets
import string
import psycopg2
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jose import jwt
from pytune_configuration.sync_config_singleton import config, SimpleConfig
from pytune_configuration.root_config import root_config
from simple_logger.logger import get_logger

# S'assurer que la config est chargée
if config is None:
    config = SimpleConfig()

logger = get_logger("auth_common")

class KeyManagementService:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._load_keys()  # 💥 charge les clés directement lors de la 1ère création
        return cls._instance

    def _connect(self):
        return psycopg2.connect(
            user=root_config.CONFIG_MANAGER_USER,
            password=root_config.CONFIG_MANAGER_PWD,
            database=root_config.DB_NAME,
            host=root_config.DB_HOST,
            port=root_config.DB_PORT,
        )

    def _load_keys(self):
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:

                    # --- CURRENT ACCESS ---
                    cur.execute("""
                        SELECT private_key, public_key, passphrase
                        FROM rsa_keys
                        WHERE key_name = 'current_access'
                    """)
                    access = cur.fetchone()
                    if access is None:
                        raise RuntimeError("Missing RSA key: current_access")

                    private_access, public_access, pass_access = access

                    # --- CURRENT REFRESH ---
                    cur.execute("""
                        SELECT private_key, public_key, passphrase
                        FROM rsa_keys
                        WHERE key_name = 'current_refresh'
                    """)
                    refresh = cur.fetchone()
                    if refresh is None:
                        raise RuntimeError("Missing RSA key: current_refresh")

                    private_refresh, public_refresh, pass_refresh = refresh

                    # --- OLD ACCESS ---
                    cur.execute("""
                        SELECT public_key
                        FROM rsa_keys
                        WHERE key_name = 'old_access'
                    """)
                    old_access = cur.fetchone()
                    old_access_key = old_access[0] if old_access else None

                    # --- OLD REFRESH ---
                    cur.execute("""
                        SELECT public_key
                        FROM rsa_keys
                        WHERE key_name = 'old_refresh'
                    """)
                    old_refresh = cur.fetchone()
                    old_refresh_key = old_refresh[0] if old_refresh else None

                    # --- ASSIGN ---
                    self.PRIVATE_ACCESS_KEY = private_access
                    self.PUBLIC_ACCESS_KEY = public_access
                    self.PASS_PHRASE_ACCESS_KEY = pass_access

                    self.PRIVATE_REFRESH_KEY = private_refresh
                    self.PUBLIC_REFRESH_KEY = public_refresh
                    self.PASS_PHRASE_REFRESH_KEY = pass_refresh

                    self.PUBLIC_ACCESS_KEY_OLD = old_access_key
                    self.PUBLIC_REFRESH_KEY_OLD = old_refresh_key

            logger.info("✅ RSA keys successfully loaded from database.")

        except Exception as e:
            logger.critical(f"❌ Failed to load RSA keys: {e}")
            raise RuntimeError("Could not initialize RSA keys.") from e
    
    def _generate_passphrase(self, length=32) -> str:
        return ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))

    def _decrypt_private_key(self, private_key_pem: str, passphrase: str):
        return serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=passphrase.encode(),
            backend=default_backend()
        )

    def sign_jwt(self, payload: dict, key_type: str = "access") -> str:
        if key_type == "access":
            private_key_pem = self.PRIVATE_ACCESS_KEY
            passphrase = self.PASS_PHRASE_ACCESS_KEY
        elif key_type == "refresh":
            private_key_pem = self.PRIVATE_REFRESH_KEY
            passphrase = self.PASS_PHRASE_REFRESH_KEY
        else:
            raise ValueError(f"Invalid key type: {key_type}")

        private_key = self._decrypt_private_key(private_key_pem, passphrase)
        pem_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return jwt.encode(payload, pem_key, algorithm=config.ALGORITHM)

    # 🔒 Rotation de clés désactivée pour l’instant
    # def rotate_keys(self): ...
    # async def notify_key_rotation(...) ...
