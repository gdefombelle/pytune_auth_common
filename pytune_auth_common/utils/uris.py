from typing import Optional
from fastapi import Request
from urllib.parse import urlparse, urlunparse
from pytune_configuration.sync_config_singleton import config, SimpleConfig

config = config or SimpleConfig()

# Fonction pour normaliser l'URI en ignorant les ports par défaut
def normalize_uri_ignore_port(uri):
    parsed_uri = urlparse(uri)
    # Reconstruire l'URI en ignorant le port
    normalized_netloc = parsed_uri.hostname  # Utiliser uniquement l'hôte sans le port
    normalized_uri = urlunparse((parsed_uri.scheme, normalized_netloc, parsed_uri.path, parsed_uri.params, parsed_uri.query, parsed_uri.fragment))
    return normalized_uri

# perform base uri based on current protocol and port
def get_base_url(request: Request, redirect_uri: str = None) -> str:
    # Déterminer le protocole à partir de la requête
    protocol = "https" if request.url.scheme == "https" else "http"

    # Déterminer l'hôte et le port directement depuis la requête
    host = request.client.host  # Par défaut, prend l'adresse client (0.0.0.0 remplacée par une IP concrète)
    port = request.url.port if request.url.port else (443 if protocol == "https" else 80)

    # Ajuster `redirect_uri` pour correspondre à l'URL de base de la requête
    if redirect_uri:
        if redirect_uri.startswith("http://") or redirect_uri.startswith("https://"):
            # Si `redirect_uri` est complet, remplacer le protocole et le port localement si nécessaire
            if "localhost" in redirect_uri or "127.0.0.1" in redirect_uri:
                return redirect_uri.replace("http://", f"{protocol}://").replace(":8000", f":{port}")
            return redirect_uri  # Laisser inchangé si l'URL est complète et valide
        else:
            # Construire l'URI complet à partir des informations de la requête
            redirect_uri = f"{protocol}://{host}:{port}{redirect_uri}"

    # Construire et retourner l'URL de base
    if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
        return f"{protocol}://{host}"
    return f"{protocol}://{host}:{port}"

def get_public_base_url(request: Optional[Request] = None) -> str:
    """
    URL publique “front-facing” pour les liens envoyés par email, etc.

    Priorité :
    1. config.PUBLIC_BASE_URL (ex: https://pytune.com)
    2. fallback sur get_base_url(request) si dispo
    """
    public = getattr(config, "PUBLIC_BASE_URL", None)
    if public:
        return public.rstrip("/")

    if request is not None:
        return get_base_url(request)

    # Fallback ultime (dev sans request) – tu peux lever une exception si tu préfères
    return ""

from typing import Optional  # si pas déjà importé

# ...

def get_public_oauth_base_url(request: Optional[Request] = None) -> str:
    """
    Retourne l'URL publique de l'API OAuth, utilisée dans les liens envoyés par email.

    Priorité :
    1. config.PUBLIC_OAUTH_BASE_URL (ex: https://oauth.pytune.com)
    2. config.PUBLIC_BASE_URL (fallback éventuel)
    3. get_base_url(request) (fallback ultime)
    """
    public = getattr(config, "PUBLIC_OAUTH_BASE_URL", None) or getattr(config, "PUBLIC_BASE_URL", None)
    if public:
        return public.rstrip("/")

    if request is not None:
        return get_base_url(request)

    return ""