from fastapi import Request
from urllib.parse import urlparse, urlunparse

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
