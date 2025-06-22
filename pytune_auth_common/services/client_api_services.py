from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
import json
from fastapi import HTTPException, status
from pytune_data.models import ClientAPI  
from pytune_data.db import init as init_db
from datetime import datetime

from simple_logger.logger import SimpleLogger, get_logger

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger : SimpleLogger = get_logger("auth_common")

async def create_client_api(
    client_id: str,
    client_secret: str,
    client_name: str,
    redirect_uris: list = None,
    client_type: str = "confidential",
    scope: str = "read write",
    grant_types: str = "authorization_code",
    token_endpoint_auth_method: str = "client_secret_basic",
    contact_email: str = None,
    valid_days: int = 30
) -> ClientAPI:
    """
    Fonction pour créer un client API dans la base de données.

    Args:
        client_id (str): Identifiant unique du client.
        client_secret (str): Secret du client (sera haché).
        redirect_uris (list, optional): Liste des URIs de redirection.
        client_name (str): Nom de l'application cliente.
        client_type (str, optional): Type de client (confidential ou public). Default "confidential".
        scope (str, optional): Scopes autorisés. Default "read write".
        grant_types (str, optional): Types de grant supportés (ex: authorization_code). Default "authorization_code".
        token_endpoint_auth_method (str, optional): Méthode d'authentification à l'endpoint du token. Default "client_secret_basic".
        contact_email (str, optional): Email de contact pour le client API.
        valid_days (int, optional): Nombre de jours avant expiration du client API. Default 30 jours.

    Returns:
        ClientAPI: Instance du client API créée.
    """
    await init_db()
    # Hachage du client_secret pour plus de sécurité
    hashed_client_secret = pwd_context.hash(client_secret)

    # Si redirect_uris est None, initialiser comme une liste vide
    if redirect_uris is None:
        redirect_uris = []

    # Définir valid_until ou le mettre à None si valid_days est None
    valid_until = None
    if valid_days is not None:
        valid_until = datetime.now(timezone.utc) + timedelta(days=valid_days)

    # Création du client API dans la base de données
    try:
        client_api = await ClientAPI.create(
            client_id=client_id,
            client_secret=hashed_client_secret,
            redirect_uris=redirect_uris,
            client_name=client_name,
            client_type=client_type,
            scope=scope,
            grant_types=grant_types,
            token_endpoint_auth_method=token_endpoint_auth_method,
            contact_email=contact_email,
            valid_until=valid_until
        )
    except Exception as e:
        logger.error(f"Error during creation: {e}")
        raise

    return client_api

async def create_client_api_from_dict(client_data: dict) -> ClientAPI:
    """
    Fonction pour créer un client API dans la base de données.

    Args:
        client_data (dict): Dictionnaire contenant les informations du client à créer.
            - client_id: Identifiant unique du client.
            - client_secret: Secret du client (sera haché).
            - redirect_uris: Liste des URIs de redirection.
            - client_name: Nom de l'application cliente.
            - client_type: Type de client (confidential ou public).
            - scope: Scopes autorisés.
            - grant_types: Types de grant supportés (ex: authorization_code).
            - token_endpoint_auth_method: Méthode d'authentification à l'endpoint du token.
            - contact_email: Email de contact pour le client API.
            - valid_days: Nombre de jours avant expiration du client API.

    Returns:
        ClientAPI: Instance du client API créée.
    """
    await init_db()
    # Hachage du client_secret pour plus de sécurité
    hashed_client_secret = pwd_context.hash(client_data["client_secret"])
    if client_data["redirect_uris"] is None:
        client_data["redirect_uris"] = "[]"
    valid_days = client_data.get("valid_days")
    if valid_days is not None:
        valid_until = datetime.now(timezone.utc) + timedelta(days=valid_days)
    else:
        valid_until = None
    # Création du client API dans la base de données
    client_api = await ClientAPI.create(
        client_id=client_data["client_id"],
        client_secret=hashed_client_secret,  # Hacher le client_secret
        redirect_uris=client_data["redirect_uris"],  # Convertir les URI en JSON
        client_name=client_data["client_name"],
        client_type=client_data["client_type"],
        scope=client_data["scope"],
        grant_types=client_data["grant_types"],
        token_endpoint_auth_method=client_data["token_endpoint_auth_method"],
        contact_email=client_data["contact_email"],
        valid_until=valid_until  # Expire après "valid_days" jours
    )

    return client_api

async def authenticate_client_api(client_id: str, client_secret: str) -> ClientAPI:
    """
    Fonction pour authentifier un client API en vérifiant le client_id, le client_secret,
    et si le client a un contrat valide (valid_until).

    Args:
        client_id (str): L'identifiant unique du client.
        client_secret (str): Le secret du client à vérifier.

    Returns:
        ClientAPI: Le client authentifié s'il est valide.

    Raises:
        HTTPException: Si le client_id n'existe pas, si le client_secret est incorrect, 
                       ou si le contrat du client a expiré.
    """

    # Rechercher le client dans la base de données
    client_api = await ClientAPI.get_or_none(client_id=client_id)

    if not client_api:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client_id")

    # Vérifier si le client_secret correspond au secret stocké
    if not pwd_context.verify(client_secret, client_api.client_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client_secret")

    # Vérifier si le contrat du client est toujours valide
    if client_api.valid_until and client_api.valid_until < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Client contract has expired")

    # Si toutes les vérifications passent, retourner le client API
    return client_api

async def update_client_api(client_id: str, update_data: dict)->ClientAPI:
    """
    Met à jour les champs de client_api_instance avec les valeurs présentes dans update_data.

    Args:
        client_api_instance: L'instance de ClientAPI à mettre à jour.
        update_data (dict): Un dictionnaire contenant les champs à mettre à jour.

    Returns:
        client_api_instance: L'instance mise à jour de ClientAPI.
    """
    await init_db()
    client_api_instance = await ClientAPI.get_or_none(client_id=client_id)
    if client_api_instance is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ClientAPI with client_id '{client_id}' not found."
        )
    # Parcourir chaque clé et valeur du dictionnaire update_data
    for field, value in update_data.items():
        # Vérifier si l'instance a cet attribut
        if hasattr(client_api_instance, field):
            setattr(client_api_instance, field, value)

    # Sauvegarder les changements dans la base de données
    
    await client_api_instance.save()

    return client_api_instance
