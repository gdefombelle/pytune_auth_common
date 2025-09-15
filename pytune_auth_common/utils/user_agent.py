platforms = ["web", "ios", "android", "macos", "windows", "linux"]
def get_platform_from_user_agent(user_agent: str) -> str:
    user_agent = user_agent.lower()

    # Détection des navigateurs web (priorité sur les plateformes)
    if "chrome" in user_agent or "safari" in user_agent or "firefox" in user_agent or "mozilla" in user_agent:
        return "web"

    # Détection des appareils iOS
    if "iphone" in user_agent or "ipad" in user_agent:
        return "ios"

    # Détection des appareils Android
    elif "android" in user_agent:
        return "android"

    # Détection des appareils macOS
    elif "macintosh" in user_agent or "mac os x" in user_agent:
        return "macos"

    # Détection des appareils Windows
    elif "windows" in user_agent:
        return "windows"

    # Détection des appareils Linux
    elif "linux" in user_agent:
        return "linux"

    # Valeur par défaut si la plateforme est inconnue
    else:
        return "unknown"

