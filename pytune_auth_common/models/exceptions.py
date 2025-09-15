class AuthException(Exception):
    """Exception raised for errors in the authentication process."""

class TokenExpiredException(AuthException):
    """Exception raised when a token is expired."""

