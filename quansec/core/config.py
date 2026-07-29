import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://quansec_user:CHANGE_ME@localhost:5432/quansec")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "change-this-in-production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_HOURS: int = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

    # IPsec
    VICI_SOCKET: str = os.getenv("VICI_SOCKET", "/var/run/charon.vici")
    IPSEC_POLL_INTERVAL: int = int(os.getenv("IPSEC_POLL_INTERVAL", "5"))

    # TLS
    NGINX_ACCESS_LOG: str = os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")
    TLS_POLL_INTERVAL: int = int(os.getenv("TLS_POLL_INTERVAL", "3"))

    # SSH
    SSH_AUTH_LOG: str = os.getenv("SSH_AUTH_LOG", "/var/log/auth.log")
    SSHD_CONFIG: str = os.getenv("SSHD_CONFIG", "/etc/ssh/sshd_config")
    SSH_POLL_INTERVAL: int = int(os.getenv("SSH_POLL_INTERVAL", "5"))

    # VPN
    WG_INTERFACE: str = os.getenv("WG_INTERFACE", "wg0")
    VPN_POLL_INTERVAL: int = int(os.getenv("VPN_POLL_INTERVAL", "5"))

settings = Settings()
