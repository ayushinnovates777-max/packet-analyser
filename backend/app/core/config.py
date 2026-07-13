import os

class Settings:
    PROJECT_NAME: str = "PacketLens AI"

    # --- Upload limits ---
    MAX_UPLOAD_SIZE: int = 50 * 1024 * 1024   # 50 MB hard cap
    MIN_UPLOAD_SIZE: int = 24                  # Minimum valid pcap header size
    UPLOAD_DIR: str = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "uploads"
    )

    # --- Allowed file types ---
    ALLOWED_EXTENSIONS: list = [".pcap", ".pcapng", ".cap"]
    ALLOWED_CONTENT_TYPES: list = [
        "application/vnd.tcpdump.pcap",
        "application/x-pcapng",
        "application/octet-stream",  # many browsers send this for pcap files
    ]

    # --- Rate limiting ---
    RATE_LIMIT_UPLOAD: str = "5/minute"   # 5 uploads per IP per minute
    RATE_LIMIT_READ:   str = "60/minute"  # 60 reads per IP per minute

    # --- Security ---
    ALLOWED_ORIGINS: list = [
        "*", # Allow Netlify and Localhost
    ]
    MAX_FILENAME_LENGTH: int = 128

settings = Settings()
