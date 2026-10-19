import os
from pathlib import Path


class Config:
    def __init__(self) -> None:
        self.data_dir = Path(os.environ.get("TIM_DATA_DIR", "/data"))
        self.port = int(os.environ.get("TIM_PORT", "8443"))
        self.static_dir = Path(os.environ.get("TIM_STATIC_DIR", Path(__file__).resolve().parent.parent / "static"))
        self.disable_scheduler = os.environ.get("TIM_DISABLE_SCHEDULER", "0") == "1"
        # Cookie "secure" flag; disable only for local plain-HTTP development.
        self.secure_cookies = os.environ.get("TIM_SECURE_COOKIES", "1") == "1"
        self.session_hours = int(os.environ.get("TIM_SESSION_HOURS", "12"))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "tim.db"

    @property
    def secrets_path(self) -> Path:
        return self.data_dir / "secrets.json"

    @property
    def cert_dir(self) -> Path:
        return self.data_dir / "certs"

    @property
    def cert_file(self) -> Path:
        return self.cert_dir / "cert.pem"

    @property
    def key_file(self) -> Path:
        return self.cert_dir / "key.pem"


config = Config()
