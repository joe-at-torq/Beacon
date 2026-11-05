"""First-run initialisation: data dir, secrets, TLS certificate, database and default admin."""

import datetime as dt
import ipaddress
import logging
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import history
from app.config import config
from app.db import init_engine, session_scope
from app.models import User
from app.security import hash_password, load_secrets

log = logging.getLogger("beacon.bootstrap")


def ensure_certificate() -> None:
    if config.cert_file.exists() and config.key_file.exists():
        return
    config.cert_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hostname = socket.gethostname()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Beacon Self-Signed"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Beacon")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName(hostname),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    config.key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    config.key_file.chmod(0o600)
    config.cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log.info("Generated self-signed TLS certificate in %s", config.cert_dir)


def seed_admin() -> None:
    with session_scope() as db:
        if db.query(User).count() == 0:
            db.add(User(username="admin", password_hash=hash_password("admin"), role="admin",
                        must_change_password=True))
            log.info("Created default admin user (admin/admin)")


def backfill_history() -> None:
    with session_scope() as db:
        n = history.backfill(db)
    if n:
        log.info("Created baseline history for %d observable(s)", n)


def init_app_state(db_url: str | None = None) -> None:
    config.data_dir.mkdir(parents=True, exist_ok=True)
    load_secrets()
    init_engine(db_url or f"sqlite:///{config.db_path}")
    seed_admin()
    backfill_history()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config.data_dir.mkdir(parents=True, exist_ok=True)
    ensure_certificate()
    init_app_state()


if __name__ == "__main__":
    main()
