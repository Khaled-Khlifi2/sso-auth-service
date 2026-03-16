"""app/totp_utils.py — 2FA TOTP avec pyotp + QR code + codes de secours bcrypt."""
import base64
import io
import json
import secrets

import pyotp
import qrcode
from passlib.context import CryptContext

from app.config import settings

_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Secret et URI ─────────────────────────────────────────────
def new_totp_secret() -> str:
    """Génère un secret TOTP aléatoire (base32, 32 caractères)."""
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, email: str) -> str:
    """Construit l'URI otpauth:// pour le QR code."""
    return pyotp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=settings.TOTP_ISSUER,
    )


def totp_qr_base64(secret: str, email: str) -> str:
    """
    Génère le QR code en image PNG encodée base64.
    Utilisation dans le frontend :
        <img src="data:image/png;base64,{{ qr_image_base64 }}" />
    """
    uri = totp_provisioning_uri(secret, email)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ── Vérification ──────────────────────────────────────────────
def verify_totp_code(secret: str, code: str) -> bool:
    """
    Vérifie un code TOTP avec une tolérance de ±1 intervalle (30 s).
    Utilise pyotp.TOTP.verify() qui est constant-time.
    """
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


# ── Codes de secours ──────────────────────────────────────────
def generate_backup_codes(n: int = 8) -> tuple[list[str], list[str]]:
    """
    Génère n codes de secours au format XXXX-XXXX.

    Retourne:
        plain_codes  — montrer à l'utilisateur UNE SEULE FOIS
        hashed_codes — stocker en base (bcrypt, usage unique)
    """
    plain, hashed = [], []
    for _ in range(n):
        raw  = secrets.token_hex(4).upper()
        code = f"{raw[:4]}-{raw[4:]}"
        plain.append(code)
        hashed.append(_ctx.hash(code.replace("-", "")))
    return plain, hashed


def verify_backup_code(code: str, hashed_json: str) -> tuple[bool, str]:
    """
    Vérifie un code de secours et le consomme (usage unique).

    Args:
        code        : code saisi par l'utilisateur (ex : "A3F2-B89C")
        hashed_json : JSON list des hashes stockés en base

    Retourne:
        (valide, nouveau_json_sans_code_consommé)
    """
    try:
        hashed = json.loads(hashed_json)
    except Exception:
        return False, hashed_json

    normalized = code.strip().replace("-", "").replace(" ", "").upper()
    for i, h in enumerate(hashed):
        if _ctx.verify(normalized, h):
            remaining = hashed[:i] + hashed[i + 1:]
            return True, json.dumps(remaining)

    return False, hashed_json
