from unittest.mock import AsyncMock, patch

from app.core.security import generate_reset_token, hash_reset_token
from app.models.user import User

REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"
RESET_REQUEST_URL = "/api/v1/auth/password-reset/request"
RESET_CONFIRM_URL = "/api/v1/auth/password-reset/confirm"
ME_URL = "/api/v1/auth/me"

CREDS = {"email": "reset@example.com", "full_name": "Reset User", "password": "Str0ng!Pass"}


def _register_and_login(client):
    client.post(REGISTER_URL, json=CREDS)
    resp = client.post(LOGIN_URL, json={"email": CREDS["email"], "password": CREDS["password"]})
    return resp.json()


def test_tc09_reset_request_existing_email(client):
    """TC-09: Solicitud con email registrado → 200 OK."""
    client.post(REGISTER_URL, json=CREDS)
    with patch("app.services.auth_service._send_reset_email", new_callable=AsyncMock):
        resp = client.post(RESET_REQUEST_URL, json={"email": CREDS["email"]})
    assert resp.status_code == 200


def test_tc10_reset_request_nonexistent_email(client):
    """TC-10: Solicitud con email NO registrado → 200 OK (respuesta neutra)."""
    resp = client.post(RESET_REQUEST_URL, json={"email": "nobody@example.com"})
    assert resp.status_code == 200


def test_tc11_reset_confirm_expired_token(client, db):
    """TC-11: Reset con token expirado → 400."""
    from datetime import datetime, timezone
    client.post(REGISTER_URL, json=CREDS)
    user = db.query(User).filter(User.email == CREDS["email"]).first()
    plain = generate_reset_token()
    user.reset_token = hash_reset_token(plain)
    user.reset_token_exp = datetime(2000, 1, 1, tzinfo=timezone.utc)  # already expired
    db.commit()

    resp = client.post(RESET_CONFIRM_URL, json={"token": plain, "new_password": "NewStr0ng!Pass"})
    assert resp.status_code == 400


def test_reset_full_flow(client, db):
    """Flujo completo: solicitar → confirmar → login con nueva contraseña."""
    client.post(REGISTER_URL, json=CREDS)
    user = db.query(User).filter(User.email == CREDS["email"]).first()

    plain = generate_reset_token()
    from datetime import datetime, timedelta, timezone
    user.reset_token = hash_reset_token(plain)
    user.reset_token_exp = datetime.now(timezone.utc) + timedelta(minutes=30)
    db.commit()

    resp = client.post(RESET_CONFIRM_URL, json={"token": plain, "new_password": "NewStr0ng!Pass"})
    assert resp.status_code == 200

    login_resp = client.post(LOGIN_URL, json={"email": CREDS["email"], "password": "NewStr0ng!Pass"})
    assert login_resp.status_code == 200


def test_tc12_me_valid_token(client):
    """TC-12: GET /me con token válido → perfil de usuario."""
    tokens = _register_and_login(client)
    resp = client.get(ME_URL, headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == CREDS["email"]
    assert "hashed_password" not in data


def test_tc13_me_no_token(client):
    """TC-13: GET /me sin token → 401."""
    resp = client.get(ME_URL)
    assert resp.status_code == 401


def test_me_invalid_token(client):
    """GET /me con token inválido → 401."""
    resp = client.get(ME_URL, headers={"Authorization": "Bearer bad.token.here"})
    assert resp.status_code == 401
