REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"

CREDENTIALS = {
    "email": "user@example.com",
    "full_name": "Login User",
    "password": "Str0ng!Pass",
}


def _register(client):
    client.post(REGISTER_URL, json=CREDENTIALS)


def test_tc04_login_success(client):
    """TC-04: Login exitoso retorna tokens."""
    _register(client)
    resp = client.post(LOGIN_URL, json={"email": CREDENTIALS["email"], "password": CREDENTIALS["password"]})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_tc05_wrong_password(client):
    """TC-05: Login con contraseña incorrecta → 401."""
    _register(client)
    resp = client.post(LOGIN_URL, json={"email": CREDENTIALS["email"], "password": "WrongPass1!"})
    assert resp.status_code == 401


def test_tc06_account_lockout(client):
    """TC-06: Bloqueo tras 5 intentos fallidos → 403."""
    _register(client)
    for _ in range(5):
        client.post(LOGIN_URL, json={"email": CREDENTIALS["email"], "password": "BadPass1!"})
    resp = client.post(LOGIN_URL, json={"email": CREDENTIALS["email"], "password": CREDENTIALS["password"]})
    assert resp.status_code == 403
    assert "locked" in resp.json()["detail"].lower()


def test_login_unknown_email(client):
    """Login con email no registrado → 401 (nunca 404 para no revelar existencia)."""
    resp = client.post(LOGIN_URL, json={"email": "nobody@example.com", "password": "Str0ng!Pass"})
    assert resp.status_code == 401


def test_login_email_case_insensitive(client):
    """RF-10: Login debe funcionar independientemente de mayúsculas en el email."""
    _register(client)
    resp = client.post(LOGIN_URL, json={"email": "USER@EXAMPLE.COM", "password": CREDENTIALS["password"]})
    assert resp.status_code == 200
