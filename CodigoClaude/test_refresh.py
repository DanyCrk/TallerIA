REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"
REFRESH_URL = "/api/v1/auth/refresh"

CREDS = {"email": "refresh@example.com", "full_name": "Refresh User", "password": "Str0ng!Pass"}


def _login(client):
    client.post(REGISTER_URL, json=CREDS)
    resp = client.post(LOGIN_URL, json={"email": CREDS["email"], "password": CREDS["password"]})
    return resp.json()


def test_tc07_refresh_valid_token(client):
    """TC-07: Refresh token válido retorna nuevo par de tokens."""
    tokens = _login(client)
    resp = client.post(REFRESH_URL, json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_tc08_refresh_token_reuse(client):
    """TC-08: Reutilización de refresh token ya rotado → 401."""
    tokens = _login(client)
    original_refresh = tokens["refresh_token"]
    # Rotate once
    client.post(REFRESH_URL, json={"refresh_token": original_refresh})
    # Try to reuse the original token
    resp = client.post(REFRESH_URL, json={"refresh_token": original_refresh})
    assert resp.status_code == 401


def test_refresh_new_tokens_differ(client):
    """Cada refresh emite tokens diferentes (rotación real)."""
    tokens = _login(client)
    resp = client.post(REFRESH_URL, json={"refresh_token": tokens["refresh_token"]})
    new_tokens = resp.json()
    assert new_tokens["access_token"] != tokens["access_token"]
    assert new_tokens["refresh_token"] != tokens["refresh_token"]


def test_refresh_invalid_token(client):
    """Refresh con token malformado → 401."""
    resp = client.post(REFRESH_URL, json={"refresh_token": "not.a.valid.token"})
    assert resp.status_code == 401
