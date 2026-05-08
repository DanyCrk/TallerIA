REGISTER_URL = "/api/v1/auth/register"

VALID_PAYLOAD = {
    "email": "test@example.com",
    "full_name": "Test User",
    "password": "Str0ng!Pass",
}


def test_tc01_register_success(client):
    """TC-01: Registro exitoso."""
    resp = client.post(REGISTER_URL, json=VALID_PAYLOAD)
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "test@example.com"
    assert "id" in data
    assert "hashed_password" not in data


def test_tc02_email_duplicate(client):
    """TC-02: Email duplicado en registro."""
    client.post(REGISTER_URL, json=VALID_PAYLOAD)
    resp = client.post(REGISTER_URL, json=VALID_PAYLOAD)
    assert resp.status_code == 400


def test_tc03_weak_password(client):
    """TC-03: Contraseña débil (sin mayúscula)."""
    payload = {**VALID_PAYLOAD, "password": "weakpassword1!"}
    resp = client.post(REGISTER_URL, json=payload)
    assert resp.status_code == 422


def test_email_normalised_to_lowercase(client):
    """RF-10: Email debe almacenarse en minúsculas."""
    payload = {**VALID_PAYLOAD, "email": "TEST@Example.COM"}
    resp = client.post(REGISTER_URL, json=payload)
    assert resp.status_code == 201
    assert resp.json()["email"] == "test@example.com"


def test_password_not_in_response(client):
    """Seguridad: contraseña nunca debe estar en la respuesta."""
    resp = client.post(REGISTER_URL, json=VALID_PAYLOAD)
    body = resp.text
    assert "Str0ng!Pass" not in body
    assert "hashed_password" not in body
