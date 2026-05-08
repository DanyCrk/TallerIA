from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_register_success():
    response = client.post("/api/v1/auth/register", json={
        "email": "newuser@example.com",
        "full_name": "New User",
        "password": "ValidPass123!"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert "id" in data

def test_register_duplicate_email():
    # First registration
    client.post("/api/v1/auth/register", json={
        "email": "duplicate@example.com",
        "full_name": "User One",
        "password": "ValidPass123!"
    })
    # Second registration with same email
    response = client.post("/api/v1/auth/register", json={
        "email": "duplicate@example.com",
        "full_name": "User Two",
        "password": "ValidPass123!"
    })
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"].lower()

def test_register_weak_password():
    response = client.post("/api/v1/auth/register", json={
        "email": "weak@example.com",
        "full_name": "Weak User",
        "password": "weak"
    })
    assert response.status_code == 422