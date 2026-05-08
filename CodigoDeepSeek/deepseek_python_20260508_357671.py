import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.user import User
from app.core.security import hash_password

client = TestClient(app)

@pytest.fixture
def db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def create_test_user(db):
    user = User(
        email="test@example.com",
        hashed_password=hash_password("ValidPass123!"),
        full_name="Test User"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def test_login_success(db, create_test_user):
    response = client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "ValidPass123!"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_password(db, create_test_user):
    response = client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "WrongPass123!"
    })
    assert response.status_code == 401

def test_account_lockout_after_5_failures(db, create_test_user):
    for _ in range(5):
        response = client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "WrongPass123!"
        })
        assert response.status_code == 401
    
    # 6th attempt should be locked
    response = client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "WrongPass123!"
    })
    assert response.status_code == 403
    assert "locked" in response.json()["detail"].lower()