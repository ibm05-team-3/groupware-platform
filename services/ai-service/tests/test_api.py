import pytest
from fastapi.testclient import TestClient

from app.llm import get_chat_model
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_task_routes_to_menu(client: TestClient) -> None:
    response = client.post("/tasks", json={"message": "연차 메뉴가 어디 있나요"})
    assert response.status_code == 200
    body = response.json()
    assert body["specialist"] == "menu"
    assert body["plan"]
    assert "메뉴" in body["output"]


def test_compliance_report(client: TestClient) -> None:
    response = client.post("/compliance/reports")
    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["code"] for item in items] == [
        "four_insurances",
        "annual_leave_promotion",
    ]
    assert all(item["status"] == "no_data" for item in items)


def test_chat_model_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GOOGLE_API_KEY"):
        get_chat_model()
