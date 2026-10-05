import pytest
import responses

from vulnauto.client import VulnApiClient
from vulnauto.config import Settings
from vulnauto.exceptions import ApiError, AuthError

BASE = "https://vuln.example.com/api"
URL = f"{BASE}/vulnerabilities"


def client(retries=3):
    s = Settings(api_url=BASE, api_token="t0k3n", max_retries=retries)
    return VulnApiClient(s, sleep=lambda _: None)       # no real sleeping in tests


@responses.activate
def test_pagination_follows_cursor():
    responses.get(URL, json={"vulnerabilities": [{"cve_id": "A"}], "next_cursor": "c2"})
    responses.get(URL, json={"vulnerabilities": [{"cve_id": "B"}], "next_cursor": None})
    ids = [v["cve_id"] for v in client().iter_vulnerabilities()]
    assert ids == ["A", "B"]
    assert "cursor=c2" in responses.calls[1].request.url


@responses.activate
def test_sends_bearer_token():
    responses.get(URL, json={"vulnerabilities": []})
    list(client().iter_vulnerabilities())
    assert responses.calls[0].request.headers["Authorization"] == "Bearer t0k3n"


@responses.activate
def test_401_raises_auth_error_without_retry():
    responses.get(URL, status=401)
    with pytest.raises(AuthError):
        list(client().iter_vulnerabilities())
    assert len(responses.calls) == 1


@responses.activate
def test_429_then_success_is_retried():
    responses.get(URL, status=429, headers={"Retry-After": "1"})
    responses.get(URL, json={"vulnerabilities": [{"cve_id": "A"}]})
    assert len(list(client().iter_vulnerabilities())) == 1
    assert len(responses.calls) == 2


@responses.activate
def test_500_exhausts_retries_then_api_error():
    for _ in range(3):
        responses.get(URL, status=500)
    with pytest.raises(ApiError):
        list(client(retries=3).iter_vulnerabilities())
    assert len(responses.calls) == 3


@responses.activate
def test_404_is_not_retried():
    responses.get(URL, status=404)
    with pytest.raises(ApiError):
        list(client().iter_vulnerabilities())
    assert len(responses.calls) == 1
