"""Shared pytest fixtures and helpers for the RedKit test suite."""

import pytest
import requests
from requests.structures import CaseInsensitiveDict


@pytest.fixture
def make_response():
    """Factory fixture building real requests.Response objects without network I/O."""

    def _make(
        status: int = 200,
        body: str = "",
        headers: dict | None = None,
        url: str = "https://test.local/page",
    ) -> requests.Response:
        resp = requests.Response()
        resp.status_code = status
        resp.url = url
        resp.headers = CaseInsensitiveDict({"Content-Type": "text/html; charset=utf-8"})
        resp.headers.update(headers or {})
        resp.encoding = "utf-8"
        resp._content = body.encode("utf-8")
        return resp

    return _make
