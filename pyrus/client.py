from __future__ import annotations

import json
import logging

import requests

logger = logging.getLogger(__name__)


class PyrusClient:
    BASE_URL = "https://pyrus.sovcombank.ru/api/v4"

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers["Content-Type"] = "application/json"

    def _request(self, method: str, endpoint: str, token: str | None = None, data: dict | None = None):
        url = f"{self.BASE_URL}/{endpoint}"
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            resp = self._session.request(method, url, headers=headers, json=data)
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            logger.error("Pyrus request error [%s %s]: %s", method, endpoint, exc)
            raise

    def get_token(self, login: str, security_key: str) -> str:
        resp = self._request("POST", "auth", data={"login": login, "security_key": security_key})
        try:
            return resp.json()["access_token"]
        except (KeyError, json.JSONDecodeError) as exc:
            logger.error("Pyrus: не удалось получить токен: %s", exc)
            raise

    def get_registry(self, form_id: int, login: str, security_key: str) -> list[dict]:
        token = self.get_token(login, security_key)
        resp = self._request("GET", f"forms/{form_id}/register", token=token)
        return resp.json().get("tasks", [])
