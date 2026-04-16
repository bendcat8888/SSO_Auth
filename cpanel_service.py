import os
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass(frozen=True)
class CPanelConfig:
    host: str
    username: str
    password: str = ""
    api_token: str = ""
    port: int = 2083
    verify_tls: bool = True
    access_mode: str = "auto"
    account_username: Optional[str] = None


class CPanelService:
    def __init__(self, config: CPanelConfig) -> None:
        self._config = config

    @classmethod
    def from_env(cls) -> "CPanelService":
        host = os.getenv("CPANEL_HOST", "")
        username = os.getenv("CPANEL_USERNAME", "")
        password = os.getenv("CPANEL_PASSWORD", "")
        api_token = os.getenv("CPANEL_API_TOKEN", "")
        port = int(os.getenv("CPANEL_PORT", "2083"))
        verify_tls = os.getenv("CPANEL_VERIFY_TLS", "true").lower() in {"1", "true", "yes"}
        access_mode = os.getenv("CPANEL_ACCESS_MODE", "auto").strip().lower() or "auto"
        account_username = os.getenv("CPANEL_ACCOUNT", "").strip().lower() or None
        return cls(
            CPanelConfig(
                host=host,
                username=username,
                password=password,
                api_token=api_token,
                port=port,
                verify_tls=verify_tls,
                access_mode=access_mode,
                account_username=account_username,
            )
        )

    def _resolved_access_mode(self) -> str:
        if self._config.access_mode in {"cpanel", "whm"}:
            return self._config.access_mode
        if self._config.account_username or self._config.port in {2086, 2087}:
            return "whm"
        return "cpanel"

    def _auth(self, mode: str) -> dict:
        if not self._config.host or not self._config.username:
            raise RuntimeError("cPanel credentials not configured")

        if self._config.api_token:
            prefix = "whm" if mode == "whm" else "cpanel"
            return {"headers": {"Authorization": f"{prefix} {self._config.username}:{self._config.api_token}"}}

        if not self._config.password:
            raise RuntimeError("cPanel credentials not configured")

        return {"auth": (self._config.username, self._config.password)}

    @staticmethod
    def _join_messages(value: object) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            parts = [str(item).strip() for item in value if str(item).strip()]
            return "; ".join(parts)
        return ""

    @classmethod
    def _extract_result(cls, payload: dict, mode: str) -> dict:
        if mode == "whm":
            metadata = payload.get("metadata") or {}
            if metadata.get("result") != 1:
                reason = metadata.get("reason") or cls._join_messages(metadata.get("output")) or "Unknown WHM error"
                raise RuntimeError(reason)
            payload = ((payload.get("data") or {}).get("uapi") or {})

        result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
        if result.get("status") != 1:
            detail = (
                cls._join_messages(result.get("errors"))
                or cls._join_messages(result.get("messages"))
                or cls._join_messages(result.get("warnings"))
                or cls._join_messages((result.get("metadata") or {}).get("reason"))
                or cls._join_messages(payload.get("error"))
                or cls._join_messages(payload.get("errors"))
                or "Unknown cPanel error"
            )
            raise RuntimeError(detail)
        return result

    async def _list_mailboxes(self, *, domain: str, local_part: str, mode: str, function_name: str) -> list[dict]:
        if mode == "whm":
            if not self._config.account_username:
                raise RuntimeError("CPANEL_ACCOUNT is required for WHM mode")
            url = f"https://{self._config.host}:{self._config.port}/json-api/uapi_cpanel"
            params = {
                "cpanel.module": "Email",
                "cpanel.function": function_name,
                "cpanel.user": self._config.account_username,
                "domain": domain,
                "email": local_part,
            }
        else:
            url = f"https://{self._config.host}:{self._config.port}/execute/Email/{function_name}"
            params = {"domain": domain, "email": local_part}

        if function_name == "list_pops_with_disk":
            params["no_disk"] = 1

        auth_kwargs = self._auth(mode)
        try:
            async with httpx.AsyncClient(verify=self._config.verify_tls, timeout=15) as client:
                resp = await client.get(url, params=params, **auth_kwargs)
                resp.raise_for_status()
                payload = resp.json()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text.strip() or str(exc)
            raise RuntimeError(f"cPanel request failed: {exc.response.status_code} {detail}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Unable to reach cPanel: {exc}") from exc

        result = self._extract_result(payload, mode)
        return result.get("data") or []

    async def mailbox_exists(self, *, email: str, domain: str) -> bool:
        mode = self._resolved_access_mode()
        local_part, _, email_domain = email.strip().lower().partition("@")
        if not local_part or email_domain != domain.strip().lower():
            raise RuntimeError("Invalid email or domain")

        try:
            data = await self._list_mailboxes(
                domain=domain,
                local_part=local_part,
                mode=mode,
                function_name="list_pops_with_disk",
            )
        except RuntimeError as exc:
            if "Unknown cPanel error" not in str(exc):
                raise
            data = await self._list_mailboxes(
                domain=domain,
                local_part=local_part,
                mode=mode,
                function_name="list_pops",
            )

        expected = f"{local_part}@{domain}".lower()
        for row in data:
            record = row or {}
            row_email = record.get("email")
            if isinstance(row_email, str) and "@" not in row_email:
                row_email = f"{row_email}@{domain}"
            if isinstance(row_email, str) and row_email.lower() == expected:
                return True
            login = record.get("login")
            if isinstance(login, str) and login.lower() == expected:
                return True
        return False
