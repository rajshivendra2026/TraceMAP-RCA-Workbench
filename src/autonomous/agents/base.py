"""Base protocol agent contract."""

from __future__ import annotations


class BaseProtocolAgent:
    protocol = "GENERIC"

    def supports(self, session: dict) -> bool:
        protocols = {str(p).upper() for p in session.get("protocols", [])}
        return self.protocol in protocols

    def analyze(self, session: dict) -> dict | None:  # pragma: no cover - interface
        raise NotImplementedError
