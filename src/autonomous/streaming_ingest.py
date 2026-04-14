"""Streaming ingest abstractions for near real-time RCA."""

from __future__ import annotations

from collections import defaultdict


class InMemoryStreamSource:
    """Simple queue-like stream source for tests and embedded use."""

    def __init__(self, items: list[dict] | None = None):
        self.items = list(items or [])

    def push(self, item: dict) -> None:
        self.items.append(item)

    def poll(self, max_items: int = 100) -> list[dict]:
        batch = self.items[:max_items]
        self.items = self.items[max_items:]
        return batch


class StreamingIngestor:
    """Groups parsed packet events into protocol buckets suitable for correlation."""

    def __init__(self):
        self.buffer = defaultdict(list)

    def ingest(self, packet: dict) -> None:
        protocol = str(packet.get("protocol", "generic")).lower()
        self.buffer[protocol].append(packet)

    def flush(self) -> dict:
        payload = dict(self.buffer)
        self.buffer.clear()
        return payload
