from __future__ import annotations

import urllib.error
from pathlib import Path
from typing import Mapping

import pytest

from repairwitness.net import (
    NetworkPolicy,
    NetworkPolicyError,
    NetworkReceipt,
    combine_receipts,
    download_to_file,
    fetch_bytes,
    fetch_json,
    persist_retrieval,
)


class FakeResponse:
    def __init__(
        self,
        content: bytes,
        *,
        url: str = "https://example.org/data.json",
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self._content = content
        self._offset = 0
        self._url = url
        self.status = status
        self.headers = dict(headers or {})

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._content) - self._offset
        chunk = self._content[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None


def opener_sequence(*items: object):
    queue = list(items)
    calls: list[str] = []

    def opener(request, timeout: int):
        calls.append(request.full_url)
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    opener.calls = calls  # type: ignore[attr-defined]
    return opener


def policy(**overrides: object) -> NetworkPolicy:
    return NetworkPolicy(frozenset({"example.org"}), **overrides)


def test_fake_response_default_read_and_policy_numeric_guards() -> None:
    assert FakeResponse(b"abc").read() == b"abc"
    for kwargs, message in (
        ({"max_bytes": 0}, "max_bytes"),
        ({"timeout_seconds": 0}, "timeout_seconds"),
        ({"attempts": 0}, "attempts"),
    ):
        with pytest.raises(ValueError, match=message):
            policy(**kwargs)


def test_network_policy_rejects_unsafe_urls_and_invalid_policy() -> None:
    with pytest.raises(ValueError, match="at least one"):
        NetworkPolicy(frozenset())
    with pytest.raises(ValueError, match="bare DNS"):
        NetworkPolicy(frozenset({"bad_host!"}))
    for url, message in (
        ("http://example.org/data.json", "only HTTPS"),
        ("https://user:pass@example.org/data.json", "embedded URL credentials"),
        ("https://evil.example/data.json", "outside the frozen allowlist"),
        ("https://example.org:444/data.json", "default HTTPS port"),
        ("https://example.org/data.json#frag", "fragments"),
    ):
        with pytest.raises(NetworkPolicyError, match=message):
            fetch_bytes(url, policy=policy(), opener=opener_sequence())


def test_fetch_bytes_success_retry_and_receipt_metadata() -> None:
    sleeper_calls: list[float] = []
    opener = opener_sequence(
        urllib.error.URLError("temporary"),
        FakeResponse(
            b'{"ok": true}',
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": "12",
                "ETag": '"abc"',
                "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT",
            },
        ),
    )
    retrieved = fetch_bytes(
        "https://example.org/data.json",
        policy=policy(attempts=2),
        opener=opener,
        sleeper=sleeper_calls.append,
    )
    assert retrieved.content == b'{"ok": true}'
    assert retrieved.receipt.status == 200
    assert retrieved.receipt.media_type == "application/json"
    assert retrieved.receipt.etag == '"abc"'
    assert opener.calls == ["https://example.org/data.json", "https://example.org/data.json"]  # type: ignore[attr-defined]
    assert sleeper_calls == [0.5]


def test_fetch_bytes_rejects_response_contract_violations() -> None:
    cases = [
        (
            FakeResponse(b"{}", headers={"Content-Type": "text/html"}),
            "unexpected response media type",
        ),
        (
            FakeResponse(b"{}", status=404, headers={"Content-Type": "application/json"}),
            "unexpected HTTP status",
        ),
        (
            FakeResponse(b"abc", headers={"Content-Type": "application/json", "Content-Length": "bad"}),
            "invalid Content-Length",
        ),
        (
            FakeResponse(b"abc", headers={"Content-Type": "application/json", "Content-Length": "2"}),
            "differs from declared",
        ),
        (
            FakeResponse(b"abcdef", headers={"Content-Type": "application/json", "Content-Length": "6"}),
            "declared response size",
        ),
    ]
    for response, message in cases:
        with pytest.raises(NetworkPolicyError, match=message):
            fetch_bytes(
                "https://example.org/data.json",
                policy=policy(max_bytes=5),
                opener=opener_sequence(response),
            )


def test_fetch_json_rejects_nonfinite_tokens() -> None:
    with pytest.raises(NetworkPolicyError, match="strict UTF-8 JSON"):
        fetch_json(
            "https://example.org/data.json",
            policy=policy(),
            opener=opener_sequence(
                FakeResponse(
                    b'{"value": NaN}',
                    headers={"Content-Type": "application/json", "Content-Length": "14"},
                )
            ),
        )


def test_persist_retrieval_and_combined_receipt_digest(tmp_path: Path) -> None:
    retrieved = fetch_bytes(
        "https://example.org/data.json",
        policy=policy(),
        opener=opener_sequence(FakeResponse(b"abc", headers={"Content-Type": "text/plain"})),
    )
    content_path, receipt_path = persist_retrieval(tmp_path, retrieved, logical_name="case-1")
    assert content_path.read_bytes() == b"abc"
    assert receipt_path.is_file()
    with pytest.raises(ValueError, match="unsafe path"):
        persist_retrieval(tmp_path, retrieved, logical_name="../escape")

    other = NetworkReceipt(
        requested_url="https://example.org/other",
        final_url="https://example.org/other",
        status=200,
        media_type="text/plain",
        byte_count=1,
        sha256="0" * 64,
        etag=None,
        last_modified=None,
    )
    assert combine_receipts([other, retrieved.receipt]) == combine_receipts([retrieved.receipt, other])


def test_download_to_file_writes_atomically_and_cleans_failed_partial(tmp_path: Path) -> None:
    destination = tmp_path / "downloads" / "payload.bin"
    receipt = download_to_file(
        "https://example.org/data.bin",
        destination,
        policy=policy(),
        opener=opener_sequence(
            FakeResponse(b"payload", headers={"Content-Type": "application/octet-stream"})
        ),
    )
    assert destination.read_bytes() == b"payload"
    assert receipt.byte_count == 7

    with pytest.raises(NetworkPolicyError, match="response exceeds"):
        download_to_file(
            "https://example.org/data.bin",
            destination,
            policy=policy(max_bytes=3),
            opener=opener_sequence(
                FakeResponse(b"payload", headers={"Content-Type": "application/octet-stream"})
            ),
        )
    assert not any(path.name.endswith(".partial") for path in destination.parent.iterdir())
