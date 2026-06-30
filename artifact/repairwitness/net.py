"""Policy-constrained HTTP retrieval with content-addressed receipts.

All network access in RepairWitness passes through this module.  The policy rejects
non-HTTPS URLs, embedded credentials, unapproved hosts, oversized responses, and
redirects outside the allowlist.  Callers may inject an opener and sleeper for fully
offline tests.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from .canonical import atomic_write_bytes, atomic_write_json, sha256_bytes


class ResponseLike(Protocol):
    """Subset of ``urllib`` response behavior used by the downloader."""

    headers: Mapping[str, str]
    status: int

    def read(self, size: int = -1) -> bytes: ...

    def geturl(self) -> str: ...

    def __enter__(self) -> ResponseLike: ...

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None: ...


Opener = Callable[..., ResponseLike]
Sleeper = Callable[[float], None]


class NetworkPolicyError(RuntimeError):
    """Raised when a request or response violates a frozen network policy."""


@dataclass(frozen=True)
class NetworkPolicy:
    """Immutable constraints for one family of public resources."""

    allowed_hosts: frozenset[str]
    max_bytes: int = 64 * 1024 * 1024
    timeout_seconds: int = 90
    attempts: int = 3
    user_agent: str = "RepairWitness-reproducer/1.0"
    accepted_media_types: tuple[str, ...] = (
        "application/json",
        "application/octet-stream",
        "application/gzip",
        "text/plain",
        "text/yaml",
        "application/x-yaml",
    )

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise ValueError("network policy requires at least one allowed host")
        if self.max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        if self.attempts < 1:
            raise ValueError("attempts must be positive")
        normalized = frozenset(host.lower().rstrip(".") for host in self.allowed_hosts)
        dns_name = re.compile(
            r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
        )
        if any(not dns_name.fullmatch(host) for host in normalized):
            raise ValueError("allowed hosts must be bare DNS names")
        object.__setattr__(self, "allowed_hosts", normalized)


@dataclass(frozen=True)
class NetworkReceipt:
    """Digest-bound metadata for a successful response."""

    requested_url: str
    final_url: str
    status: int
    media_type: str
    byte_count: int
    sha256: str
    etag: str | None
    last_modified: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status": self.status,
            "media_type": self.media_type,
            "byte_count": self.byte_count,
            "sha256": self.sha256,
            "etag": self.etag,
            "last_modified": self.last_modified,
        }


@dataclass(frozen=True)
class RetrievedBytes:
    content: bytes
    receipt: NetworkReceipt


def _validate_url(url: str, policy: NetworkPolicy) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        raise NetworkPolicyError("only HTTPS URLs are permitted")
    if parsed.username is not None or parsed.password is not None:
        raise NetworkPolicyError("embedded URL credentials are forbidden")
    host = (parsed.hostname or "").lower().rstrip(".")
    if host not in policy.allowed_hosts:
        raise NetworkPolicyError(f"host {host!r} is outside the frozen allowlist")
    try:
        port = parsed.port
    except ValueError as exc:
        raise NetworkPolicyError("URL contains an invalid port") from exc
    if port not in {None, 443}:
        raise NetworkPolicyError("only the default HTTPS port is permitted")
    if parsed.fragment:
        raise NetworkPolicyError("URL fragments are not part of retrievable resources")
    return parsed


def _media_type(headers: Mapping[str, str]) -> str:
    value = headers.get("Content-Type", headers.get("content-type", ""))
    return value.split(";", 1)[0].strip().lower()


def _header(headers: Mapping[str, str], name: str) -> str | None:
    return headers.get(name) or headers.get(name.lower())


def _read_bounded(response: ResponseLike, limit: int) -> bytes:
    declared = _header(response.headers, "Content-Length")
    declared_size: int | None = None
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise NetworkPolicyError("invalid Content-Length header") from exc
        if declared_size < 0 or declared_size > limit:
            raise NetworkPolicyError(
                f"declared response size {declared_size} exceeds limit {limit}"
            )
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(1024 * 1024, limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise NetworkPolicyError(f"response exceeds byte limit {limit}")
        chunks.append(chunk)
    if declared_size is not None and total != declared_size:
        raise NetworkPolicyError(
            f"response length {total} differs from declared Content-Length {declared_size}"
        )
    return b"".join(chunks)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in {408, 425, 429, 500, 502, 503, 504}
    return isinstance(exc, urllib.error.URLError | TimeoutError | OSError)


def fetch_bytes(
    url: str,
    *,
    policy: NetworkPolicy,
    accept: str = "application/json, text/plain;q=0.9, */*;q=0.1",
    opener: Opener | None = None,
    sleeper: Sleeper = time.sleep,
) -> RetrievedBytes:
    """Retrieve bytes under ``policy`` and return a cryptographic receipt."""

    _validate_url(url, policy)
    open_call: Opener = opener or cast(Opener, urllib.request.urlopen)
    last_error: BaseException | None = None
    for attempt in range(policy.attempts):
        request = urllib.request.Request(
            url,
            headers={"Accept": accept, "User-Agent": policy.user_agent},
            method="GET",
        )
        try:
            with open_call(request, timeout=policy.timeout_seconds) as response:
                final_url = response.geturl()
                _validate_url(final_url, policy)
                status = int(getattr(response, "status", 200))
                if status < 200 or status >= 300:
                    raise NetworkPolicyError(f"unexpected HTTP status {status}")
                media_type = _media_type(response.headers)
                if media_type and media_type not in policy.accepted_media_types:
                    raise NetworkPolicyError(f"unexpected response media type {media_type!r}")
                content = _read_bounded(response, policy.max_bytes)
                receipt = NetworkReceipt(
                    requested_url=url,
                    final_url=final_url,
                    status=status,
                    media_type=media_type,
                    byte_count=len(content),
                    sha256=sha256_bytes(content),
                    etag=_header(response.headers, "ETag"),
                    last_modified=_header(response.headers, "Last-Modified"),
                )
                return RetrievedBytes(content=content, receipt=receipt)
        except BaseException as exc:
            if isinstance(exc, KeyboardInterrupt | SystemExit):
                raise
            last_error = exc
            if attempt + 1 >= policy.attempts or not _is_retryable(exc):
                break
            sleeper(0.5 * (2**attempt))
    if last_error is None:  # defensive: a valid policy executes at least one attempt
        raise NetworkPolicyError("request loop terminated without an error")
    raise NetworkPolicyError(
        f"request failed after {policy.attempts} attempt(s): "
        f"{type(last_error).__name__}: {last_error}"
    ) from last_error


def fetch_json(
    url: str,
    *,
    policy: NetworkPolicy,
    opener: Opener | None = None,
    sleeper: Sleeper = time.sleep,
) -> tuple[object, RetrievedBytes]:
    """Retrieve and decode a UTF-8 JSON resource without accepting NaN/Infinity."""

    retrieved = fetch_bytes(
        url,
        policy=policy,
        accept="application/json",
        opener=opener,
        sleeper=sleeper,
    )
    try:
        text = retrieved.content.decode("utf-8")
        payload = json.loads(
            text,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON token {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise NetworkPolicyError(f"response is not strict UTF-8 JSON: {exc}") from exc
    return payload, retrieved


def cache_key(url: str) -> str:
    """Return a stable URL cache key without leaking package names into paths."""

    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def persist_retrieval(
    directory: Path | str,
    retrieved: RetrievedBytes,
    *,
    logical_name: str | None = None,
) -> tuple[Path, Path]:
    """Persist content and receipt atomically under content-addressed names."""

    root = Path(directory)
    key = retrieved.receipt.sha256 if logical_name is None else logical_name
    if not key or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        for character in key
    ):
        raise ValueError("logical_name contains unsafe path characters")
    content_path = root / f"{key}.bin"
    receipt_path = root / f"{key}.receipt.json"
    atomic_write_bytes(content_path, retrieved.content)
    atomic_write_json(receipt_path, retrieved.receipt.to_dict())
    return content_path, receipt_path


def combine_receipts(receipts: Iterable[NetworkReceipt]) -> str:
    """Hash a deterministic sequence of response receipts."""

    rows = [receipt.to_dict() for receipt in receipts]
    rows.sort(key=lambda row: (str(row["requested_url"]), str(row["sha256"])))
    return sha256_bytes(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())


def download_to_file(
    url: str,
    destination: Path | str,
    *,
    policy: NetworkPolicy,
    accept: str = "application/octet-stream, application/gzip",
    opener: Opener | None = None,
    sleeper: Sleeper = time.sleep,
) -> NetworkReceipt:
    """Stream a bounded HTTPS response into an atomically replaced file."""

    _validate_url(url, policy)
    open_call: Opener = opener or cast(Opener, urllib.request.urlopen)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    last_error: BaseException | None = None
    for attempt in range(policy.attempts):
        request = urllib.request.Request(
            url,
            headers={"Accept": accept, "User-Agent": policy.user_agent},
            method="GET",
        )
        try:
            with open_call(request, timeout=policy.timeout_seconds) as response:
                final_url = response.geturl()
                _validate_url(final_url, policy)
                status = int(getattr(response, "status", 200))
                if status < 200 or status >= 300:
                    raise NetworkPolicyError(f"unexpected HTTP status {status}")
                media_type = _media_type(response.headers)
                if media_type and media_type not in policy.accepted_media_types:
                    raise NetworkPolicyError(f"unexpected response media type {media_type!r}")
                declared = _header(response.headers, "Content-Length")
                if declared is not None:
                    try:
                        declared_size = int(declared)
                    except ValueError as exc:
                        raise NetworkPolicyError("invalid Content-Length header") from exc
                    if declared_size < 0 or declared_size > policy.max_bytes:
                        raise NetworkPolicyError(
                            f"declared response size {declared_size} exceeds limit {policy.max_bytes}"
                        )
                digest = hashlib.sha256()
                total = 0
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    prefix=f".{destination_path.name}.",
                    suffix=".partial",
                    dir=destination_path.parent,
                    delete=False,
                ) as output:
                    temporary = Path(output.name)
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > policy.max_bytes:
                            raise NetworkPolicyError(
                                f"response exceeds byte limit {policy.max_bytes}"
                            )
                        digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                if declared is not None and total != declared_size:
                    raise NetworkPolicyError(
                        f"response length {total} differs from declared Content-Length "
                        f"{declared_size}"
                    )
                temporary.replace(destination_path)
                temporary = None
                return NetworkReceipt(
                    requested_url=url,
                    final_url=final_url,
                    status=status,
                    media_type=media_type,
                    byte_count=total,
                    sha256=digest.hexdigest(),
                    etag=_header(response.headers, "ETag"),
                    last_modified=_header(response.headers, "Last-Modified"),
                )
        except BaseException as exc:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
                temporary = None
            if isinstance(exc, KeyboardInterrupt | SystemExit):
                raise
            last_error = exc
            if attempt + 1 >= policy.attempts or not _is_retryable(exc):
                break
            sleeper(0.5 * (2**attempt))
    if last_error is None:  # defensive: a valid policy executes at least one attempt
        raise NetworkPolicyError("download loop terminated without an error")
    raise NetworkPolicyError(
        f"download failed after {policy.attempts} attempt(s): "
        f"{type(last_error).__name__}: {last_error}"
    ) from last_error
