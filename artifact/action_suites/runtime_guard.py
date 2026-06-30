from __future__ import annotations

from pathlib import Path

from .authorization_verifier import verify_authorization


class ObservationalRunBlocked(RuntimeError):
    pass


def require_authorized(root: Path | str) -> None:
    passed, errors = verify_authorization(root)
    if not passed:
        raise ObservationalRunBlocked(
            "observational action evaluation is fail-closed: " + "; ".join(errors)
        )
