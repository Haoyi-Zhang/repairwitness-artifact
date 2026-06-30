"""Deterministic infrastructure for action-separating security-advisory studies."""

from .authorization_verifier import verify_authorization
from .model import Action, ActionKind, BlockerCode, Edge, ReleaseUniverse
from .runtime_guard import ObservationalRunBlocked, require_authorized
from .suite import KernelStats, SuiteCertificate, solve_exact, solve_greedy, verify_certificate

__all__ = [
    "Action",
    "ActionKind",
    "BlockerCode",
    "Edge",
    "ReleaseUniverse",
    "KernelStats",
    "SuiteCertificate",
    "ObservationalRunBlocked",
    "require_authorized",
    "solve_exact",
    "solve_greedy",
    "verify_authorization",
    "verify_certificate",
]
