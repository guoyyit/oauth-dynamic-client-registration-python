"""Client lifecycle state machine.

States:

* ``active``    - usable in authorization/token flows
* ``suspended`` - temporarily disabled, may be reactivated or revoked
* ``revoked``   - permanently revoked; normal updates cannot reactivate,
                  only the independent recovery flow may restore it
* ``deleted``   - soft-deleted and terminal

The recovery flow is intentionally separate from the regular state
transition endpoint.
"""

from __future__ import annotations

from app.errors import ERR_INVALID_STATE_TRANSITION, RegistrationError

STATE_ACTIVE = "active"
STATE_SUSPENDED = "suspended"
STATE_REVOKED = "revoked"
STATE_DELETED = "deleted"

ALL_STATES = frozenset(
    {STATE_ACTIVE, STATE_SUSPENDED, STATE_REVOKED, STATE_DELETED}
)

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    STATE_ACTIVE: frozenset({STATE_SUSPENDED, STATE_REVOKED, STATE_DELETED}),
    STATE_SUSPENDED: frozenset({STATE_ACTIVE, STATE_REVOKED, STATE_DELETED}),
    STATE_REVOKED: frozenset({STATE_DELETED}),
    STATE_DELETED: frozenset(),
}

# Independent recovery flow: only a revoked client may be recovered, and it
# returns to the suspended state (never straight back to active).
RECOVERABLE_STATES = frozenset({STATE_REVOKED})
RECOVERY_TARGET = STATE_SUSPENDED


def is_known_state(state: str) -> bool:
    return state in ALL_STATES


def can_transition(current: str, target: str) -> bool:
    """Return True when *current -> target* is an allowed normal transition."""
    if current == target:
        return False
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def ensure_transition(current: str, target: str) -> None:
    """Raise unless *current -> target* is allowed."""
    if not is_known_state(target):
        raise RegistrationError(
            ERR_INVALID_STATE_TRANSITION,
            f"unknown target lifecycle state: {target!r}",
            400,
        )
    if not can_transition(current, target):
        raise RegistrationError(
            ERR_INVALID_STATE_TRANSITION,
            f"illegal lifecycle transition: {current!r} -> {target!r}",
            409,
        )


def can_recover(current: str) -> bool:
    return current in RECOVERABLE_STATES


def recovery_target(current: str) -> str:
    """Return the state produced by the independent recovery flow."""
    if not can_recover(current):
        raise RegistrationError(
            ERR_INVALID_STATE_TRANSITION,
            f"client in state {current!r} cannot be recovered",
            409,
        )
    return RECOVERY_TARGET
