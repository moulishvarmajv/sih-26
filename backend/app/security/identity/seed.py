"""Synthetic development identities.

Clearly fake users for local development and tests. The password is never
hard-coded here: callers pass one, and the CLI reads DEV_SEED_PASSWORD from the
environment and refuses to run without it, so no credential is ever committed.

Never run this against anything but a local development database.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from app.core.domain.identity import Clearance, Role
from app.infrastructure.clock import utc_now_iso
from app.security.grants import InMemoryAccessGrantRepository
from app.security.identity.models import AccountStatus, UserAccount
from app.security.identity.passwords import PasswordHasher
from app.security.identity.user_store import SQLiteUserStore

INVESTIGATOR = Role(
    id="ROLE-INVESTIGATOR",
    name="INVESTIGATOR",
    permissions=(
        "VIEW_CASE",
        "VIEW_EVIDENCE",
        "SWITCH_AGENCY_CONTEXT",
        "ANALYZE_EVIDENCE",
        "REANALYZE_EVIDENCE",
    ),
)
ANALYST = Role(
    id="ROLE-ANALYST",
    name="ANALYST",
    # No REANALYZE_EVIDENCE: analysts read and analyse, they do not reprocess.
    permissions=("VIEW_CASE", "VIEW_EVIDENCE", "SWITCH_AGENCY_CONTEXT", "ANALYZE_EVIDENCE"),
)
DEV_ROLES = (INVESTIGATOR, ANALYST)


@dataclass(frozen=True)
class SeedUser:
    user_id: str
    username: str
    display_name: str
    clearance_level: str
    role: Role
    agencies: tuple[str, ...]
    status: AccountStatus = AccountStatus.ACTIVE


DEV_USERS: tuple[SeedUser, ...] = (
    SeedUser("USR-001", "dev.investigator", "Dev Investigator", "L2", INVESTIGATOR, ("POLICE",)),
    SeedUser(
        "USR-002",
        "dev.analyst",
        "Dev Analyst",
        "L1",
        ANALYST,
        ("FINANCIAL_CRIME",),
    ),
    SeedUser(
        "USR-003",
        "dev.disabled",
        "Dev Disabled Account",
        "L1",
        ANALYST,
        (),
        status=AccountStatus.DISABLED,
    ),
)


def seed_development_identities(
    store: SQLiteUserStore,
    hasher: PasswordHasher,
    password: str,
    grants: InMemoryAccessGrantRepository | None = None,
) -> list[UserAccount]:
    """Create the synthetic dev accounts. `password` is supplied by the caller."""
    if not password:
        raise ValueError("a seed password must be provided explicitly")

    for role in DEV_ROLES:
        store.upsert_role(role)

    now = utc_now_iso()
    accounts = []
    for seed in DEV_USERS:
        accounts.append(
            store.create_account(
                user_id=seed.user_id,
                username=seed.username,
                password_hash=hasher.hash(password),
                display_name=seed.display_name,
                status=seed.status,
                clearance=Clearance(
                    level_code=seed.clearance_level, granted_by="DEV-SEED", granted_at=now
                ),
                role_ids=(seed.role.id,),
            )
        )
        if grants is not None:
            for agency_id in seed.agencies:
                grants.grant_agency(seed.user_id, agency_id)
    return accounts


def main() -> int:  # pragma: no cover - operator entry point
    from app.api.dependencies import get_grant_repository, get_password_hasher, get_user_store

    password = os.environ.get("DEV_SEED_PASSWORD", "")
    if not password:
        print("DEV_SEED_PASSWORD is not set; refusing to seed.", file=sys.stderr)
        return 1

    accounts = seed_development_identities(
        get_user_store(), get_password_hasher(), password, get_grant_repository()
    )
    print(f"seeded {len(accounts)} synthetic development accounts")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
