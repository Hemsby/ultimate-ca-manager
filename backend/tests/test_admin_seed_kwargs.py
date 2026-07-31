"""
Guard: every kwarg passed to User(...) by an admin-bootstrap seeding site
must be a mapped attribute of the User model.

SQLAlchemy's declarative constructor raises TypeError on any non-mapped
keyword, so a drifted kwarg (`is_active=True` where the column is `active`)
turns the seeding path into a crash — harmless in backend/init_db.py (a
manual fallback script), destructive in POST /api/v2/system/database/reset,
where the TypeError fired AFTER drop_all() and left a wiped database with no
admin user, masked as a generic "Database reset failed".

The seeding call sites are parsed from source (AST) so a future rename or a
new kwarg is caught without anyone remembering to update this test. No app
or database is needed, so this also runs on hosts where the shared `app`
fixture cannot start.
"""
import ast
from pathlib import Path

import pytest

from models import User

BACKEND_DIR = Path(__file__).resolve().parent.parent

# Every file that seeds the bootstrap admin via User(...).
SEEDING_FILES = [
    BACKEND_DIR / 'init_db.py',
    BACKEND_DIR / 'app.py',
    BACKEND_DIR / 'database_health.py',
    BACKEND_DIR / 'api' / 'v2' / 'system' / 'database.py',
]


def _user_call_kwargs(path):
    """Yield (lineno, {kwarg names}) for every `User(...)` call in the file."""
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == 'User'
        ):
            names = {kw.arg for kw in node.keywords if kw.arg is not None}
            yield node.lineno, names


def _mapped_names():
    return {attr.key for attr in User.__mapper__.attrs}


def test_user_model_has_no_is_active_attribute():
    """The column is `active`; if this ever changes, update the seeders too."""
    mapped = _mapped_names()
    assert 'active' in mapped
    assert 'is_active' not in mapped


@pytest.mark.parametrize('path', SEEDING_FILES, ids=lambda p: p.name)
def test_seeding_call_sites_only_use_mapped_kwargs(path):
    mapped = _mapped_names()
    calls = list(_user_call_kwargs(path))
    assert calls, f"expected at least one User(...) call in {path}"
    for lineno, names in calls:
        unknown = names - mapped
        assert not unknown, (
            f"{path.name}:{lineno} passes non-mapped kwargs {sorted(unknown)} "
            f"to User(...) — SQLAlchemy will raise TypeError when this runs"
        )


def test_seeding_kwargs_construct_a_user():
    """Belt and braces: the exact kwarg shape used by the fixed seeders must
    construct without TypeError and land on the right attributes."""
    user = User(
        username='seed-guard',
        email='seed-guard@example.test',
        password_hash='x',
        role='admin',
        active=True,
        force_password_change=True,
        totp_exempt=True,
    )
    assert user.active is True
    assert user.force_password_change is True
    assert user.totp_exempt is True
