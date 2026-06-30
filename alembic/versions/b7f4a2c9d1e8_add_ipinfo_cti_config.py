"""Add IPinfo CTI config

Revision ID: b7f4a2c9d1e8
Revises: 14b43480c45e
Create Date: 2026-06-29 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7f4a2c9d1e8"
down_revision: Union[str, Sequence[str], None] = "14b43480c45e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("""
        DELETE FROM cti_config
        WHERE code = 'reverse_dns'
        """)
    op.execute("""
        INSERT INTO cti_config (
            code,
            label,
            is_key_required,
            is_active,
            last_validation_status
        )
        VALUES ('ipinfo', 'IPinfo', TRUE, FALSE, 'not_tested')
        ON CONFLICT (code) DO UPDATE
        SET label = EXCLUDED.label,
            is_key_required = EXCLUDED.is_key_required,
            updated_at = NOW()
        """)


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM cti_config WHERE code = 'ipinfo'")
    op.execute("""
        INSERT INTO cti_config (
            code,
            label,
            is_key_required,
            is_active,
            last_validation_status
        )
        VALUES ('reverse_dns', 'Reverse DNS', FALSE, FALSE, 'not_tested')
        ON CONFLICT (code) DO UPDATE
        SET label = EXCLUDED.label,
            is_key_required = EXCLUDED.is_key_required,
            updated_at = NOW()
        """)
