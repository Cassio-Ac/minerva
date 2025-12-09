"""merge_heads

Revision ID: 6a320382c619
Revises: 52b0d7511db7, 20251110_1130
Create Date: 2025-11-10 14:45:53.351224+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6a320382c619'
down_revision: Union[str, None] = ('52b0d7511db7', '20251110_1130')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
