"""add_user_profile_photo_fields

Revision ID: 8ac66d253837
Revises: 68f59d5036f1
Create Date: 2025-11-12 19:30:14.767832+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8ac66d253837'
down_revision: Union[str, None] = '68f59d5036f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add profile photo fields to users table
    op.add_column('users', sa.Column('profile_photo_url', sa.String(500), nullable=True, comment='URL relativa: /static/profile-photos/{user_id}.jpg'))
    op.add_column('users', sa.Column('photo_source', sa.String(20), nullable=True, server_default='default', comment="'entra_id', 'upload', 'gravatar', 'default'"))
    op.add_column('users', sa.Column('photo_updated_at', sa.DateTime(timezone=True), nullable=True, comment='Última atualização da foto'))


def downgrade() -> None:
    # Remove profile photo fields
    op.drop_column('users', 'photo_updated_at')
    op.drop_column('users', 'photo_source')
    op.drop_column('users', 'profile_photo_url')
