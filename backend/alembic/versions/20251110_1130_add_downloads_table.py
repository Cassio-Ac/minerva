"""add_downloads_table

Revision ID: 20251110_1130
Revises: 20251110_0100
Create Date: 2025-11-10 11:30:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20251110_1130'
down_revision = '20251110_0100'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create downloads table"""
    op.create_table(
        'downloads',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('filename', sa.String(), nullable=False),
        sa.Column('original_name', sa.String(), nullable=False),
        sa.Column('file_type', sa.String(), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column('file_path', sa.String(), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('dashboard_id', sa.String(), nullable=True),
        sa.Column('is_public', sa.Boolean(), default=False),
        sa.Column('download_count', sa.Integer(), default=0),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    )

    # Create indexes
    op.create_index('ix_downloads_filename', 'downloads', ['filename'], unique=True)
    op.create_index('ix_downloads_user_id', 'downloads', ['user_id'])


def downgrade() -> None:
    """Drop downloads table"""
    op.drop_index('ix_downloads_user_id')
    op.drop_index('ix_downloads_filename')
    op.drop_table('downloads')
