"""add llm providers

Revision ID: 002_llm_providers
Revises: 001_initial
Create Date: 2025-11-07 17:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_llm_providers'
down_revision = '001_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create llm_providers table
    op.create_table(
        'llm_providers',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('provider_type', sa.String(), nullable=False),
        sa.Column('model_name', sa.String(), nullable=False),
        sa.Column('api_key_encrypted', sa.String(), nullable=False),
        sa.Column('api_base_url', sa.String(), nullable=True),
        sa.Column('temperature', sa.Float(), nullable=False, server_default='0.1'),
        sa.Column('max_tokens', sa.Integer(), nullable=False, server_default='4000'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('extra_config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # Create index on provider_type
    op.create_index('ix_llm_providers_provider_type', 'llm_providers', ['provider_type'])

    # Create index on is_active
    op.create_index('ix_llm_providers_is_active', 'llm_providers', ['is_active'])

    # Create index on is_default
    op.create_index('ix_llm_providers_is_default', 'llm_providers', ['is_default'])

    # Create trigger to update updated_at
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
        $$ language 'plpgsql';
    """)

    op.execute("""
        CREATE TRIGGER update_llm_providers_updated_at
            BEFORE UPDATE ON llm_providers
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS update_llm_providers_updated_at ON llm_providers")
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column()")
    op.drop_index('ix_llm_providers_is_default', table_name='llm_providers')
    op.drop_index('ix_llm_providers_is_active', table_name='llm_providers')
    op.drop_index('ix_llm_providers_provider_type', table_name='llm_providers')
    op.drop_table('llm_providers')
