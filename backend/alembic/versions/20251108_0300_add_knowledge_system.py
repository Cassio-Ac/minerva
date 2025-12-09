"""add knowledge system

Revision ID: 004_knowledge_system
Revises: 003_mcp_servers
Create Date: 2025-11-08 03:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '004_knowledge_system'
down_revision = '003_mcp_servers'
branch_labels = None
depends_on = None


def upgrade():
    # Create index_contexts table
    op.create_table(
        'index_contexts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('es_server_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('index_pattern', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('field_descriptions', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('query_examples', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('business_context', sa.Text(), nullable=True),
        sa.Column('tips', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_index_contexts_id', 'index_contexts', ['id'], unique=True)
    op.create_index('ix_index_contexts_index_pattern', 'index_contexts', ['index_pattern'], unique=False)
    op.create_index('ix_index_contexts_es_server_id', 'index_contexts', ['es_server_id'], unique=False)

    # Create knowledge_documents table
    op.create_table(
        'knowledge_documents',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('category', sa.String(), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('related_indices', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_knowledge_documents_id', 'knowledge_documents', ['id'], unique=True)
    op.create_index('ix_knowledge_documents_title', 'knowledge_documents', ['title'], unique=False)
    op.create_index('ix_knowledge_documents_category', 'knowledge_documents', ['category'], unique=False)


def downgrade():
    op.drop_index('ix_knowledge_documents_category', table_name='knowledge_documents')
    op.drop_index('ix_knowledge_documents_title', table_name='knowledge_documents')
    op.drop_index('ix_knowledge_documents_id', table_name='knowledge_documents')
    op.drop_table('knowledge_documents')

    op.drop_index('ix_index_contexts_es_server_id', table_name='index_contexts')
    op.drop_index('ix_index_contexts_index_pattern', table_name='index_contexts')
    op.drop_index('ix_index_contexts_id', table_name='index_contexts')
    op.drop_table('index_contexts')
