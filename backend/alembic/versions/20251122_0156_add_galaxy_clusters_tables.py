"""add_galaxy_clusters_tables

Revision ID: 6847286b8ed4
Revises: 89c585eb75f3
Create Date: 2025-11-22 01:56:01.530789+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6847286b8ed4'
down_revision: Union[str, None] = '89c585eb75f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create galaxy_clusters table
    op.create_table(
        'galaxy_clusters',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('galaxy_type', sa.String(length=50), nullable=False),
        sa.Column('uuid_galaxy', sa.String(length=100), nullable=False),
        sa.Column('value', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('country', sa.String(length=2), nullable=True),
        sa.Column('attribution_confidence', sa.Integer(), nullable=True),
        sa.Column('synonyms', sa.JSON(), nullable=True),
        sa.Column('refs', sa.JSON(), nullable=True),
        sa.Column('suspected_state_sponsor', sa.String(length=100), nullable=True),
        sa.Column('suspected_victims', sa.JSON(), nullable=True),
        sa.Column('target_category', sa.JSON(), nullable=True),
        sa.Column('type_of_incident', sa.JSON(), nullable=True),
        sa.Column('targeted_sector', sa.JSON(), nullable=True),
        sa.Column('motive', sa.Text(), nullable=True),
        sa.Column('malware_type', sa.String(length=50), nullable=True),
        sa.Column('raw_meta', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('uuid_galaxy')
    )

    # Create indexes for galaxy_clusters
    op.create_index('idx_galaxy_type', 'galaxy_clusters', ['galaxy_type'])
    op.create_index('idx_galaxy_value', 'galaxy_clusters', ['value'])
    op.create_index('idx_galaxy_country', 'galaxy_clusters', ['country'])
    op.create_index('idx_galaxy_type_value', 'galaxy_clusters', ['galaxy_type', 'value'])
    op.create_index('idx_galaxy_country_type', 'galaxy_clusters', ['country', 'galaxy_type'])
    op.create_index('idx_galaxy_uuid', 'galaxy_clusters', ['uuid_galaxy'])

    # Create galaxy_relationships table
    op.create_table(
        'galaxy_relationships',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('source_cluster_id', sa.UUID(), nullable=False),
        sa.Column('dest_cluster_uuid', sa.String(length=100), nullable=False),
        sa.Column('relationship_type', sa.String(length=50), nullable=False),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for galaxy_relationships
    op.create_index('idx_relationship_source', 'galaxy_relationships', ['source_cluster_id'])
    op.create_index('idx_relationship_dest', 'galaxy_relationships', ['dest_cluster_uuid'])
    op.create_index('idx_relationship_type', 'galaxy_relationships', ['relationship_type'])
    op.create_index('idx_relationship_source_dest', 'galaxy_relationships', ['source_cluster_id', 'dest_cluster_uuid'])
    op.create_index('idx_relationship_type_source', 'galaxy_relationships', ['relationship_type', 'source_cluster_id'])


def downgrade() -> None:
    # Drop galaxy_relationships table and indexes
    op.drop_index('idx_relationship_type_source', table_name='galaxy_relationships')
    op.drop_index('idx_relationship_source_dest', table_name='galaxy_relationships')
    op.drop_index('idx_relationship_type', table_name='galaxy_relationships')
    op.drop_index('idx_relationship_dest', table_name='galaxy_relationships')
    op.drop_index('idx_relationship_source', table_name='galaxy_relationships')
    op.drop_table('galaxy_relationships')

    # Drop galaxy_clusters table and indexes
    op.drop_index('idx_galaxy_uuid', table_name='galaxy_clusters')
    op.drop_index('idx_galaxy_country_type', table_name='galaxy_clusters')
    op.drop_index('idx_galaxy_type_value', table_name='galaxy_clusters')
    op.drop_index('idx_galaxy_country', table_name='galaxy_clusters')
    op.drop_index('idx_galaxy_value', table_name='galaxy_clusters')
    op.drop_index('idx_galaxy_type', table_name='galaxy_clusters')
    op.drop_table('galaxy_clusters')
