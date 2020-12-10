"""Replication config

Revision ID: ae629228373b
Revises: 90b815426c10
Create Date: 2020-12-10 20:38:57.399180+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ae629228373b'
down_revision = '90b815426c10'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('storage_replication_config',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('max_parallel_replication_tasks', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_storage_replication_config'))
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('storage_replication_config')
    # ### end Alembic commands ###
