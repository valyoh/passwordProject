"""Add is_compromised and expiry_date to Password

Revision ID: ac5e97451b55
Revises: 
Create Date: 2024-10-16 09:05:15.391669

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ac5e97451b55'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('vault_users')
    with op.batch_alter_table('password', schema=None) as batch_op:
        batch_op.add_column(sa.Column('username', sa.String(length=150), nullable=False))
        batch_op.add_column(sa.Column('is_compromised', sa.Boolean(), nullable=False))
        batch_op.add_column(sa.Column('expiry_date', sa.Date(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('password', schema=None) as batch_op:
        batch_op.drop_column('expiry_date')
        batch_op.drop_column('is_compromised')
        batch_op.drop_column('username')

    op.create_table('vault_users',
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.Column('vault_id', sa.INTEGER(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['vault_id'], ['vault.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'vault_id')
    )
    # ### end Alembic commands ###
