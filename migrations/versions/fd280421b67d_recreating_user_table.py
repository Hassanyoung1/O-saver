"""Recreating user table

Revision ID: fd280421b67d
Revises: 898d52c954aa
Create Date: 2025-03-15 23:47:02.121202

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fd280421b67d'
down_revision: Union[str, None] = '898d52c954aa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_users_email', table_name='users')
    op.drop_index('ix_users_id', table_name='users')
    op.drop_index('ix_users_phone', table_name='users')
    op.drop_table('users')
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('name', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('email', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('phone', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('password_hash', sa.VARCHAR(), autoincrement=False, nullable=False),
    sa.Column('is_agent', sa.BOOLEAN(), autoincrement=False, nullable=True),
    sa.Column('created_by', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('is_verified', sa.BOOLEAN(), autoincrement=False, nullable=True),
    sa.Column('otp_code', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name='users_created_by_fkey'),
    sa.PrimaryKeyConstraint('id', name='users_pkey')
    )
    op.create_index('ix_users_phone', 'users', ['phone'], unique=True)
    op.create_index('ix_users_id', 'users', ['id'], unique=False)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    # ### end Alembic commands ###
