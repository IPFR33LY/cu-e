"""empty message

Revision ID: 5400f917095b
Revises: 4dea02caf29f
Create Date: 2018-04-14 15:21:28.863000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5400f917095b'
down_revision = '4dea02caf29f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('killmails',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('solar_system', sa.Integer(), nullable=True),
    sa.Column('killmail_time', sa.String(length=20000, convert_unicode=True), nullable=True),
    sa.Column('attackers', sa.String(length=20000), nullable=True),
    sa.Column('zkb', sa.String(length=20000), nullable=True),
    sa.Column('victim', sa.String(length=20000), nullable=True),
    sa.Column('killmail_id', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('killmails')
    # ### end Alembic commands ###