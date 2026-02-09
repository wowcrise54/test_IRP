"""Add user language preference

Revision ID: 3a9f4f2b6c1a
Revises: d5a720d1b99b
Create Date: 2026-02-06 00:00:00.000000

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '3a9f4f2b6c1a'
down_revision = 'd5a720d1b99b'
branch_labels = None
depends_on = None


def upgrade():
    # Use SQL-level IF NOT EXISTS for reliability during bootstrap.
    op.execute('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS language VARCHAR(8)')
    op.execute('UPDATE "user" SET language = \'en\' WHERE language IS NULL')
    op.execute('ALTER TABLE "user" ALTER COLUMN language SET DEFAULT \'en\'')
    op.execute('ALTER TABLE "user" ALTER COLUMN language SET NOT NULL')


def downgrade():
    op.execute('ALTER TABLE "user" DROP COLUMN IF EXISTS language')
