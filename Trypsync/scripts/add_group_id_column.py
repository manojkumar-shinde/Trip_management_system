"""
Simple script to add nullable group_id column to trip table for SQLite without Alembic.
Run: python scripts/add_group_id_column.py
"""
import os, sys
# ensure project root is on sys.path when running from scripts/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, db
import sqlalchemy as sa
from sqlalchemy import inspect

with app.app_context():
    inspector = inspect(db.engine)
    cols = [c['name'] for c in inspector.get_columns('trip')]
    if 'group_id' in cols:
        print('trip.group_id already exists; nothing to do')
    else:
        print('Adding group_id column to trip table')
        # SQLite limited ALTER support — use a transaction with CREATE TABLE AS
        # Approach: create a new temporary table with the extra column, copy data, drop old, rename new
        conn = db.engine.connect()
        trans = conn.begin()
        try:
            # reflect current table
            metadata = sa.MetaData()
            metadata.reflect(bind=db.engine)
            trip = metadata.tables['trip']
            # build create table statement for new table
            new_columns = []
            for col in trip.columns:
                new_columns.append(sa.Column(col.name, col.type, primary_key=col.primary_key, nullable=col.nullable))
            # add group_id
            new_columns.append(sa.Column('group_id', sa.Integer(), nullable=True))
            new_table = sa.Table('trip_new', metadata)
            for c in new_columns:
                new_table.append_column(c)
            new_table.create(bind=conn)
            # copy data
            col_names = ','.join([c.name for c in trip.columns])
            conn.execute(sa.text(f"INSERT INTO trip_new ({col_names}) SELECT {col_names} FROM trip"))
            # drop old table and rename
            conn.execute(sa.text('DROP TABLE trip'))
            conn.execute(sa.text('ALTER TABLE trip_new RENAME TO trip'))
            trans.commit()
            print('Migration completed')
        except Exception as e:
            trans.rollback()
            print('Migration failed:', e)
        finally:
            conn.close()
