import sqlalchemy as sa
from sqlalchemy import inspect

# Setup database connection
engine = sa.create_engine('postgresql://timetagger:timetagger@postgres:5432/timetagger')
inspector = inspect(engine)

# Print all tables
print("Tables in the database:")
for table_name in inspector.get_table_names():
    print(f"- {table_name}")
    print("  Columns:")
    for column in inspector.get_columns(table_name):
        print(f"    - {column['name']}: {column['type']}") 