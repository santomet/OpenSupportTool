from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# The default is with SQLite
SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False} # these connect_args only for SQLite
)

# MySQL example (you need apt install python3-mysqldb)
# Note that some (most of the free ones) providers limit the length of row to 767 bytes. We need more than that!
# Also MySQL often does not support VARCHAR with dynamic size of
# SQLALCHEMY_DATABASE_URL = "mysql://user:pass@db4free.net/db"
#
# engine = create_engine(
#     SQLALCHEMY_DATABASE_URL
# )

# Example with Postgres (you need apt install python3-psycopg2)
# SQLALCHEMY_DATABASE_URL = "postgresql://user:pass@db.fi.muni.cz:5432/pgdb"
# engine = create_engine(
#     SQLALCHEMY_DATABASE_URL
# )
# ....

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
