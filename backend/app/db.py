"""One session per unit of work. Alembic, not create_all, owns the schema."""
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.types import DateTime, TypeDecorator


def uid() -> str:
    return str(uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("Timestamp must include timezone")
        return value.astimezone(timezone.utc) if value else None

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


class Base(DeclarativeBase):
    pass


class Database:
    def __init__(self, url: str):
        args = {"check_same_thread": False, "timeout": 15} if url.startswith("sqlite:") else {}
        # A small pool for one worker on a free database: at most 2 idle and 4 open connections. Connections are
        # replaced after 280 s (below the usual 300 s idle cut-off of hosted PostgreSQL) and checked on checkout.
        # Neither setting makes a database call while the application is idle: both act only on checkout.
        self.engine = create_engine(url, connect_args=args, hide_parameters=True, pool_pre_ping=True,
                                    pool_size=2, max_overflow=2, pool_recycle=280)
        if self.engine.dialect.name == "sqlite":
            @event.listens_for(self.engine, "connect")
            def configure(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA busy_timeout=15000")
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def transaction(self):
        with self.sessions.begin() as session:
            yield session
