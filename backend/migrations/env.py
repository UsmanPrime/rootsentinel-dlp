"""Connection URL comes from validated environment; never print it."""
from alembic import context

from app.db import Database, Base
from app import models  # noqa: F401
from app import gateway_models  # noqa: F401
from app.settings import Settings

config = context.config
settings = config.attributes.get("settings") or Settings.from_environment()
settings.prepare_storage()

if context.is_offline_mode():
    context.configure(url=settings.database_url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    db = Database(settings.database_url)
    with db.engine.connect() as connection:
        # SQLite: one transaction per migration, so a migration that rebuilds a referenced table can switch
        # foreign keys off before it writes anything (PRAGMA foreign_keys is a no-op inside a transaction).
        context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True,
                          transaction_per_migration=connection.dialect.name == "sqlite")
        with context.begin_transaction():
            context.run_migrations()
    db.engine.dispose()
