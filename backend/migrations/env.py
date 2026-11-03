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
        context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    db.engine.dispose()
