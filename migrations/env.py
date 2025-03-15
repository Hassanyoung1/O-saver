import os
from sqlalchemy import engine_from_config, pool
from logging.config import fileConfig
from alembic import context
from app.core.config import settings
from app.core.database import Base

# Load Alembic Config
config = context.config
fileConfig(config.config_file_name)

# Set the database URL
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Target metadata for 'autogenerate' feature
target_metadata = Base.metadata

def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    context.configure(url=settings.DATABASE_URL, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(config.get_section(config.config_ini_section), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
