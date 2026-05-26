import asyncio
from logging.config import fileConfig
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context
from src.db.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
target_metadata = Base.metadata

def run_migrations_online():
    connectable = create_async_engine(config.get_main_option("sqlalchemy.url"))
    async def do_run():
        async with connectable.connect() as connection:
            await connection.run_sync(target_metadata.create_all)
    asyncio.run(do_run())

run_migrations_online()
