from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings

engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db():
    """FastAPI dependency that yields a database session."""
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    """Create all tables and apply idempotent schema migrations."""
    from .models import Base  # noqa: F401 – side-effect import registers all models

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Idempotent migrations: add columns/tables that didn't exist on older installs
        await conn.execute(text(
            "ALTER TABLE collections ADD COLUMN IF NOT EXISTS parent_id UUID"
        ))
        await conn.execute(text(
            "ALTER TABLE collections ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]'"
        ))
        await conn.execute(text(
            "ALTER TABLE collections ADD COLUMN IF NOT EXISTS notes TEXT"
        ))
