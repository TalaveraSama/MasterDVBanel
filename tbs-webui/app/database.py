"""Motor y sesiones de SQLAlchemy (SQLite por defecto).

SQLite se usa en modo **WAL** para que los hilos de trabajo (monitor de señal,
escaneo) puedan leer mientras el proceso principal escribe.

La inicialización es perezosa: `configure()` fija el motor a partir de los
ajustes actuales e `init_db()` crea las tablas. Esto permite que los tests (y
cualquier cambio de `TBS_DATABASE_URL`) configuren la base de datos antes del
primer uso real.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings

logger = logging.getLogger(__name__)

engine: Engine | None = None
SessionLocal: sessionmaker[Session] | None = None
_url: str | None = None

_connect_args: dict = {}


def configure(url: str | None = None, echo: bool = False) -> Engine:
    """Crea (o recrea) el motor y la factoría de sesiones."""
    global engine, SessionLocal, _url, _connect_args

    settings = get_settings()
    resolved = url or settings.resolved_database_url()
    if engine is not None and _url == resolved:
        return engine

    if engine is not None:  # pragma: no cover - sólo al reconfigurar
        engine.dispose()

    _url = resolved
    connect_args: dict = {}
    if resolved.startswith("sqlite"):
        # check_same_thread=False: cada hilo crea su propia sesión.
        connect_args = {"check_same_thread": False, "timeout": 30.0}
        if resolved.startswith("sqlite:///") and ":memory:" not in resolved:
            db_path = Path(resolved.replace("sqlite:///", "", 1))
            db_path.parent.mkdir(parents=True, exist_ok=True)
    _connect_args = connect_args

    engine = create_engine(
        resolved,
        echo=echo,
        future=True,
        connect_args=connect_args,
        pool_pre_ping=True,
    )
    SessionLocal = sessionmaker(
        bind=engine, autoflush=False, expire_on_commit=False, future=True
    )
    logger.debug("Motor de base de datos configurado: %s", resolved)
    return engine


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection, _record) -> None:  # pragma: no cover - depende del driver
    """Activa WAL, claves foráneas y busy_timeout en conexiones SQLite."""
    module = type(dbapi_connection).__module__
    if "sqlite" not in module:
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=10000")
    finally:
        cursor.close()


def get_engine() -> Engine:
    """Motor actual (lo crea si aún no existe)."""
    if engine is None:
        return configure()
    return engine


def get_sessionmaker() -> sessionmaker[Session]:
    """Factoría de sesiones actual."""
    if SessionLocal is None:
        configure()
    assert SessionLocal is not None  # para el verificador de tipos
    return SessionLocal


def _ensure_columns(engine: Engine) -> None:
    """Añade columnas nuevas a tablas ya existentes (SQLite no las migra sola).

    `create_all` solo crea tablas que faltan: si una tabla ya existe y el modelo
    gana una columna, hay que añadirla a mano. Se comprueba `PRAGMA
    table_info` y se hace `ALTER TABLE ... ADD COLUMN` (SQLite lo soporta).
    """
    from sqlalchemy import inspect, text

    # (tabla, columna, definicion SQL)
    columnas_nuevas = [
        ("services", "cam_name", "VARCHAR(48)"),
        ("newcamd_accounts", "timeout_s", "INTEGER NOT NULL DEFAULT 8"),
        ("newcamd_accounts", "disable_emm", "BOOLEAN NOT NULL DEFAULT 1"),
        ("newcamd_accounts", "deskey_enc", "TEXT NOT NULL DEFAULT ''"),
    ]
    inspector = inspect(engine)
    tablas = set(inspector.get_table_names())
    with engine.begin() as conexion:
        for tabla, columna, definicion in columnas_nuevas:
            if tabla not in tablas:
                continue
            existentes = {fila[1] for fila in conexion.execute(text(f"PRAGMA table_info({tabla})"))}
            if columna in existentes:
                continue
            try:
                conexion.execute(text(f"ALTER TABLE {tabla} ADD COLUMN {columna} {definicion}"))
                logger.info("Migración: %s.%s añadida", tabla, columna)
            except Exception:  # pragma: no cover - tabla sin soporte de ALTER
                logger.warning("No se pudo añadir %s.%s", tabla, columna, exc_info=True)


def init_db(url: str | None = None) -> Engine:
    """Configura el motor, crea las tablas que falten y migra columnas nuevas."""
    from . import models  # noqa: F401  (registra los modelos en el metadata)

    db_engine = configure(url)
    models.Base.metadata.create_all(bind=db_engine)
    _ensure_columns(db_engine)
    logger.info("Base de datos lista: %s", _url)
    return db_engine


def get_session() -> Iterator[Session]:
    """Dependencia FastAPI: una sesión por petición."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Sesión con commit/rollback automático para hilos de trabajo."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def now() -> float:
    """Marca de tiempo actual (helper para logs rápidos)."""
    import time

    return time.time()
