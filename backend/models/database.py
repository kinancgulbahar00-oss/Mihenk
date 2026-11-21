from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from backend.config import settings

db_url = settings.DATABASE_URL
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
elif db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

connect_args = {}
if db_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    db_url,
    connect_args=connect_args,
    future=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    migrate_ioc_value_index()
    migrate_ioc_last_verdict()
    migrate_ioc_unique()


def migrate_ioc_unique():
    """A-11: onceki surumlerde olusmus yinelenen gosterge kayitlarini birlestirir ve (type, value_hash)
    uzerinde tekil dizin olusturur. Idempotenttir."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    tables = inspector.get_table_names()
    if "iocs" not in tables:
        return
    if "ux_iocs_type_value_hash" in {i["name"] for i in inspector.get_indexes("iocs")}:
        return
    with engine.begin() as conn:
        groups = conn.execute(text(
            "SELECT type, value_hash, MIN(id) FROM iocs WHERE value_hash IS NOT NULL "
            "GROUP BY type, value_hash HAVING COUNT(*) > 1")).fetchall()
        for ioc_type, digest, keep in groups:
            dup_ids = [r[0] for r in conn.execute(
                text("SELECT id FROM iocs WHERE type = :t AND value_hash = :h AND id <> :k"),
                {"t": ioc_type, "h": digest, "k": keep}).fetchall()]
            for dup in dup_ids:
                params = {"k": keep, "d": dup}
                conn.execute(text("UPDATE analysis_results SET ioc_id = :k WHERE ioc_id = :d"), params)
                if "campaign_iocs" in tables:
                    conn.execute(text(
                        "DELETE FROM campaign_iocs WHERE ioc_id = :d AND campaign_id IN "
                        "(SELECT campaign_id FROM (SELECT campaign_id FROM campaign_iocs WHERE ioc_id = :k) AS kept)"), params)
                    conn.execute(text("UPDATE campaign_iocs SET ioc_id = :k WHERE ioc_id = :d"), params)
                for table in ("domains", "ip_addresses", "urls"):
                    conn.execute(text(f"DELETE FROM {table} WHERE ioc_id = :d"), params)
                # Kayitli karar, birlestirilen kayitlarin en yuksegidir (B-08). Duzey de skorla BIRLIKTE tasinir
                # (E-17): yalnizca skor guncellendiginde "skor 86, duzey LOW" gibi tutarsiz kayit olusuyordu.
                conn.execute(text(
                    "UPDATE iocs SET risk_level = (SELECT risk_level FROM iocs WHERE id = :d) WHERE id = :k "
                    "AND (SELECT risk_score FROM iocs WHERE id = :d) > COALESCE(risk_score, -1)"), params)
                conn.execute(text(
                    "UPDATE iocs SET risk_score = (SELECT MAX(risk_score) FROM iocs WHERE id IN (:k, :d)) WHERE id = :k"), params)
                conn.execute(text("DELETE FROM iocs WHERE id = :d"), params)
        conn.execute(text("CREATE UNIQUE INDEX ux_iocs_type_value_hash ON iocs (type, value_hash)"))


def migrate_ioc_last_verdict():
    """B-08: kayitli karar ile son analizin karari ayri sutunlarda tutulur. Idempotent."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "iocs" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("iocs")}
    with engine.begin() as conn:
        if "last_risk_score" not in columns:
            conn.execute(text("ALTER TABLE iocs ADD COLUMN last_risk_score INTEGER"))
        if "last_risk_level" not in columns:
            conn.execute(text("ALTER TABLE iocs ADD COLUMN last_risk_level VARCHAR(20)"))


def migrate_ioc_value_index():
    """Onceki surumlerle olusturulmus veritabanlari icin (Z-02): iocs.value uzerindeki dizin
    kaldirilir, deger sinirsiz metne cevrilir ve SHA-256 ozet sutunu eklenip doldurulur.
    Islem idempotenttir; her acilista guvenle calisir."""
    import hashlib

    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "iocs" not in inspector.get_table_names():
        return
    columns = {c["name"]: c for c in inspector.get_columns("iocs")}
    indexes = {i["name"] for i in inspector.get_indexes("iocs")}
    postgres = engine.dialect.name == "postgresql"
    with engine.begin() as conn:
        if "value_hash" not in columns:
            conn.execute(text("ALTER TABLE iocs ADD COLUMN value_hash VARCHAR(64)"))
        if "ix_iocs_value" in indexes:
            conn.execute(text("DROP INDEX ix_iocs_value"))
        if "ix_iocs_value_hash" not in indexes:
            conn.execute(text("CREATE INDEX ix_iocs_value_hash ON iocs (value_hash)"))
        if postgres and "VARCHAR" in str(columns["value"]["type"]).upper():
            conn.execute(text("ALTER TABLE iocs ALTER COLUMN value TYPE TEXT"))
        rows = conn.execute(text("SELECT id, value FROM iocs WHERE value_hash IS NULL")).fetchall()
        for row_id, value in rows:
            conn.execute(text("UPDATE iocs SET value_hash = :h WHERE id = :i"),
                         {"h": hashlib.sha256((value or "").encode("utf-8")).hexdigest(), "i": row_id})
