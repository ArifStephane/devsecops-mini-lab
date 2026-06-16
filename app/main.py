"""
Application cible du mini-lab de sécurité DevSecOps.
API REST minimaliste exposant trois endpoints représentatifs
d'une application cloud-native réelle.
"""

from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
import os
import logging

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://appuser:apppassword@db:5432/appdb"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Base de données
# ---------------------------------------------------------------------------

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(String(1024))


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Schémas Pydantic
# ---------------------------------------------------------------------------

class ItemCreate(BaseModel):
    name: str
    description: str | None = None


class ItemResponse(BaseModel):
    id: int
    name: str
    description: str | None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Application FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Target API — DevSecOps Mini-Lab",
    description="Application cible utilisée pour l'expérimentation sécurité.",
    version="1.0.0",
)


@app.get("/health")
def health_check():
    """Endpoint de lecture : vérification de l'état de l'application."""
    return {"status": "healthy", "service": "target-api"}


@app.get("/items/{item_id}", response_model=ItemResponse)
def read_item(item_id: int, db: Session = Depends(get_db)):
    """Endpoint de lecture : récupération d'un item par identifiant."""
    item = db.query(Item).filter(Item.id == item_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    logger.info(f"Item {item_id} retrieved")
    return item


@app.post("/items", response_model=ItemResponse, status_code=201)
def create_item(item: ItemCreate, db: Session = Depends(get_db)):
    """Endpoint d'écriture : création d'un item en base de données."""
    db_item = Item(name=item.name, description=item.description)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    logger.info(f"Item created with id={db_item.id}")
    return db_item


@app.get("/admin/status")
def admin_status(db: Session = Depends(get_db)):
    """
    Endpoint administratif : état de la base de données.
    En production, cet endpoint serait protégé par authentification.
    """
    try:
        result = db.execute(text("SELECT COUNT(*) FROM items")).scalar()
        return {
            "database": "connected",
            "item_count": result,
            "db_url": DATABASE_URL.split("@")[-1],  # masque les credentials
        }
    except Exception as e:
        logger.error(f"Database error: {e}")
        raise HTTPException(status_code=503, detail="Database unavailable")
