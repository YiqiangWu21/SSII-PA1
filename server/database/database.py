# database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Usamos SQLite para la persistencia local. 
# check_same_thread=False es necesario en FastAPI con SQLite.
SQLALCHEMY_DATABASE_URL = "sqlite:///./secbank.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Creamos la fábrica de sesiones para interactuar con la base de datos
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Clase base de la que heredarán todos nuestros modelos de datos
Base = declarative_base()

# Dependencia para inyectar la sesión de base de datos en los endpoints de FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()