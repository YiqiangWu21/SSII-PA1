# server/main.py
from fastapi import FastAPI
from database.database import engine, Base

# Importamos los dos enrutadores
from routes import transfer
from routes import auth

from fastapi import Depends
from security.middleware import security_validation
from security.logging_config import setup_security_logging

setup_security_logging()

# Aseguramos la base de datos
Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecBank API - Servidor Principal", dependencies=[Depends(security_validation)])

# Conectamos las rutas al servidor
app.include_router(auth.router)
app.include_router(transfer.router)