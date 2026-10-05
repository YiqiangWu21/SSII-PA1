from fastapi import FastAPI, Depends

# Importaciones de base de datos y lógica de negocio (Capa 2)
from database.database import engine, Base, SessionLocal
from database import business_logic

# Importaciones de enrutadores modulares
from routes import transfer
from routes import auth

# Importaciones de seguridad (Capa 3)
from security.middleware import security_validation
from security.logging_config import setup_security_logging

# 1. Inicialización de los registros de auditoría
setup_security_logging()

# 2. Creación y aseguramiento del esquema de la base de datos
Base.metadata.create_all(bind=engine)

# 3. Función de inicialización autónoma (sustituye a setup_db.py)
def initialize_default_user():
    """
    Inyecta el usuario por defecto al arrancar el servidor. 
    Abre una sesión temporal y la cierra de forma segura usando el bloque finally.
    """
    db = SessionLocal()
    try:
        # El método register_user ya gestiona internamente si el usuario existe (HTTP 409)
        business_logic.register_user(db, "cliente_prueba", "PasswordSegura123")
    finally:
        db.close()

# Ejecutamos la inyección del usuario antes de levantar la API
initialize_default_user()

# 4. Declaración de la aplicación FastAPI con protección global
app = FastAPI(
    title="SecBank API - Servidor Principal", 
    dependencies=[Depends(security_validation)]
)

# 5. Conexión de las rutas al servidor principal
app.include_router(auth.router)
app.include_router(transfer.router)