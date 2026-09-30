# models.py
from sqlalchemy import Column, Integer, String, Float, DateTime
from database.database import Base
import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    # Almacenaremos el hash generado por Argon2id (incluye la sal internamente)
    password_hash = Column(String, nullable=False)
    
    # Campos para mitigar ataques de fuerza bruta
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

class Transaction(Base):
    __tablename__ = "transactions"

    # Usamos el UUIDv4 de la transacción como clave primaria
    tx_id = Column(String, primary_key=True, index=True)
    origin_account = Column(String, nullable=False)
    destination_account = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String, nullable=False)
    
    # Timestamp original enviado por el cliente
    client_timestamp = Column(Integer, nullable=False)
    # Fecha de registro en el servidor para auditoría
    registered_at = Column(DateTime, default=datetime.datetime.utcnow)

class Nonce(Base):
    __tablename__ = "nonces"

    # El Nonce en sí mismo es único
    nonce = Column(String, primary_key=True, index=True)
    # Almacenamos cuándo se registró para poder purgar los antiguos
    timestamp = Column(Integer, nullable=False)