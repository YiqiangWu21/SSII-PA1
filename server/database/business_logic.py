# business_logic.py
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import datetime
from database import models

# Inicializamos el hasher de Argon2id (es el algoritmo por defecto en argon2-cffi)
# Genera automáticamente una sal única y aleatoria por cada contraseña.
ph = PasswordHasher()

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

def register_user(db: Session, username: str, password_plain: str):
    """
    Registra un nuevo usuario aplicando Argon2id a la contraseña.
    """
    # Verificamos si el usuario ya existe
    existing_user = db.query(models.User).filter(models.User.username == username).first()
    if existing_user:
        return {"error": "El usuario ya existe."}
    
    # Generamos el hash robusto
    hashed_password = ph.hash(password_plain)
    
    # Guardamos en la base de datos
    new_user = models.User(username=username, password_hash=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Usuario registrado correctamente."}

def verify_login(db: Session, username: str, password_plain: str):
    """
    Verifica las credenciales mitigando ataques de fuerza bruta.
    """
    user = db.query(models.User).filter(models.User.username == username).first()
    
    if not user:
        return {"error": "Credenciales inválidas"} # Mensaje genérico por seguridad

    # 1. Comprobar si la cuenta está bloqueada temporalmente
    if user.locked_until and user.locked_until > datetime.datetime.utcnow():
        return {"error": "Cuenta bloqueada temporalmente", "status_code": 429}

    # 2. Verificar la contraseña con Argon2id
    try:
        ph.verify(user.password_hash, password_plain)
        
        # Si la contraseña es correcta y la función de hash necesita actualizarse (rehash), lo hacemos aquí
        if ph.check_needs_rehash(user.password_hash):
            user.password_hash = ph.hash(password_plain)

        # Login exitoso: reseteamos los intentos fallidos
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()
        return {"success": True, "user_id": user.id}
        
    except VerifyMismatchError:
        # Contraseña incorrecta: incrementamos el contador de fallos
        user.failed_login_attempts += 1
        
        # Si supera el límite, bloqueamos la cuenta
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            db.commit()
            return {"error": "Cuenta bloqueada temporalmente", "status_code": 429}
            
        db.commit()
        return {"error": "Credenciales inválidas"}

def process_transaction(db: Session, tx_data: dict):
    """
    Registra la transacción en la base de datos.
    IMPORTANTE: Esta función asume que la Capa 3 ya validó el HMAC y el Nonce.
    """
    # Comprobar que el tx_id no esté repetido en la base de datos
    existing_tx = db.query(models.Transaction).filter(models.Transaction.tx_id == tx_data["tx_id"]).first()
    if existing_tx:
        return {"error": "Transacción duplicada (tx_id ya existe)", "status_code": 409}

    # Crear el registro de la transacción
    new_tx = models.Transaction(
        tx_id=tx_data["tx_id"],
        origin_account=tx_data["origin_account"],
        destination_account=tx_data["destination_account"],
        amount=tx_data["amount"],
        currency=tx_data["currency"],
        client_timestamp=tx_data["timestamp"]
    )
    
    db.add(new_tx)
    db.commit()
    db.refresh(new_tx)
    
    return {"status": "registrada", "tx_id": new_tx.tx_id}