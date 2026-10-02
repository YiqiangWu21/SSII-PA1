from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import datetime
import secrets
from database import models

ph = PasswordHasher()
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
DUMMY_HASH = ph.hash("contrasena_falsa_mitigacion")

def register_user(db: Session, username: str, password_plain: str):
    existing_user = db.query(models.User).filter(models.User.username == username).first()
    if existing_user:
        return {"error": "El usuario ya existe.", "status_code": 409}
    
    hashed_pw = ph.hash(password_plain)
    new_user = models.User(username=username, password_hash=hashed_pw)
    db.add(new_user)
    db.commit()
    return {"success": True, "message": "Usuario registrado correctamente."}

def verify_login(db: Session, username: str, password_plain: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    
    if not user:
        try:
            ph.verify(DUMMY_HASH, password_plain)
        except VerifyMismatchError:
            pass
        return {"error": "Credenciales inválidas", "status_code": 401}

    if user.locked_until and datetime.datetime.utcnow() < user.locked_until:
        return {"error": "Cuenta bloqueada temporalmente", "status_code": 429}

    try:
        ph.verify(user.password_hash, password_plain)
        if ph.check_needs_rehash(user.password_hash):
            user.password_hash = ph.hash(password_plain)
            
        user.failed_login_attempts = 0
        user.locked_until = None
        
        # Generamos un token opaco seguro y lo guardamos en la BBDD
        token = secrets.token_hex(32)
        user.active_token = token
        db.commit()
        
        return {"success": True, "access_token": token}
        
    except VerifyMismatchError:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        db.commit()
        return {"error": "Credenciales inválidas", "status_code": 401}

def process_transaction(db: Session, tx_data: dict):
    # Bloqueamos transferencias negativas o a cero (Solución al error detectado)
    if tx_data.get("amount", 0) <= 0:
        return {"error": "El importe de la transferencia debe ser mayor que cero.", "status_code": 400}
        
    # Asumiendo que tu modelo Transaction coincide con los campos de tx_data
    nueva_tx = models.Transaction(
        tx_id=tx_data["tx_id"],
        origin_account=tx_data["origin_account"],
        destination_account=tx_data["destination_account"],
        amount=tx_data["amount"],
        currency=tx_data["currency"],
        timestamp=tx_data["timestamp"]
    )
    db.add(nueva_tx)
    db.commit()
    return {"status": "registrada", "tx_id": tx_data["tx_id"]}

def validate_and_revoke_token(db: Session, token: str):
    user = db.query(models.User).filter(models.User.active_token == token).first()
    if user:
        user.active_token = None
        db.commit()
        return True
    return False

def get_user_by_token(db: Session, token: str):
    return db.query(models.User).filter(models.User.active_token == token).first()