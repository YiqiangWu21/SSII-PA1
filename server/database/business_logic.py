from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import datetime
import models

ph = PasswordHasher()

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# Generamos un hash falso al arrancar para usarlo en la mitigación de ataques de tiempo
DUMMY_HASH = ph.hash("contrasena_falsa_mitigacion")

def verify_login(db: Session, username: str, password_plain: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    
    # Mitigación de Enumeración y Timing Attack:
    # Si el usuario no existe, calculamos de todas formas un hash para igualar el tiempo de respuesta.
    if not user:
        try:
            ph.verify(DUMMY_HASH, password_plain)
        except VerifyMismatchError:
            pass
        return {"error": "Credenciales inválidas", "status_code": 401}

    # Control de expiración del bloqueo
    if user.locked_until:
        if datetime.datetime.utcnow() > user.locked_until:
            # El castigo ha expirado: reseteamos contadores ANTES de verificar
            user.failed_login_attempts = 0
            user.locked_until = None
            db.commit()
        else:
            # Sigue bloqueado
            return {"error": "Cuenta bloqueada temporalmente", "status_code": 429}

    # Verificación normal
    try:
        ph.verify(user.password_hash, password_plain)
        
        if ph.check_needs_rehash(user.password_hash):
            user.password_hash = ph.hash(password_plain)

        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()
        return {"success": True, "user_id": user.id}
        
    except VerifyMismatchError:
        user.failed_login_attempts += 1
        
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            db.commit()
            return {"error": "Cuenta bloqueada temporalmente", "status_code": 429}
            
        db.commit()
        return {"error": "Credenciales inválidas", "status_code": 401}