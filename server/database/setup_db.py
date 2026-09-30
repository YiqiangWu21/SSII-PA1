from database.database import SessionLocal, engine
from database import business_logic, models

models.Base.metadata.create_all(bind=engine)

def init_test_user():
    db = SessionLocal()
    try:
        print("Conectando a la base de datos...")
        resultado = business_logic.register_user(db, "cliente_prueba", "PasswordSegura123")
        print("Resultado del registro:", resultado)
    finally:
        db.close()

if __name__ == "__main__":
    init_test_user()