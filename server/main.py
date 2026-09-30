from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

# Los imports ahora apuntan a la carpeta 'database'
from database.database import engine, get_db, Base
from database import business_logic
from database import models

# Crear las tablas al iniciar
Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecBank API")

class LoginRequest(BaseModel):
    username: str
    password: str

class TransferRequest(BaseModel):
    tx_id: str
    origin_account: str
    destination_account: str
    amount: float
    currency: str
    timestamp: int

@app.post("/auth/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    resultado = business_logic.verify_login(db, request.username, request.password)
    if "error" in resultado:
        raise HTTPException(status_code=resultado.get("status_code", 401), detail=resultado["error"])
    return {"access_token": "TOKEN_PENDIENTE", "token_type": "bearer"}

@app.post("/transfer")
def transfer(request: TransferRequest, db: Session = Depends(get_db)):
    tx_data = request.dict()
    resultado = business_logic.process_transaction(db, tx_data)
    if "error" in resultado:
        raise HTTPException(status_code=resultado.get("status_code", 400), detail=resultado["error"])
    return resultado