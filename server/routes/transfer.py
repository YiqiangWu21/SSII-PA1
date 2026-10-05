from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database.database import get_db
from database import business_logic

router = APIRouter()

class TransferRequest(BaseModel):
    tx_id: str
    origin_account: str
    destination_account: str
    amount: float
    currency: str
    timestamp: int

@router.post("/transfer")
def transfer(
    request: TransferRequest, 
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    # 1. Validación de Sesión (M2)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente o formato inválido")
    
    token = authorization.split(" ")[1]
    user = business_logic.get_user_by_token(db, token)
    if not user:
        raise HTTPException(status_code=401, detail="Token de sesión inválido")

    # 2. Procesamiento de la transacción (M2)
    tx_data = request.model_dump()
    resultado = business_logic.process_transaction(db, tx_data)
    
    if "error" in resultado:
        raise HTTPException(status_code=resultado["status_code"], detail=resultado["error"])
        
    return resultado