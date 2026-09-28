import re
import sys
import uuid
from decimal import Decimal, InvalidOperation
from getpass import getpass

from network import SecBankClient
from security import SecurityManager

ACCOUNT_RE = re.compile(r"^ES\d{22}$")  # 24 caracteres


# ---------- Generador de mensajes ----------
def parse_amount(text: str) -> float:
    try:
        d = Decimal(text.strip().replace(",", "."))
    except InvalidOperation:
        raise ValueError("Importe no numérico")
    if not d.is_finite() or d <= 0:
        raise ValueError("El importe debe ser un número positivo y finito")
    if d.as_tuple().exponent < -2:
        raise ValueError("Máximo 2 decimales")
    return float(d)


def build_transfer(origin: str, destination: str, amount: float) -> dict:
    if not ACCOUNT_RE.match(origin) or not ACCOUNT_RE.match(destination):
        raise ValueError("Las cuentas deben ser 'ES' + 22 dígitos (24 caracteres)")
    if origin == destination:
        raise ValueError("Origen y destino no pueden coincidir")
    return {
        "tx_id": str(uuid.uuid4()),
        "origin_account": origin,
        "destination_account": destination,
        "amount": amount,
        "currency": "EUR",
        "timestamp": SecurityManager.get_timestamp(),
    }


# ---------- Interfaz CLI ----------
def main():
    client = SecBankClient(SecurityManager.from_env())
    while True:
        print("\n" + "=" * 30 + "\n🏦 SECBANK - TERMINAL CLIENTE\n" + "=" * 30)
        print("1. Iniciar sesión\n2. Enviar transferencia\n3. Cerrar sesión\n4. Salir")
        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            ok = client.login(input("Usuario: "), getpass("Contraseña: "))
            print("[+] Login exitoso." if ok else "[-] Error de autenticación.")
        elif opcion == "2":
            if not client.session_token:
                print("[-] Debes iniciar sesión primero.")
                continue
            try:
                payload = build_transfer(input("Cuenta origen (ES + 22 dígitos): ").strip(),
                                         input("Cuenta destino (ES + 22 dígitos): ").strip(),
                                         parse_amount(input("Cantidad (EUR): ")))
            except ValueError as e:
                print(f"[-] {e}")
                continue
            result = client.send_transfer(payload)
            if result.get("success"):
                print(f"[+] Registrada: {result['data']}")
            else:
                print(f"[-] Rechazada: {result.get('error')}")
        elif opcion == "3":
            client.logout()
            print("[+] Sesión cerrada.")
        elif opcion == "4":
            sys.exit(0)
        else:
            print("[-] Opción no reconocida.")


if __name__ == "__main__":
    main()