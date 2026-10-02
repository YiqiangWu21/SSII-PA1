import re
import sys
import uuid
from decimal import Decimal, InvalidOperation
from getpass import getpass

from network import SecBankClient
from security import SecurityManager

ACCOUNT_RE = re.compile(r"^ES\d{22}$")  # Regular expression to validate Spanish bank account numbers (IBAN)

# ---------- Functions to build transactions ----------
# Function to parse a string amount into a float, ensuring it is a valid positive number
def parse_amount(text: str) -> float:
    """Parses a string amount into a float, ensuring it is a valid positive number with at most 2 decimal places."""
    try:
        d = Decimal(text.strip().replace(",", ".")) # Converts the input string to a Decimal, replacing commas with dots for decimal points
    except InvalidOperation:
        raise ValueError("Importe no numérico")
    if not d.is_finite() or d <= 0: # Checks if the amount is a finite positive number
        raise ValueError("El importe debe ser un número positivo y finito")
    if d.as_tuple().exponent < -2: # Checks if the amount has more than 2 decimal places (X.YZ)
        raise ValueError("Máximo 2 decimales")
    return float(d)

# Function to build a transfer payload that will be sent to the server
def build_transfer(origin: str, destination: str, amount: float) -> dict:
    """Builds a transfer payload that will be sent to the server, including a unique transaction ID and timestamp."""
    if not ACCOUNT_RE.match(origin) or not ACCOUNT_RE.match(destination): # Checks if the origin and destination account numbers match the expected format (Spanish IBAN)
        raise ValueError("Las cuentas deben ser 'ES' + 22 dígitos (24 caracteres)")
    if origin == destination: # Checks if the origin and destination accounts are the same, which is not allowed for transfers
        raise ValueError("Origen y destino no pueden coincidir")
    return { # Returns a dictionary containing the transfer details, including a unique transaction ID, origin and destination accounts, amount, currency, and timestamp
        "tx_id": str(uuid.uuid4()),
        "origin_account": origin,
        "destination_account": destination,
        "amount": amount,
        "currency": "EUR",
        "timestamp": SecurityManager.get_timestamp(),
    }


# ---------- CLI Interface ----------
def main():
    try:
        client = SecBankClient(SecurityManager.from_env()) # Initializes the SecBankClient with a SecurityManager instance created from an environment variable containing the HMAC key
    except (RuntimeError, ValueError) as e:
        print(f"[-] Error de inicialización: {e}")
        sys.exit(1)
    
    while True:
        print("\n" + "=" * 30 + "\n🏦 SECBANK - TERMINAL CLIENTE\n" + "=" * 30)
        print("1. Registrar usuario\n2. Iniciar sesión\n3. Enviar transferencia\n4. Cerrar sesión\n5. Salir")
        opcion = input("Seleccione una opción: ")

        if opcion == "1": # Registers a new user (username + password) on the server
            user = input("Nuevo usuario: ").strip()
            pwd = getpass("Contraseña (mín. 8 caracteres): ")
            if len(pwd) < 8: # Checks if the password meets the minimum length requirement of 8 characters
                print("[-] La contraseña debe tener al menos 8 caracteres.")
                continue
            ok = client.register(user, pwd)
            print("[+] Usuario registrado. Ya puedes iniciar sesión." if ok else f"[-] Registro rechazado: {client.last_error}")
        elif opcion == "2": # Prompts the user for their username and password, and attempts to log in using the SecBankClient instance
            ok = client.login(input("Usuario: "), getpass("Contraseña: "))
            print("[+] Login exitoso." if ok else f"[-] Error de autenticación: {client.last_error}")
        elif opcion == "3": # Prompts the user for the origin and destination account numbers, as well as the transfer amount, and attempts to send a transfer using the SecBankClient instance
            if not client.session_token: # Checks if the user is authenticated before allowing them to send a transfer
                print("[-] Debes iniciar sesión primero.")
                continue
            try: # Prompts the user for the origin and destination account numbers, as well as the transfer amount, and builds a transfer payload using the build_transfer function
                payload = build_transfer(input("Cuenta origen (ES + 22 dígitos): ").strip(),
                                         input("Cuenta destino (ES + 22 dígitos): ").strip(),
                                         parse_amount(input("Cantidad (EUR): ")))
            except ValueError as e:
                print(f"[-] {e}")
                continue
            result = client.send_transfer(payload) # Attempts to send the transfer using the SecBankClient instance, and prints the result of the operation (success or error message)
            if result.get("success"): # If the transfer was successful, it prints a success message along with the server's response data
                print(f"[+] Registrada: {result['data']}")
            else:
                print(f"[-] Rechazada: {result.get('error')}")
        elif opcion == "4": # Logs out the user by calling the logout method of the SecBankClient instance, and prints a message indicating that the session has been closed
            client.logout()
            print("[+] Sesión cerrada.")
        elif opcion == "5": # Exits the program by calling sys.exit(0), which terminates the Python interpreter with a status code of 0 (indicating successful termination)
            sys.exit(0)
        else: # If the user enters an unrecognized option, it prints an error message indicating that the option is not recognized
            print("[-] Opción no reconocida.")


if __name__ == "__main__":
    main()