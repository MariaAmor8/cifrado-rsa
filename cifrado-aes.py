import os
import time
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ==========================================
# FUNCIONES CRIPTOGRÁFICAS
# ==========================================

def derive_key(password: str, salt=None) -> tuple:
    """
    Deriva una llave de 32 bytes a partir de una contraseña.
    Si no se proporciona un salt, se genera uno nuevo.
    """
    salt = os.urandom(16) if salt is None else salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode()), salt

def encrypt_data(plaintext_bytes: bytes, password: str) -> str:
    """
    Cifra datos binarios y devuelve una cadena en Base64 que contiene:
    SALT (16) + IV (12) + CIPHERTEXT
    Incluye medición de tiempo del proceso de cifrado.
    """
    # 1. Derivar llave y generar IV
    key, salt = derive_key(password)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)

    # 2. Medir solo la operación de cifrado
    start_time = time.perf_counter()
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)
    end_time = time.perf_counter()

    print(f"[RELOJ] Tiempo neto de cifrado AES-GCM: {end_time - start_time:.6f} segundos.")
    
    # 3. Empaquetar todo en un Base64 para fácil manejo
    return base64.urlsafe_b64encode(salt + iv + ciphertext).decode()

def decrypt_data(ciphertext_b64: str, password: str) -> bytes:
    """
    Desempaqueta el Base64 y descifra los datos.
    Incluye medición de tiempo del proceso de descifrado.
    """
    try:
        # 1. Decodificar Base64 y separar componentes
        decoded = base64.urlsafe_b64decode(ciphertext_b64.encode())
        salt, iv, ct = decoded[:16], decoded[16:28], decoded[28:]
        
        # 2. Re-derivar la llave usando el salt recuperado
        key, _ = derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        # 3. Medir solo la operación de descifrado
        start_time = time.perf_counter()
        decrypted_data = aesgcm.decrypt(iv, ct, None)
        end_time = time.perf_counter()

        print(f"[RELOJ] Tiempo neto de descifrado AES-GCM: {end_time - start_time:.6f} segundos.")
        return decrypted_data

    except Exception as e:
        raise ValueError("Contraseña incorrecta o archivo corrupto") from e

# ==========================================
# FUNCIONES DE MANEJO DE ARCHIVOS
# ==========================================

def process_encrypt_file():
    """Maneja la lectura, cifrado y guardado de un archivo."""
    input_path = input(">> Ingrese la ruta del archivo a cifrar: ")
    if not os.path.exists(input_path):
        print("[-] Error: El archivo no existe.")
        return

    try:
        # Leemos en binario para soportar cualquier tipo de archivo (PDF, Imagen, etc.)
        with open(input_path, 'rb') as f:
            data = f.read()
        
        password = input(">> Ingrese la contraseña para cifrar: ")
        
        # Ciframos
        result_b64 = encrypt_data(data, password)
        
        # Guardamos con extensión .aes
        output_path = input_path + ".aes"
        with open(output_path, 'w') as f:
            f.write(result_b64)
        
        print(f"[+] Archivo cifrado con éxito.")
        print(f"[+] Guardado en: {os.path.abspath(output_path)}")

    except Exception as e:
        print(f"[-] Error durante el proceso: {e}")

def process_decrypt_file():
    """Maneja la lectura, descifrado y guardado del archivo resultante."""
    input_path = input(">> Ingrese la ruta del archivo cifrado (.aes): ")
    if not os.path.exists(input_path):
        print("[-] Error: El archivo no existe.")
        return

    try:
        with open(input_path, 'r') as f:
            ciphertext_b64 = f.read()
        
        password = input(">> Ingrese la contraseña para descifrar: ")
        
        # Desciframos
        decrypted_bytes = decrypt_data(ciphertext_b64, password)
        
        # Definir nombre de salida (quitando el .aes o pidiendo uno nuevo)
        output_path = input(">> Ingrese nombre/ruta del archivo de salida (ej: documento_restaurado.pdf): ")
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_bytes)
            
        print(f"[+] Archivo descifrado con éxito.")
        print(f"[+] Guardado en: {os.path.abspath(output_path)}")

    except Exception as e:
        print(f"[-] Error: {e}")

# ==========================================
# MENÚ PRINCIPAL
# ==========================================

def main():
    while True:
        print("\n==============================================")
        print("   CIFRADO AES   ")
        print("==============================================")
        print("1. Cifrar archivo (Genera .aes)")
        print("2. Descifrar archivo (A partir de .aes)")
        print("3. Salir")
        print("----------------------------------------------")
        
        choice = input("Seleccione una opción: ").strip()

        if choice == '1':
            process_encrypt_file()
        elif choice == '2':
            process_decrypt_file()
        elif choice == '3':
            print("[*] Saliendo...")
            break
        else:
            print("[-] Opción no válida.")

if __name__ == "__main__":
    main()