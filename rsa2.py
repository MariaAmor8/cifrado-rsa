import os
import socket
import struct
import hashlib
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ==========================================
# CONFIGURACIÓN
# ==========================================
PORT = 8080
CHUNK_SIZE = 64 * 1024  # 64KB para lectura/escritura eficiente

# ==========================================
# UTILIDADES DE RED (FRAMING)
# ==========================================
def send_all(sock, data):
    """Envía todos los datos asegurando que se transmitan completos."""
    sock.sendall(data)

def recv_exact(sock, length):
    """Recibe exactamente la cantidad de bytes solicitados."""
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Conexión cerrada inesperadamente")
        data += packet
    return data

def send_msg(sock, msg_bytes):
    """Envía un mensaje con prefijo de longitud (4 bytes big-endian)."""
    msg_len = len(msg_bytes)
    sock.sendall(struct.pack('>I', msg_len) + msg_bytes)

def recv_msg(sock):
    """Recibe un mensaje con prefijo de longitud."""
    raw_len = recv_exact(sock, 4)
    msg_len = struct.unpack('>I', raw_len)[0]
    return recv_exact(sock, msg_len)

def calculate_file_hash(filepath):
    """Calcula el hash SHA256 de un archivo."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

# ==========================================
# FUNCIONES CRIPTOGRÁFICAS (SIMÉTRICAS)
# ==========================================
def generate_aes_key():
    """Genera una clave AES de 256 bits (32 bytes)."""
    return AESGCM.generate_key(bit_length=256)

def load_aes_key(path):
    """Carga una llave AES desde un archivo."""
    with open(path, 'rb') as f:
        return f.read()

def encrypt_file_aes(key, input_path, output_path):
    """
    Cifra un archivo usando AES-GCM.
    Formato salida: NONCE (12 bytes) + CIPHERTEXT + TAG (16 bytes, implícito en GCM)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # AESGCM.encrypt devuelve ciphertext + tag concatenados
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    with open(output_path, 'wb') as f:
        f.write(nonce + ciphertext)
    print(f"[+] Archivo cifrado guardado en: {output_path}")

def decrypt_file_aes(key, input_path, output_path):
    """Descifra un archivo cifrado con AES-GCM."""
    aesgcm = AESGCM(key)
    
    with open(input_path, 'rb') as f:
        data = f.read()
    
    if len(data) < 28: # 12 nonce + 16 tag mínimo
        raise ValueError("El archivo es demasiado corto o está corrupto.")
        
    nonce = data[:12]
    ciphertext = data[12:]
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print(f"[+] Archivo descifrado guardado en: {output_path}")
    except Exception as e:
        print("[-] Error: La llave es incorrecta o el archivo fue modificado (Fallo de integridad).")

# ==========================================
# FUNCIONES DE SOBRE DIGITAL (HÍBRIDO)
# ==========================================
def encrypt_digital_envelope(input_path, output_path, public_key_path):
    """
    1. Genera una llave AES efímera.
    2. Cifra el archivo con esa llave AES.
    3. Cifra la llave AES con la llave pública RSA.
    4. Empaqueta todo en un solo archivo.
    """
    # 1. Cargar llave pública RSA
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # 2. Generar llave AES efímera y cifrar datos
    aes_key = generate_aes_key()
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    
    with open(input_path, 'rb') as f:
        data = f.read()
    encrypted_data = aesgcm.encrypt(nonce, data, None) # data + tag

    # 3. Cifrar la llave AES con RSA-OAEP
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Guardar estructura: Longitud_Key_Cifrada (4 bytes) + Key_Cifrada + Nonce (12) + Datos_Cifrados
    with open(output_path, 'wb') as f:
        f.write(struct.pack('>I', len(encrypted_key)))
        f.write(encrypted_key)
        f.write(nonce)
        f.write(encrypted_data)
    
    print(f"[+] Sobre digital creado en: {output_path}")

def decrypt_digital_envelope(input_path, output_path, private_key_path):
    """Abre un sobre digital usando la llave privada RSA."""
    # 1. Cargar llave privada RSA
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # 2. Leer estructura del archivo
    with open(input_path, 'rb') as f:
        file_content = f.read()

    # Parsear cabecera
    offset = 0
    key_len = struct.unpack('>I', file_content[offset:offset+4])[0]
    offset += 4
    encrypted_key = file_content[offset:offset+key_len]
    offset += key_len
    nonce = file_content[offset:offset+12]
    offset += 12
    encrypted_data = file_content[offset:]

    # 3. Descifrar llave AES
    try:
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        print("[-] Error: Fallo al descifrar la llave AES (posible llave privada incorrecta).")
        return

    # 4. Descifrar datos
    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print(f"[+] Sobre abierto exitosamente en: {output_path}")
    except Exception:
        print("[-] Error: Fallo de integridad en los datos cifrados.")

# ==========================================
# FUNCIONES DE RED (SOCKETS)
# ==========================================
def send_file_socket(ip, filepath):
    """Envía archivo por puerto 8080 y espera confirmación (ACK)."""
    if not os.path.exists(filepath):
        print("[-] El archivo no existe.")
        return

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    filehash = calculate_file_hash(filepath)

    print(f"[*] Conectando a {ip}:{PORT}...")
    try:
        with socket.create_connection((ip, PORT), timeout=10) as s:
            # 1. Enviar Metadatos (JSON)
            metadata = {
                "filename": filename,
                "size": filesize,
                "hash": filehash
            }
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            send_msg(s, metadata_bytes)

            # 2. Enviar Contenido
            print(f"[*] Enviando {filename} ({filesize} bytes)...")
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    s.sendall(chunk)
            
            # 3. Esperar Confirmación (ACK)
            response = recv_msg(s).decode('utf-8')
            if response == "ACK":
                print("[+] ÉXITO: El servidor confirmó la recepción e integridad del archivo.")
            else:
                print(f"[-] ERROR: El servidor reportó un problema: {response}")

    except ConnectionRefusedError:
        print("[-] No se pudo conectar. Asegúrate de que el servidor esté escuchando (Opción 7).")
    except Exception as e:
        print(f"[-] Error en el envío: {e}")

def start_server_socket():
    """Servidor que escucha en el puerto 8080 y guarda archivos."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Permite reutilizar el puerto si el script se reinicia rápido
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', PORT))
        server_socket.listen(1)
        print(f"\n[+] Servidor escuchando en puerto {PORT}. Presiona Ctrl+C para salir.")
        print(f"[+] Los archivos recibidos se guardarán en: {os.getcwd()}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"\n[*] Conexión recibida de {addr[0]}")
                try:
                    # 1. Recibir Metadatos
                    metadata_bytes = recv_msg(conn)
                    metadata = json.loads(metadata_bytes.decode('utf-8'))
                    
                    filename = "recibido_" + metadata['filename']
                    expected_size = metadata['size']
                    expected_hash = metadata['hash']

                    # 2. Recibir Archivo
                    received_size = 0
                    sha256 = hashlib.sha256()
                    
                    with open(filename, 'wb') as f:
                        while received_size < expected_size:
                            # Calcular cuánto falta para evitar leer de más (si el cliente envía basura extra)
                            to_read = min(CHUNK_SIZE, expected_size - received_size)
                            chunk = conn.recv(to_read)
                            if not chunk:
                                break
                            f.write(chunk)
                            sha256.update(chunk)
                            received_size += len(chunk)

                    # 3. Verificar Integridad
                    actual_hash = sha256.hexdigest()
                    if actual_hash == expected_hash:
                        print(f"[+] Archivo {filename} recibido correctamente (Hash validado).")
                        send_msg(conn, b"ACK")
                    else:
                        print(f"[-] ALERTA: El hash no coincide. Archivo corrupto.")
                        send_msg(conn, b"HASH_MISMATCH")
                        
                except Exception as e:
                    print(f"[-] Error procesando cliente: {e}")
                    # Intentar enviar error al cliente si el socket sigue vivo
                    try: send_msg(conn, f"SERVER_ERROR: {str(e)}".encode())
                    except: pass
                    
    except KeyboardInterrupt:
        print("\n[+] Servidor detenido.")
    finally:
        server_socket.close()

# ==========================================
# MENÚ PRINCIPAL
# ==========================================
def main():
    while True:
        print("\n--- HERRAMIENTA DE TRANSFERENCIA Y CIFRADO SEGURO ---")
        print("1. Generar nueva llave simétrica AES")
        print("2. Cifrar archivo (Simétrico AES)")
        print("3. Descifrar archivo (Simétrico AES)")
        print("4. Crear Sobre Digital (Híbrido: Archivo + Llave Pública)")
        print("5. Abrir Sobre Digital (Híbrido: Sobre + Llave Privada)")
        print("6. Enviar archivo a otro servidor (TCP 8080)")
        print("7. Iniciar Servidor (Escuchar archivos en TCP 8080)")
        print("8. Salir")
        
        opcion = input("Seleccione una opción: ")

        try:
            if opcion == '1':
                path = input("Nombre del archivo para guardar la llave (ej. mi_llave.key): ")
                key = generate_aes_key()
                with open(path, 'wb') as f:
                    f.write(key)
                print(f"[+] Llave generada y guardada en {path}")

            elif opcion == '2':
                key_path = input("Ruta de la llave AES: ")
                input_file = input("Archivo a cifrar: ")
                output_file = input("Ruta de salida (ej. secreto.enc): ")
                key = load_aes_key(key_path)
                encrypt_file_aes(key, input_file, output_file)

            elif opcion == '3':
                key_path = input("Ruta de la llave AES: ")
                input_file = input("Archivo cifrado: ")
                output_file = input("Ruta de salida (archivo descifrado): ")
                key = load_aes_key(key_path)
                decrypt_file_aes(key, input_file, output_file)
            
            elif opcion == '4':
                input_file = input("Archivo a proteger: ")
                pub_key = input("Ruta de la llave PÚBLICA (PEM): ")
                output_file = input("Nombre del sobre digital de salida: ")
                encrypt_digital_envelope(input_file, output_file, pub_key)

            elif opcion == '5':
                input_file = input("Ruta del sobre digital: ")
                priv_key = input("Ruta de la llave PRIVADA (PEM): ")
                output_file = input("Donde guardar el contenido extraído: ")
                decrypt_digital_envelope(input_file, output_file, priv_key)

            elif opcion == '6':
                ip = input("IP del servidor destino: ")
                filepath = input("Archivo a enviar: ")
                send_file_socket(ip, filepath)

            elif opcion == '7':
                start_server_socket()

            elif opcion == '8':
                break
            else:
                print("Opción no válida.")
        except Exception as e:
            print(f"[-] Ocurrió un error: {e}")

if __name__ == "__main__":
    main()