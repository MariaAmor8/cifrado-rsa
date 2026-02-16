#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Transferencia segura con "sobre digital":
- RSA-OAEP (SHA-256) cifra una llave AES aleatoria.
- AES-256-GCM cifra el archivo (rápido y autenticado).
- Envío por TCP/8080 con framing + SHA-256 + ACK para confirmar recepción.

Requisito:
    pip install pycryptodome
"""

import os
import json
import time
import socket
import struct
import hashlib
from pathlib import Path
from getpass import getpass
from typing import Tuple, Optional

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# ==========================
# Config / Constantes
# ==========================
CHUNK = 64 * 1024  # 64KB streaming
PORT_DEFAULT = 8080

# "Sobre digital" (archivo cifrado + llave cifrada)
ENV_MAGIC = b"ENV1"
ENV_VERSION = 1

# Protocolo de transferencia (archivo genérico)
XFER_MAGIC = b"XFR1"
XFER_VERSION = 1


# ==========================
# Utilidades
# ==========================
def prompt_non_empty(msg: str) -> str:
    while True:
        s = input(msg).strip()
        if s:
            return s
        print(">>> Entrada vacía.")

def prompt_path(msg: str, must_exist: bool = False, must_be_file: bool = False, must_be_dir: bool = False) -> Path:
    while True:
        raw = input(msg).strip().strip('"').strip("'")
        p = Path(raw).expanduser()

        if must_exist and not p.exists():
            print(">>> La ruta no existe.")
            continue
        if must_be_file and (not p.exists() or not p.is_file()):
            print(">>> Se esperaba un archivo.")
            continue
        if must_be_dir and (not p.exists() or not p.is_dir()):
            print(">>> Se esperaba un directorio.")
            continue
        return p

def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()

def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Conexión cerrada inesperadamente.")
        data += chunk
    return data

def send_all(sock: socket.socket, b: bytes) -> None:
    view = memoryview(b)
    while view:
        sent = sock.send(view)
        view = view[sent:]


# ==========================
# Carga de llaves (OpenSSL PEM)
# ==========================
def load_rsa_key(key_path: Path) -> RSA.RsaKey:
    data = key_path.read_bytes()
    try:
        return RSA.import_key(data)
    except (ValueError, IndexError, TypeError):
        pw = getpass("La llave parece estar protegida. Ingresa passphrase: ")
        return RSA.import_key(data, passphrase=pw)


# ==========================
# Sobre digital (RSA-OAEP + AES-GCM)
# ==========================
def encrypt_file_oaep_envelope(input_file: Path, rsa_pub_key_path: Path, output_envelope: Path) -> None:
    """
    Crea un sobre digital:
    - AES-256-GCM cifra el archivo
    - RSA-OAEP(SHA-256) cifra la llave AES
    Formato:
        ENV_MAGIC(4) | VER(1) | header_len(4) | header_json | enc_key | nonce | tag | ciphertext
    """
    pub_key = load_rsa_key(rsa_pub_key_path).publickey()

    # Generar llave simétrica y cifrar el archivo con AES-GCM
    aes_key = get_random_bytes(32)  # AES-256
    nonce = get_random_bytes(12)    # recomendado GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    # Cifrado streaming (para archivos grandes)
    ensure_parent_dir(output_envelope)

    # RSA-OAEP cifra la llave AES
    cipher_rsa = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # Guardaremos ciphertext al final; para escribir en streaming,
    # ciframos todo y luego escribimos encabezado + payload.
    # (Para máxima simplicidad de parsing.)
    with input_file.open("rb") as fin:
        plaintext = fin.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    header = {
        "alg": "AES-256-GCM",
        "rsa": "RSA-OAEP-SHA256",
        "orig_name": input_file.name,
        "orig_size": input_file.stat().st_size,
        "enc_key_len": len(enc_aes_key),
        "nonce_len": len(nonce),
        "tag_len": len(tag),
        "sha256_plain": hashlib.sha256(plaintext).hexdigest(),
    }
    header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")

    with output_envelope.open("wb") as f:
        f.write(ENV_MAGIC)
        f.write(struct.pack("B", ENV_VERSION))
        f.write(struct.pack(">I", len(header_bytes)))
        f.write(header_bytes)
        f.write(enc_aes_key)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

def decrypt_file_oaep_envelope(input_envelope: Path, rsa_priv_key_path: Path, output_file: Path) -> None:
    """
    Abre el sobre digital y descifra:
    - RSA-OAEP descifra AES key
    - AES-GCM descifra y verifica tag
    """
    priv_key = load_rsa_key(rsa_priv_key_path)
    if not priv_key.has_private():
        raise ValueError("Para descifrar se necesita una llave PRIVADA.")

    blob = input_envelope.read_bytes()
    idx = 0

    if blob[idx:idx+4] != ENV_MAGIC:
        raise ValueError("No es un sobre válido (MAGIC incorrecto).")
    idx += 4

    ver = blob[idx]
    idx += 1
    if ver != ENV_VERSION:
        raise ValueError(f"Versión de sobre no soportada: {ver}")

    header_len = struct.unpack(">I", blob[idx:idx+4])[0]
    idx += 4

    header_bytes = blob[idx:idx+header_len]
    idx += header_len
    header = json.loads(header_bytes.decode("utf-8"))

    enc_key_len = int(header["enc_key_len"])
    nonce_len = int(header["nonce_len"])
    tag_len = int(header["tag_len"])

    enc_aes_key = blob[idx:idx+enc_key_len]
    idx += enc_key_len
    nonce = blob[idx:idx+nonce_len]
    idx += nonce_len
    tag = blob[idx:idx+tag_len]
    idx += tag_len
    ciphertext = blob[idx:]

    # RSA-OAEP descifra la llave AES
    cipher_rsa = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    try:
        aes_key = cipher_rsa.decrypt(enc_aes_key)
    except ValueError as e:
        raise ValueError("No se pudo descifrar la llave (llave privada incorrecta o sobre corrupto).") from e

    # AES-GCM descifra y verifica integridad
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        raise ValueError("Fallo de autenticidad (tag inválido): sobre alterado o llave incorrecta.") from e

    # (Opcional) verificar hash del plaintext
    sha_plain = hashlib.sha256(plaintext).hexdigest()
    if "sha256_plain" in header and header["sha256_plain"] != sha_plain:
        raise ValueError("Hash SHA-256 no coincide: posible corrupción.")

    ensure_parent_dir(output_file)
    output_file.write_bytes(plaintext)


# ==========================
# Envío por TCP/8080 con ACK
# ==========================
def send_file_tcp(ip: str, port: int, file_path: Path, remote_name: Optional[str] = None, timeout_s: int = 20) -> None:
    """
    Envía un archivo por TCP, con:
    - header JSON (nombre, tamaño, sha256)
    - payload streaming
    - ACK del receptor (OK + sha256) o (ERR + msg)
    """
    if remote_name is None:
        remote_name = file_path.name

    file_size = file_path.stat().st_size
    file_hash = sha256_of_file(file_path)

    header = {
        "name": remote_name,
        "size": file_size,
        "sha256": file_hash,
        "sent_at": int(time.time()),
    }
    header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")

    with socket.create_connection((ip, port), timeout=timeout_s) as sock:
        sock.settimeout(timeout_s)

        # Enviar framing: MAGIC | VER | header_len | header | payload
        send_all(sock, XFER_MAGIC)
        send_all(sock, struct.pack("B", XFER_VERSION))
        send_all(sock, struct.pack(">I", len(header_bytes)))
        send_all(sock, header_bytes)

        # Enviar archivo en streaming
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(CHUNK), b""):
                send_all(sock, chunk)

        # Esperar ACK
        ack_magic = recv_exact(sock, 3)  # b"OK!" o b"ERR"
        if ack_magic == b"OK!":
            ack_hash_len = struct.unpack(">H", recv_exact(sock, 2))[0]
            ack_hash = recv_exact(sock, ack_hash_len).decode("utf-8")
            if ack_hash != file_hash:
                raise RuntimeError("El receptor respondió OK pero el hash no coincide (inconsistencia).")
        elif ack_magic == b"ERR":
            msg_len = struct.unpack(">H", recv_exact(sock, 2))[0]
            msg = recv_exact(sock, msg_len).decode("utf-8", errors="replace")
            raise RuntimeError(f"El receptor reportó error: {msg}")
        else:
            raise RuntimeError("ACK inválido del receptor.")

def start_receiver_tcp(bind_ip: str, port: int, output_dir: Path) -> None:
    """
    Servidor receptor:
    - recibe header + payload
    - guarda archivo
    - verifica sha256
    - envía ACK
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, port))
        srv.listen(5)
        print(f" --> Receptor escuchando en {bind_ip}:{port}")
        print(f" --> Guardando en: {output_dir.resolve()}\n")

        while True:
            conn, addr = srv.accept()
            with conn:
                try:
                    print(f"🔌 Conexión de {addr[0]}:{addr[1]}")
                    magic = recv_exact(conn, 4)
                    if magic != XFER_MAGIC:
                        raise ValueError("MAGIC de transferencia inválido.")

                    ver = recv_exact(conn, 1)[0]
                    if ver != XFER_VERSION:
                        raise ValueError(f"Versión de transferencia no soportada: {ver}")

                    header_len = struct.unpack(">I", recv_exact(conn, 4))[0]
                    header = json.loads(recv_exact(conn, header_len).decode("utf-8"))

                    name = header["name"]
                    size = int(header["size"])
                    expected_hash = header["sha256"]

                    # Guardar a un archivo temporal primero
                    out_path = output_dir / name
                    tmp_path = output_dir / (name + ".part")

                    h = hashlib.sha256()
                    remaining = size

                    with tmp_path.open("wb") as f:
                        while remaining > 0:
                            chunk = conn.recv(min(CHUNK, remaining))
                            if not chunk:
                                raise ConnectionError("Conexión cerrada antes de completar el archivo.")
                            f.write(chunk)
                            h.update(chunk)
                            remaining -= len(chunk)

                    got_hash = h.hexdigest()

                    if got_hash != expected_hash:
                        tmp_path.unlink(missing_ok=True)
                        # ACK error
                        msg = f"Hash no coincide. esperado={expected_hash}, recibido={got_hash}"
                        send_all(conn, b"ERR")
                        send_all(conn, struct.pack(">H", len(msg.encode("utf-8"))))
                        send_all(conn, msg.encode("utf-8"))
                        print(f">> {msg}\n")
                        continue

                    # Renombrar final
                    tmp_path.replace(out_path)

                    # ACK ok
                    send_all(conn, b"OK!")
                    send_all(conn, struct.pack(">H", len(got_hash.encode("utf-8"))))
                    send_all(conn, got_hash.encode("utf-8"))
                    print(f"-> Recibido OK: {out_path.name} (sha256={got_hash})\n")

                except Exception as e:
                    try:
                        msg = str(e)
                        send_all(conn, b"ERR")
                        send_all(conn, struct.pack(">H", len(msg.encode("utf-8"))))
                        send_all(conn, msg.encode("utf-8"))
                    except Exception:
                        pass
                    print(f">>> Error recibiendo: {e}\n")


# ==========================
# Funciones pedidas: enviar archivo / enviar sobre digital
# ==========================
def send_digital_envelope(ip: str, port: int, input_file: Path, rsa_pub_key_path: Path, remote_name: Optional[str] = None) -> None:
    """
    Crea un sobre digital (archivo + llave cifrada) y lo envía al receptor.
    El receptor solo lo guarda; el descifrado lo hace quien tenga la llave privada.
    """
    # Crear sobre en una ruta temporal en la misma carpeta del input
    envelope_path = input_file.parent / (input_file.name + ".env")
    encrypt_file_oaep_envelope(input_file, rsa_pub_key_path, envelope_path)

    try:
        if remote_name is None:
            remote_name = envelope_path.name
        send_file_tcp(ip, port, envelope_path, remote_name=remote_name)
    finally:
        # Puedes comentar esto si quieres conservar el .env localmente
        envelope_path.unlink(missing_ok=True)


# ==========================
# Menú interactivo
# ==========================
def menu() -> str:
    print("\n==============================")
    print(" RSA-OAEP ")
    print("==============================")
    print("1) Cifrar archivo (crear sobre digital) y guardar")
    print("2) Descifrar sobre digital y guardar archivo")
    print("3) Enviar archivo por TCP/8080")
    print("4) Enviar sobre digital por TCP/8080 (archivo+llave cifrada en paquete)")
    print("5) Iniciar receptor (escuchar 0.0.0.0:8080)")
    print("6) Salir")
    return input("Elige una opción (1-6): ").strip()

def flow_encrypt() -> None:
    in_file = prompt_path("Ruta del archivo a cifrar: ", must_exist=True, must_be_file=True)
    pub_key = prompt_path("Ruta de la llave RSA pública (OpenSSL .pem): ", must_exist=True, must_be_file=True)
    out_env = prompt_path("Ruta destino del sobre (incluye nombre, ej. archivo.env): ", must_exist=False)
    encrypt_file_oaep_envelope(in_file, pub_key, out_env)
    print(f"-> Sobre creado: {out_env.resolve()}")

def flow_decrypt() -> None:
    in_env = prompt_path("Ruta del sobre .env: ", must_exist=True, must_be_file=True)
    priv_key = prompt_path("Ruta de la llave RSA privada (OpenSSL .pem): ", must_exist=True, must_be_file=True)
    out_file = prompt_path("Ruta destino del archivo descifrado (incluye nombre): ", must_exist=False)
    decrypt_file_oaep_envelope(in_env, priv_key, out_file)
    print(f"-> Archivo descifrado: {out_file.resolve()}")

def flow_send_file() -> None:
    ip = prompt_non_empty("IP del servidor receptor: ")
    port_raw = input(f"Puerto [default {PORT_DEFAULT}]: ").strip()
    port = int(port_raw) if port_raw else PORT_DEFAULT
    file_path = prompt_path("Ruta del archivo a enviar: ", must_exist=True, must_be_file=True)
    remote_name = input("Nombre con el que se guardará en el receptor (enter para mismo nombre): ").strip() or None
    send_file_tcp(ip, port, file_path, remote_name=remote_name)
    print("-> Envío confirmado")

def flow_send_envelope() -> None:
    ip = prompt_non_empty("IP del servidor receptor: ")
    port_raw = input(f"Puerto [default {PORT_DEFAULT}]: ").strip()
    port = int(port_raw) if port_raw else PORT_DEFAULT
    in_file = prompt_path("Ruta del archivo a mandar como sobre digital: ", must_exist=True, must_be_file=True)
    pub_key = prompt_path("Ruta de la llave RSA pública del destinatario (OpenSSL .pem): ", must_exist=True, must_be_file=True)
    remote_name = input("Nombre del sobre en el receptor (enter para auto): ").strip() or None
    send_digital_envelope(ip, port, in_file, pub_key, remote_name=remote_name)
    print("-> Sobre digital enviado y confirmado")

def flow_receiver() -> None:
    bind_ip = input("IP de binding [enter para 0.0.0.0]: ").strip() or "0.0.0.0"
    port_raw = input(f"Puerto [default {PORT_DEFAULT}]: ").strip()
    port = int(port_raw) if port_raw else PORT_DEFAULT
    out_dir = prompt_path("Directorio donde guardar archivos recibidos: ", must_exist=False)
    out_dir.mkdir(parents=True, exist_ok=True)
    print("\n(CTRL+C para detener el receptor)\n")
    start_receiver_tcp(bind_ip, port, out_dir)

def main() -> None:
    while True:
        try:
            op = menu()
            if op == "1":
                flow_encrypt()
            elif op == "2":
                flow_decrypt()
            elif op == "3":
                flow_send_file()
            elif op == "4":
                flow_send_envelope()
            elif op == "5":
                flow_receiver()
            elif op == "6":
                print("Saliendo. 👋")
                return
            else:
                print(">>> Opción inválida.")
        except KeyboardInterrupt:
            print("\nInterrumpido. 👋")
            return
        except Exception as e:
            print(f">>> Error: {e}")

if __name__ == "__main__":
    main()