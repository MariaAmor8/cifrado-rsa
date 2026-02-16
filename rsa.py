#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cifrado/Descifrado de archivos con RSA (por bloques) usando RSA-OAEP (SHA-256).

- Cifrar: usa una llave pública (o una privada, de la cual se extrae la pública).
- Descifrar: requiere llave privada.

Formato de archivo cifrado:
  MAGIC(4) | VERSION(1) | k(2) | orig_len(8) | bloques_RSA...

Donde:
- k = tamaño del módulo RSA en bytes (ej. 256 para 2048 bits)
- cada bloque cifrado mide exactamente k bytes
"""

import os
import struct
from pathlib import Path
from getpass import getpass

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


MAGIC = b"RSAB"
VERSION = 1


# -------------------- Utilidades -------------------- #

def prompt_path(msg: str, must_exist: bool = False, must_be_file: bool = False) -> Path:
    while True:
        raw = input(msg).strip().strip('"').strip("'")
        p = Path(raw).expanduser()
        if must_exist and not p.exists():
            print(">>> La ruta no existe. Intenta de nuevo.")
            continue
        if must_be_file and (not p.exists() or not p.is_file()):
            print(">>> Se esperaba un archivo válido. Intenta de nuevo.")
            continue
        return p

def write_dir_for_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def load_rsa_key(key_path: Path) -> RSA.RsaKey:
    """
    Carga una llave RSA desde PEM/DER. Si está cifrada, pide passphrase.
    """
    data = key_path.read_bytes()
    try:
        return RSA.import_key(data)
    except (ValueError, IndexError, TypeError):
        pw = getpass("La llave parece estar protegida. Ingresa passphrase: ")
        return RSA.import_key(data, passphrase=pw)

def rsa_oaep_max_plaintext_len(rsa_key: RSA.RsaKey) -> int:
    """
    Máximo tamaño de bloque en RSA-OAEP:
      mLen <= k - 2*hLen - 2
    con SHA-256 => hLen=32
    """
    k = rsa_key.size_in_bytes()
    hlen = 32
    return k - 2 * hlen - 2


# -------------------- RSA: Cifrar/Descifrar -------------------- #

def encrypt_file_rsa(input_file: Path, key_path: Path, output_file: Path) -> None:
    """
    Cifra un archivo por bloques con RSA-OAEP(SHA-256).
    key_path debe ser una llave pública o una privada (se usará su parte pública).
    """
    key = load_rsa_key(key_path)
    pub = key.publickey()  # asegura usar pública

    k = pub.size_in_bytes()
    max_plain = rsa_oaep_max_plaintext_len(pub)
    if max_plain <= 0:
        raise ValueError("Parámetros inválidos: no hay espacio para OAEP con esa llave.")

    orig_len = input_file.stat().st_size

    cipher_rsa = PKCS1_OAEP.new(pub, hashAlgo=SHA256)

    write_dir_for_file(output_file)
    with input_file.open("rb") as fin, output_file.open("wb") as fout:
        # Header
        fout.write(MAGIC)
        fout.write(struct.pack("B", VERSION))
        fout.write(struct.pack(">H", k))
        fout.write(struct.pack(">Q", orig_len))

        # Bloques
        while True:
            chunk = fin.read(max_plain)
            if not chunk:
                break
            enc = cipher_rsa.encrypt(chunk)  # len(enc) == k
            fout.write(enc)

def decrypt_file_rsa(input_file: Path, key_path: Path, output_file: Path) -> None:
    """
    Descifra un archivo cifrado por este script (RSA-OAEP SHA-256).
    Requiere llave privada.
    """
    priv = load_rsa_key(key_path)
    if not priv.has_private():
        raise ValueError("Para descifrar se necesita una llave PRIVADA.")

    write_dir_for_file(output_file)

    with input_file.open("rb") as fin:
        magic = fin.read(4)
        if magic != MAGIC:
            raise ValueError("Archivo inválido: no parece cifrado con este script (MAGIC incorrecto).")

        version = fin.read(1)
        if len(version) != 1 or version[0] != VERSION:
            raise ValueError("Versión no soportada o archivo corrupto.")

        k_bytes = fin.read(2)
        if len(k_bytes) != 2:
            raise ValueError("Archivo corrupto (no se pudo leer k).")
        k = struct.unpack(">H", k_bytes)[0]

        orig_len_bytes = fin.read(8)
        if len(orig_len_bytes) != 8:
            raise ValueError("Archivo corrupto (no se pudo leer orig_len).")
        orig_len = struct.unpack(">Q", orig_len_bytes)[0]

        # Validación de tamaño de bloque vs llave
        if priv.size_in_bytes() != k:
            raise ValueError("La llave privada no coincide con el tamaño RSA del archivo cifrado.")

        cipher_rsa = PKCS1_OAEP.new(priv, hashAlgo=SHA256)

        written = 0
        with output_file.open("wb") as fout:
            while True:
                block = fin.read(k)
                if not block:
                    break
                if len(block) != k:
                    raise ValueError("Archivo corrupto: bloque RSA truncado.")

                chunk = cipher_rsa.decrypt(block)

                # Respetar longitud original (por si el último bloque era más corto)
                remaining = orig_len - written
                if remaining <= 0:
                    break

                if len(chunk) > remaining:
                    chunk = chunk[:remaining]

                fout.write(chunk)
                written += len(chunk)

        if written != orig_len:
            # corrupción o llave equivocada.
            raise ValueError("Descifrado incompleto: posible archivo corrupto o llave incorrecta.")


# -------------------- Interfaz -------------------- #

def menu() -> str:
    print("\n==============================")
    print(" RSA (por bloques)")
    print("==============================")
    print("1) Cifrar archivo (con llave pública)")
    print("2) Descifrar archivo (con llave privada)")
    print("3) Salir")
    return input("Elige una opción (1-3): ").strip()

def main() -> None:
    while True:
        try:
            op = menu()
            if op == "1":
                in_file = prompt_path("Ruta del archivo a cifrar: ", must_exist=True, must_be_file=True)
                key_path = prompt_path("Ruta de la llave (pública o privada): ", must_exist=True, must_be_file=True)
                out_file = prompt_path("Ruta destino del archivo cifrado (incluye nombre): ", must_exist=False)
                encrypt_file_rsa(in_file, key_path, out_file)
                print(f"-> Cifrado listo: {out_file.resolve()}")

            elif op == "2":
                in_file = prompt_path("Ruta del archivo cifrado: ", must_exist=True, must_be_file=True)
                key_path = prompt_path("Ruta de la llave privada: ", must_exist=True, must_be_file=True)
                out_file = prompt_path("Ruta destino del archivo descifrado (incluye nombre): ", must_exist=False)
                decrypt_file_rsa(in_file, key_path, out_file)
                print(f"-> Descifrado listo: {out_file.resolve()}")

            elif op == "3":
                print("Saliendo...")
                return
            else:
                print(">>> Opción inválida.")

        except KeyboardInterrupt:
            print("\nInterrumpido por el usuario...")
            return
        except Exception as e:
            print(f">>> Error: {e}")

if __name__ == "__main__":
    main()