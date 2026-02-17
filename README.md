# Cifrado RSA y Sobre Digital

Este repositorio contiene una implementación en Python de herramientas criptográficas para la protección y transferencia segura de archivos. El proyecto se centra en el concepto de **Sobre Digital**, combinando la eficiencia del cifrado simétrico (AES) con la seguridad del cifrado asimétrico (RSA).

## Características

*   **Cifrado Simétrico (AES-GCM):** Uso de AES en modo GCM para garantizar tanto la confidencialidad como la integridad de los datos.
*   **Cifrado Asimétrico (RSA-OAEP):** Implementación de RSA con padding OAEP para el intercambio seguro de llaves.
*   **Sobre Digital:** Proceso que cifra archivos grandes con una llave AES efímera, la cual es protegida a su vez por una llave pública RSA.
*   **Transferencia de Archivos:** Sistema Cliente/Servidor mediante Sockets TCP para enviar y recibir archivos de forma directa.
*   **Medición de Desempeño:** Los scripts incluyen contadores para medir el tiempo exacto que toman las operaciones criptográficas.

## Requisitos

Para ejecutar estos scripts, necesitarás Python 3.x y la librería `cryptography`.

1. Instala la dependencia necesaria:
   ```bash
   pip install cryptography
   ```

## Estructura del Proyecto

### 1. `sobre-digital.py` (Script Principal)
Es el núcleo del proyecto. Ofrece un menú interactivo con las siguientes opciones:
*   **Crear Sobre Digital:** Solicita un archivo y una llave pública RSA (`.pem`) para generar un archivo protegido.
*   **Abrir Sobre Digital:** Usa una llave privada RSA para recuperar la llave AES y descifrar el archivo original.
*   **Enviar Archivo:** Actúa como cliente para enviar cualquier archivo a una dirección IP específica.
*   **Recibir Archivos:** Inicia un servidor que escucha en el puerto `8080` para recibir archivos entrantes.

### 2. `cifrado-aes.py`
Un módulo enfocado en el cifrado de archivos basado en contraseñas:
*   Utiliza **PBKDF2HMAC** para derivar llaves seguras a partir de una frase de contraseña.
*   Empaqueta el Salt, el IV y el contenido cifrado en una cadena Base64 para facilitar su manejo.

## Ejemplo de Uso

### Generar Llaves RSA
Antes de usar el sobre digital, asegúrate de tener tus llaves en formato PEM. Puedes generarlas con OpenSSL:
```bash
openssl genrsa -out privada.pem 2048
openssl rsa -in privada.pem -pubout -out publica.pem
```

### Ejecución
Para iniciar el menú principal:
```bash
python sobre-digital.py
```

## Detalles Técnicos
*   **Puerto por defecto:** 8080
*   **Tamaño de bloque (Chunk):** 64KB (optimizado para archivos grandes).
*   **Algoritmo de Hash:** SHA-256.
*   **Seguridad:** Se utiliza `os.urandom` para la generación de Nonces y Salts aleatorios.

