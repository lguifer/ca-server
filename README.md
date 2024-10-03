Aquí tienes la documentación detallada del script para que tus colegas puedan entender cómo funciona y utilizarlo sin problemas. Esta guía explica cada comando, argumento, y los pasos a seguir para generar certificados y usarlos en la infraestructura.

---

# **Guía de Uso: CA Tool - Generación y Firma de Certificados TLS**

Este script Python permite gestionar una Autoridad de Certificación (CA) interna, generar certificados TLS, y firmar certificados de servidores o clientes. Además, cuenta con la funcionalidad de enviar los certificados generados a una máquina remota usando `scp`.

## **Requisitos previos**
1. **Python 3.6 o superior**: El script utiliza la librería `cryptography`, por lo que asegúrate de tener Python 3 instalado.
2. **Librerías necesarias**:
   - Instala las librerías necesarias con el siguiente comando:
     ```bash
     pip install cryptography argparse
     ```
3. **Acceso SSH**: Para enviar certificados a otras máquinas, debes tener configurado el acceso SSH a esas máquinas (por ejemplo, mediante claves SSH).

---

## **Uso General del Script**

El script tiene dos funcionalidades principales:
1. **Generar la CA**: Crear una clave privada y un certificado autofirmado para la CA.
2. **Firmar certificados**: Generar certificados TLS (para servidores o clientes) y firmarlos con la CA generada.

También, puedes usar la opción `--send-certs <IP>` para enviar los archivos generados a una máquina remota.

### **Ejecución del Script**

El script se invoca desde la línea de comandos, y acepta distintos subcomandos para realizar las acciones necesarias.

### **Opciones del Script**

1. **Generar la CA**
   - Este comando genera una nueva CA (clave privada y certificado autofirmado).
   - Archivos generados:
     - La clave privada de la CA (`ca_key.pem`).
     - El certificado de la CA (`ca_cert.pem`).

   **Comando:**
   ```bash
   python ca_tool.py generate_ca --ca-key <ca_key_filename> --ca-cert <ca_cert_filename>
   ```

   **Parámetros:**
   - `--ca-key`: Nombre del archivo donde se guardará la clave privada de la CA (por defecto: `ca_key.pem`).
   - `--ca-cert`: Nombre del archivo donde se guardará el certificado de la CA (por defecto: `ca_cert.pem`).

   **Ejemplo:**
   ```bash
   python ca_tool.py generate_ca --ca-key my_ca_key.pem --ca-cert my_ca_cert.pem
   ```

   En este ejemplo, el archivo `my_ca_key.pem` contendrá la clave privada de la CA, y `my_ca_cert.pem` será el certificado autofirmado.

---

2. **Firmar Certificados de Servidor/Cliente**
   - Este comando genera un certificado para un servidor o cliente y lo firma usando la CA previamente generada.
   - Archivos generados:
     - La clave privada del servidor o cliente (`server_key.pem`).
     - El certificado firmado (`server_cert.pem`).

   **Comando:**
   ```bash
   python ca_tool.py sign_cert --common-name <common_name> --ca-key <ca_key_filename> --ca-cert <ca_cert_filename> --output-key <output_key_filename> --output-cert <output_cert_filename>
   ```

   **Parámetros:**
   - `--common-name`: Nombre común (Common Name) que identifica al servidor o cliente (por ejemplo: `server.mydomain.com`).
   - `--ca-key`: Archivo de la clave privada de la CA usada para firmar (por defecto: `ca_key.pem`).
   - `--ca-cert`: Archivo del certificado de la CA (por defecto: `ca_cert.pem`).
   - `--output-key`: Nombre del archivo donde se guardará la clave privada del servidor o cliente (por defecto: `server_key.pem`).
   - `--output-cert`: Nombre del archivo donde se guardará el certificado firmado (por defecto: `server_cert.pem`).

   **Ejemplo:**
   ```bash
   python ca_tool.py sign_cert --common-name "server.mydomain.com" --ca-key my_ca_key.pem --ca-cert my_ca_cert.pem --output-key server_key.pem --output-cert server_cert.pem
   ```

   En este ejemplo, se genera un certificado para `server.mydomain.com` y se guardan los archivos `server_key.pem` (clave privada) y `server_cert.pem` (certificado firmado).

---

3. **Enviar Certificados a una Máquina Remota con SCP**
   - Este comando permite enviar automáticamente los certificados generados a otra máquina mediante `scp`.
   - Requiere que tengas acceso SSH a la máquina remota.
   
   **Comando:**
   ```bash
   python ca_tool.py sign_cert --common-name <common_name> --ca-key <ca_key_filename> --ca-cert <ca_cert_filename> --output-key <output_key_filename> --output-cert <output_cert_filename> --send-certs <IP>
   ```

   **Parámetros Adicionales:**
   - `--send-certs <IP>`: IP de la máquina destino donde se enviarán los archivos. Los certificados se copiarán al directorio `~/` del usuario remoto.

   **Ejemplo:**
   ```bash
   python ca_tool.py sign_cert --common-name "server.mydomain.com" --ca-key my_ca_key.pem --ca-cert my_ca_cert.pem --output-key server_key.pem --output-cert server_cert.pem --send-certs 192.168.1.10
   ```

   En este ejemplo, además de firmar el certificado, el script enviará los archivos `server_key.pem` y `server_cert.pem` a la máquina con IP `192.168.1.10`.

---

## **Errores Comunes y Soluciones**

1. **Error: `subprocess.CalledProcessError` al usar `scp`**
   - Este error ocurre si `scp` no puede conectarse a la máquina destino o si hay un problema de permisos.
   - **Solución**: Asegúrate de que:
     - Puedes conectarte a la máquina destino usando SSH sin problemas (posiblemente con claves SSH).
     - El servicio SSH está corriendo en la máquina destino.
     - Tienes permisos para escribir en el directorio de destino (`~/`).

2. **Error: `FileNotFoundError` al cargar la clave o certificado de la CA**
   - Este error ocurre si los archivos de la CA especificados (`--ca-key` o `--ca-cert`) no existen.
   - **Solución**: Verifica que los nombres de los archivos sean correctos y que los archivos existen en el directorio desde donde estás ejecutando el script.

---

## **FAQs**

### 1. ¿Cómo sé que los certificados generados son válidos?
El script utiliza el estándar `X.509` para la generación y firma de certificados. Los certificados generados serán válidos para su uso en TLS, y puedes verificarlos usando herramientas como `openssl`:
```bash
openssl x509 -in server_cert.pem -text -noout
```

### 2. ¿Qué pasa si pierdo los archivos de la CA?
Es fundamental **proteger y hacer un respaldo** de los archivos de la CA (`ca_key.pem` y `ca_cert.pem`). Si pierdes la clave privada de la CA, no podrás firmar nuevos certificados ni validar los existentes.

### 3. ¿Qué hago si quiero cambiar el Common Name (CN) de un certificado?
Si necesitas cambiar el `Common Name` de un certificado, simplemente usa el comando `sign_cert` con el nuevo valor de `--common-name` y genera un nuevo certificado.

---

## **Resumen de Comandos**

| Comando                                       | Descripción                                         |
|-----------------------------------------------|-----------------------------------------------------|
| `generate_ca`                                 | Genera una nueva CA (clave y certificado autofirmado). |
| `sign_cert`                                   | Firma un certificado de servidor/cliente con la CA. |
| `sign_cert --send-certs <IP>`                 | Firma un certificado y lo envía a una máquina remota. |

---

Con esta documentación, tus colegas tendrán todo lo necesario para generar certificados con este script, firmarlos, y enviarlos a servidores de destino mediante `scp`.
