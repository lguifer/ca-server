# Volver a generar el archivo Markdown para asegurarse de que el enlace funcione

# Crear archivo Markdown con la documentación para GitHub
markdown_content = """
# Guía de Uso: CA Tool - Generación y Firma de Certificados TLS

Este script Python permite gestionar una Autoridad de Certificación (CA) interna, generar certificados TLS, y firmar certificados de servidores o clientes. Además, cuenta con la funcionalidad de enviar los certificados generados a una máquina remota usando `scp`.

## Requisitos previos

1. **Python 3.6 o superior**: El script utiliza la librería `cryptography`, por lo que asegúrate de tener Python 3 instalado.
2. **Librerías necesarias**:
   - Instala las librerías necesarias con el siguiente comando:
     ```bash
     pip install cryptography argparse
     ```
3. **Acceso SSH**: Para enviar certificados a otras máquinas, debes tener configurado el acceso SSH a esas máquinas (por ejemplo, mediante claves SSH).

---

## Uso General del Script

El script tiene dos funcionalidades principales:
1. **Generar la CA**: Crear una clave privada y un certificado autofirmado para la CA.
2. **Firmar certificados**: Generar certificados TLS (para servidores o clientes) y firmarlos con la CA generada.

También, puedes usar la opción `--send-certs <IP>` para enviar los archivos generados a una máquina remota.

### Ejecución del Script

El script se invoca desde la línea de comandos, y acepta distintos subcomandos para realizar las acciones necesarias.

### Opciones del Script

#### 1. Generar la CA

Este comando genera una nueva CA (clave privada y certificado autofirmado).

Archivos generados:
- La clave privada de la CA (`ca_key.pem`).
- El certificado de la CA (`ca_cert.pem`).

**Comando:**
```bash
python ca_tool.py generate_ca --ca-key <ca_key_filename> --ca-cert <ca_cert_filename>
