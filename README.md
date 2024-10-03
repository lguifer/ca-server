---

# FAQ - Herramienta de Gestión de Certificados

## 1. ¿Qué es esta herramienta?

Esta herramienta permite gestionar una Autoridad de Certificación (CA) para generar y firmar certificados digitales. Los certificados pueden ser utilizados para asegurar comunicaciones y validar identidades en aplicaciones.

## 2. ¿Cómo instalar la herramienta?

1. **Requisitos previos**:
   - Asegúrate de tener Python 3.x instalado en tu máquina.
   - Instala las dependencias necesarias ejecutando:
     ```bash
     pip install cryptography
     ```

2. **Clona el repositorio** o descarga los archivos de la herramienta en tu máquina.

## 3. ¿Cómo se configura la herramienta?

1. **Archivo de configuración**: La herramienta utiliza un archivo de configuración llamado `ca-server.conf`. Este archivo define los parámetros de validez de los certificados y las rutas para almacenar las claves y certificados.
2. **Ejemplo de `ca-server.conf`**:
   ```ini
   [directories]
   ca_key_path = ./ca/ca_key.pem
   ca_cert_path = ./ca/ca_cert.pem
   server_directory = ./server

   [cert]
   validity_days = 365
   ```

## 4. ¿Qué comandos están disponibles?

- **Generar CA**: Crea una nueva Autoridad de Certificación.
  ```bash
  python ca-server.py generate_ca
  ```

- **Firmar un certificado**: Firma un certificado usando la CA.
  ```bash
  python ca-server.py sign_cert --common-name <nombre_comun>
  ```

- **Comprobar un certificado**: Verifica la validez de un certificado.
  ```bash
  python ca-server.py check-cert --path <ruta_certificado>
  ```

- **Enviar certificados**: Envía certificados a una IP remota (a implementar).
  ```bash
  python ca-server.py send_certs --destination-ip <IP_destino> --cert-file <ruta_certificado> --key-file <ruta_clave_privada>
  ```

## 5. ¿Cómo generar una nueva CA?

Ejecuta el siguiente comando en la terminal:

```bash
python ca-server.py generate_ca
```

Esto generará una nueva clave privada y un certificado autofirmado, que se almacenará en las rutas especificadas en el archivo de configuración.

## 6. ¿Cómo firmar un certificado?

Para firmar un certificado, utiliza el siguiente comando, reemplazando `<nombre_comun>` por el nombre deseado para el certificado:

```bash
python ca-server.py sign_cert --common-name <nombre_comun>
```

Esto generará un nuevo certificado y clave privada, y los guardará en el directorio especificado.

## 7. ¿Cómo comprobar la validez de un certificado?

Para verificar si un certificado es válido, usa el siguiente comando:

```bash
python ca-server.py check-cert --path <ruta_certificado>
```

Esto comprobará si el certificado está dentro de las fechas de validez y si ha sido firmado por la CA.

## 8. ¿Qué hacer si recibo un error sobre la firma del certificado?

Si ves un error de "firma no válida", asegúrate de que:
- Estás usando la clave pública correcta de la CA para verificar el certificado.
- El certificado que estás verificando fue realmente firmado por la CA.

Puedes usar OpenSSL para comprobar la firma de un certificado de la siguiente manera:

```bash
openssl verify -CAfile ca_cert.pem server/fwPaloAlto_cert.pem
```

## 9. ¿Dónde se almacenan las claves y certificados?

Las rutas para almacenar las claves y certificados se definen en el archivo de configuración (`ca-server.conf`). Asegúrate de que estas rutas existan y tengan los permisos adecuados para que la herramienta pueda escribir en ellas.

## 10. ¿Qué hacer si el archivo de configuración no se encuentra?

Asegúrate de que el archivo `ca-server.conf` esté en el mismo directorio que el script de Python. Si no está presente, crea uno nuevo siguiendo el ejemplo proporcionado anteriormente.

## 11. ¿Dónde puedo encontrar ayuda adicional?

Para obtener más ayuda, consulta el código fuente de la herramienta, revisa los comentarios en el código y explora la documentación de la biblioteca `cryptography` en [cryptography.io](https://cryptography.io/en/latest/).

---