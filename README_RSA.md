# Implementación de Encriptación RSA

## Descripción
Se ha implementado la funcionalidad de encriptación RSA siguiendo el mismo patrón que los métodos SHA1 y MD5 existentes.

## Archivos Modificados

### 1. `src/controllers/usuarios.controller.js`
- Se agregó la función `encriptarRSA()` con clave pública quemada
- Se modificaron las funciones `postUsuarios()` y `putUsuarios()` para incluir RSA
- Se removió la dependencia de `llave_rsa` como parámetro

### 2. `src/controllers/verificarContrasena.controller.js`
- Se agregó la función `encriptarRSA()` con clave pública quemada
- Se agregó la función `desencriptarRSA()` con clave privada quemada
- Se corrigió la función `verificarContrasenaRSA()` para desencriptar y comparar correctamente

### 3. `src/database/querys.js`
- Se agregó la consulta `obtenerRSA` para obtener contraseñas RSA almacenadas

### 4. `src/app.js`
- Se limpió la referencia a rutas RSA inexistentes

## Endpoints Disponibles

### Usuarios
- `POST /usuarios` - Crear usuario (incluye encriptación RSA)
- `PUT /usuarios/:id` - Actualizar usuario (incluye encriptación RSA)
- `GET /usuarios` - Obtener todos los usuarios
- `GET /usuarios/:id` - Obtener usuario por ID
- `DELETE /usuarios/:id` - Eliminar usuario

### Verificación de Contraseñas
- `POST /usuarios/verificarsha1` - Verificar contraseña SHA1
- `POST /usuarios/verificarmd5` - Verificar contraseña MD5
- `POST /usuarios/verificarhash` - Verificar contraseña bcrypt
- `POST /usuarios/verificarrsa` - Verificar contraseña RSA

## Estructura de Datos

### Crear Usuario (POST /usuarios)
```json
{
    "nombre": "Juan",
    "apellido": "Pérez",
    "email": "juan@example.com",
    "usuario": "jperez",
    "contrasena_hash": "micontrasena",
    "contrasena_md5": "micontrasena",
    "contrasena_sha1": "micontrasena",
    "contrasena_rsa": "micontrasena"
}
```

### Verificar Contraseña RSA (POST /usuarios/verificarrsa)
```json
{
    "usuario": "jperez",
    "contrasena": "micontrasena"
}
```

## Características de la Implementación RSA

1. **Clave Quemada**: Las claves RSA están hardcodeadas en el código como solicitaste
2. **Encriptación Segura**: Usa OAEP padding con SHA-256
3. **Verificación Correcta**: Desencripta la contraseña almacenada y la compara con la ingresada
4. **Tamaño de Clave**: 2048 bits para seguridad adecuada

## Notas Importantes

- En RSA, cada encriptación del mismo texto produce un resultado diferente debido al padding aleatorio
- La verificación se realiza desencriptando la contraseña almacenada, no comparando encriptaciones
- Las claves están temporalmente quemadas en el código para desarrollo
- La implementación sigue el mismo patrón que SHA1 y MD5 para consistencia

## Próximos Pasos

1. Reemplazar las claves quemadas con tu propia clave RSA
2. Implementar manejo de claves más seguro (variables de entorno)
3. Agregar validación adicional según sea necesario
4. Probar todos los endpoints con herramientas como Postman

## Ejemplo de Clave RSA para Reemplazar

Puedes generar nuevas claves con:
```bash
node -e "
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
console.log('Pública:'); console.log(publicKey);
console.log('Privada:'); console.log(privateKey);
"
``` 