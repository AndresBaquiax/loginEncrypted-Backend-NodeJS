import pkg from 'pg';
const { Pool } = pkg;
import crypto from 'crypto';
import config from '../config.js';

// Clave privada RSA (para descifrar)
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCUKJd+5e3wvbol
rdtfR5IVuQZeN6lUZAvg5y3gUZY5bq7UqhYcJi8ot1slkyhE7yiwPgBlREcrbs9K
W4BLau1QDcGT4jnvFN6qV7/L34KJz9T/sauxRiCxq7vXWl5gAUqt0gLXEUSWgxaF
ur3IaXx+Unfog3h2LFQHx47QW4eIsL9nAqVz8HrqWxtmqAEcwnfqH1rzAIU8afSz
AFdbT7t0DWcN/fAmu9f1RMr5w52rJ6lsXT4f9yxtvBweaCBOHWhkylaaGgKYX2RB
dymItZMmR6Iv5VggEI74xXJYOhtyQpgrhc1e5DPqDRVAkK6GOHZywvQRB6fpGruP
0W64EUlFAgMBAAECggEADN0BWjkoUXCHiuHvW/Rg0JYB4Yg/oV4WUe6AYytyOYZM
k5Y42TTPf198AGUoZ+PDypl3e1NUQocaZEBRgTrFY9/t4KMRmJpdQrjfpBnBwalT
uud4GqoWCJb6dhYYf4ldLH5BVN7g75huCipOc+oErwsF8iAIA2qR2SMQWTK5L7rW
7red1Lu2DrgotUS6xQSDtxQewyndf6HYuPK28si/MtcOsdbmu90qzI3kHjBhgKR6
RBb3j+pad/bbM9ZOG0+UBgFC313aYgHYUxQCu07lpAQ/ypz6WJ1zSOHrgja0XctF
iaPuTjIjObb5wuGwmZMGxYcNFZXWyU1iJoc2RjdVQQKBgQDIM62xwVPxUUCSPUYd
tzI4HLL+HSuwIOAdY5tCvR5xEWktKiomXD0vQwZr1AnYmPGhkbdLgBq2tMNXaF/b
l6SPUlyruYoAsxalts2MaUxIwxW0Y2p959huBV8yiCdXgkg9xcLBhP1ZdBjiwMTY
4lG018VApUm3oMS3UEXj2RMzjQKBgQC9c6UC+p42KjxOEab+OQ3r9QXhO02mKMua
LSMJwKtlwjD6xZyDY+tT8gKX1StAZBiQyCV38E8rkA9kN/0z/krOkBN3MvQrSzlX
pnO5DEMBXuF+RY/GcRjoyWnUukm38oOEMsQJ3ak9ztj0xxZF+K6AbuhY9bvDJmet
glc6AKnimQKBgFMPTcLvyJnX8gg6L7roZIdvMLvI8nUyToki6Cl6OQUECjTYx3/+
yMuw7RsTb7pTSfyUbg1+6pZezKSZAxwh//4OV7BPW/gKVR0PiJv2m9WcSob6sBXo
eJy80dAvONNPlBU81R5gxJO2XRTGkWTCENAMrSOy77ClnLfJMBXl29eJAoGAdMct
BsoO7dpY89Jjuj7W+wQ8zJnugiaRYgbCm0ddH0t1P47BrCfSLht2R7sJfxZ0IgKN
PgIt+u9A3Yi5lewAlpUuuoH5ChrDTOj4Wi9ZuiWPH3OnbS3Xqd5FUvBFcpKVSM62
ElLE+KlhCHkTnKvufJJgvD00sNUigUxfkgxIq7kCgYBTpRPMw2MfEsUwxaJhbQId
U/KM6wsJk6s8cIP395O571yZYRd2XYKUYmmWSHzWFE+nYnDLG3vqNpt8XKYtfWwK
Ax+o4IVBCfElqaT/+F86VsEOlvdo5guPaayBFj/bsjeeJDxRFT/BAFngeutNZ0nH
a9tbw1U3muZrwx8mzMg44g==
-----END PRIVATE KEY-----`;

// Función para descifrar RSA
function descifrarRSA(textoBase64) {
    try {
        const buffer = Buffer.from(textoBase64, 'base64');
        const decrypted = crypto.privateDecrypt({
            key: PRIVATE_KEY,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, buffer);
        return decrypted.toString('utf8');
    } catch (error) {
        console.error('Error descifrando:', error.message);
        return null;
    }
}

// Función para obtener y descifrar variables desde .env
function obtenerVariableDescifrada(nombreRSA) {
    const valorCifrado = process.env[nombreRSA];
    if (!valorCifrado) {
        console.error(`Variable ${nombreRSA} no encontrada en .env`);
        return null;
    }
    return descifrarRSA(valorCifrado);
}

// Obtener todas las variables descifradas desde .env
const secretKey = obtenerVariableDescifrada('SECRET_KEY_RSA');
const port = obtenerVariableDescifrada('PORT_RSA');

const dbsettings = {
    host: obtenerVariableDescifrada('DB_SERVER_RSA'),
    user: obtenerVariableDescifrada('DB_USER_RSA'),
    password: obtenerVariableDescifrada('DB_PASSWORD_RSA'),
    database: obtenerVariableDescifrada('DB_DATABASE_RSA'),
    port: obtenerVariableDescifrada('DB_PORT_RSA')
};

// Mostrar estado
console.log('=== VARIABLES DESCIFRADAS ===');
console.log('SECRET_KEY:', secretKey ? '✅ Descifrada' : '❌ Error');
console.log('PORT:', port ? '✅ Descifrada' : '❌ Error');
console.log('DB_HOST:', dbsettings.host ? '✅ Descifrada' : '❌ Error');
console.log('DB_USER:', dbsettings.user ? '✅ Descifrada' : '❌ Error');
console.log('DB_PASSWORD:', dbsettings.password ? '✅ Descifrada' : '❌ Error');
console.log('DB_DATABASE:', dbsettings.database ? '✅ Descifrada' : '❌ Error');
console.log('DB_PORT:', dbsettings.port ? '✅ Descifrada' : '❌ Error');

const pool = new Pool(dbsettings);

export async function getConnection() {
    try {
        const client = await pool.connect();
        return client;
    } catch (error) {
        console.error('Error connecting to the database:', error);
        throw error;
    }
}

export { pool };

// Exportar variables descifradas para uso en la app
export const envConfig = {
    secretKey,
    port
};