import { getConnection, querysVerificarContrasena } from "../database/index.js";
import crypto from 'crypto';
import bcrypt from 'bcrypt';

// --------------------- ENCRIPTACION ---------------------
const encriptarSHA1 = (texto) => {
    return crypto.createHash('sha1').update(texto).digest('hex');
};

const encriptarMD5 = (texto) => {
    return crypto.createHash('md5').update(texto).digest('hex');
};

const hashearTexto = (texto) => {
    const saltRounds = 10; 
    return bcrypt.hashSync(texto, saltRounds);
};

// Clave RSA pública quemada en el código (temporal)
const RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp+C1ISbU2BcukE98Ja9U
8hCNeLezpfiSAL/EAp7Uj8fGknT2Y2kVire/domHEvnrCxXda9jzqqpIdMGYgLjs
ee6Qw3OZ+SpSS4D/W7ruF42pL3O8Sk35NtKbV03wVrrIplTXezC7WVf2V91DsrRQ
xssw3A4eT0/O0fmvxyEku+hRzMqxFXQw1qvbplKo2T+Drnbyfr2sOnGlJplnliN3
dcZycjjEPqGrI0qbx3wquCXTQufVYv6IMCO7iGb7hu4k23d5KnqUoAufJDWrsOLw
V+zkP5a972QvKQShJi7T6q0ULV3mZYON5JNMDwEY0CAuyFAytT44J3+ey4ZWs478
FwIDAQAB
-----END PUBLIC KEY-----`;

// Clave RSA privada quemada en el código (temporal) - SOLO para verificación
const RSA_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCn4LUhJtTYFy6Q
T3wlr1TyEI14t7Ol+JIAv8QCntSPx8aSdPZjaRWKt792iYcS+esLFd1r2POqqkh0
wZiAuOx57pDDc5n5KlJLgP9buu4Xjakvc7xKTfk20ptXTfBWusimVNd7MLtZV/ZX
3UOytFDGyzDcDh5PT87R+a/HISS76FHMyrEVdDDWq9umUqjZP4OudvJ+vaw6caUm
mWeWI3d1xnJyOMQ+oasjSpvHfCq4JdNC59Vi/ogwI7uIZvuG7iTbd3kqepSgC58k
Nauw4vBX7OQ/lr3vZC8pBKEmLtPqrRQtXeZlg43kk0wPARjQIC7IUDK1Pjgnf57L
hlazjvwXAgMBAAECggEACToOen354M6VXpUfy6pxTsSeIe5mz050J9piWYqFQEnI
njATgq854d/rhAZXCDH4Oym+e7j224B0bwZc7WY8iQ8VochuxAURdNjoMBB8GYtN
qy//P049zkeRBiFgfkPR12J+XWT2RxjQj0+38tB6SBLO4qlb/Rvz0BKbGKS3siQh
3VWHaCMaendAqTyw6fDKwRwbkZKOg1JEBRvDPuWzyN1eTUSzUieutdjX3FWLaPk6
t6uwau0LYof9VvI+sucAV2uoSQp+KPBFAcSKUWJz807WGObhxBcD35EXrbxqT64B
KxNrkSyleurXstcA38wAd0kBe2TXfbppigJT6b6P8QKBgQDW01fpeUgbdmZ8rj4n
gMZnc+s/ESK7zyOytsd0MM4w6vIpEYFgKPEIlEaZGSCiD+7sTt/98+2f/Lv7fqsB
6Vl76its0UgrJbFh+SLiLmazC4w7+yUqOAKCt9PFkQdIpzJ222cKwm/zA9jQWDnp
kJlB8uk33im3Q69h69Y9k2xPnQKBgQDIDdFk/IJSGhJC7ppAV1taWi6w5G2W4KjS
yIhwAjEfaaC/dB5nJq0FGO0lbCk7uIP3PFpHQcK0xm0ExNMHCaGBrlkBEckkAqMp
jMILL2s6wbtjD+xXYOcmE07C7tcWakL567iyFsQZs1yf+6rrGsq1csraHmm5/bC7
637HrBzeQwKBgQC6g5vcNVSJo26v6YhFO+UGhPpGM1Z4wQs5asAY/RbIGfRN+8jb
+C/tRu9UlSBkFHlX6dNH5bT2JrP/Uqaebj8m+tThEYMbEwrDCU9kGO1JnkkO+qn1
0dM8MuZGrfgo+CE0WKFKEi6oSzq/CRqe0tB9Fa2ut9B4MOfgmKXVqF1tcQKBgHIT
hxL59mpQ2Zb3LliAN+SGxlcyetdtVneTyFFuvoo2Fmb2FRwm7sSYWSpcygp3BjFm
Zeh6NEgXWjU880TxFfq366LzfGofYuEflcsBCDliHbO4ccHFzSlmGySHQ3lRsM2I
wDI1Ty+Ems3Tmbwk8/CR++BzNUDMzAnsmMfNeky3AoGBAKpPA/NsYbRe0VI3ES2o
Gl6N+cJhEpT0GgTj5GzHXFD7QBukdlDpmuulJPk+59zDB8k9S5d1wvN5nPkydLiw
7p5XxwaXuFzjPZLE5TusSjYp7cQvK4nO+dCMvIIOgsVkNXi5f2BQ1geXZEC1oURw
aricx8laZCSpKEVHpOqoC5vY
-----END PRIVATE KEY-----`;

const encriptarRSA = (texto) => {
    try {
    const buffer = Buffer.from(texto, 'utf8');
        const encrypted = crypto.publicEncrypt({
            key: RSA_PUBLIC_KEY,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        }, buffer);
    return encrypted.toString('base64');
    } catch (error) {
        throw new Error('Error en encriptación RSA: ' + error.message);
    }
};

// Función para desencriptar RSA
const desencriptarRSA = (textoEncriptado) => {
    try {
        const buffer = Buffer.from(textoEncriptado, 'base64');
        const decrypted = crypto.privateDecrypt({
            key: RSA_PRIVATE_KEY,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        }, buffer);
        return decrypted.toString('utf8');
    } catch (error) {
        throw new Error('Error en desencriptación RSA: ' + error.message);
    }
};

export const verificarContrasenaSHA1 = async (req, res) => {
    try {
        const { usuario, contrasena } = req.body;

        // Validamos los datos
        if (!usuario || !contrasena) {
            return res.status(400).json({ msg: "Bad Request. Please provide ID and password." });
        }

        // Encriptamos la contraseña
        const contrasenaEncriptada = encriptarSHA1(contrasena);

        // Obtenemos la conexión
        const usuarios = await getConnection();

        // Ejecutamos la función almacenada
        const result = await usuarios.query(querysVerificarContrasena.verificarSha1, [usuario, contrasenaEncriptada]);

        // Liberamos la conexión
        usuarios.release();

        const esCorrecta = result.rows.length > 0;

        // Devolvemos el resultado
        res.json({ resultado: esCorrecta ? 1 : 0 });
    } catch (error) {
        res.status(500).send(error.message);
    }
};

export const verificarContrasenaMD5 = async (req, res) => {
    try {
        const { usuario, contrasena } = req.body;

        // Validamos los datos
        if (!usuario || !contrasena) {
            return res.status(400).json({ msg: "Bad Request. Please provide ID and password." });
        }

        // Encriptamos la contraseña
        const contrasenaEncriptada = encriptarMD5(contrasena);

        // Obtenemos la conexión
        const usuarios = await getConnection();

        // Ejecutamos la función almacenada
        const result = await usuarios.query(querysVerificarContrasena.verificarMD5, [usuario, contrasenaEncriptada]);

        // Liberamos la conexión
        usuarios.release();

        const esCorrecta = result.rows.length > 0;

        res.json({ resultado: esCorrecta ? 1 : 0 });
    } catch (error) {
        res.status(500).send(error.message);
    }
};

export const verificarContrasenaHash = async (req, res) => {
    try {
        const { usuario, contrasena } = req.body;

        // Validamos los datos
        if (!usuario || !contrasena) {
            return res.status(400).json({ msg: "Bad Request. Please provide ID and password." });
        }

        // Obtenemos la conexión
        const usuarios = await getConnection();

        // Obtenemos el hash almacenado en la base de datos
        const result = await usuarios.query(querysVerificarContrasena.obtenerhash, [usuario]);

        // Ejecutamos la función almacenada
        //const result = await usuarios.query(querysVerificarContrasena.verificarHash, [usuario, contrasenaEncriptada]);

        // Liberamos la conexión
        usuarios.release();

        if (result.rows.length === 0) {
            return res.status(404).json({ msg: "User not found." });
        }

        const hashAlmacenado = result.rows[0].contrasena_hash;

        // Comparamos la contraseña ingresada con el hash almacenado
        const esCorrecta = await bcrypt.compare(contrasena, hashAlmacenado);

        // Devolvemos el resultado
        res.json({ resultado: esCorrecta ? 1 : 0 });
    } catch (error) {
        res.status(500).send(error.message);
    }
};

export const verificarContrasenaRSA = async (req, res) => {
    try {
        const { usuario, contrasena } = req.body;

        // Validamos los datos
        if (!usuario || !contrasena) {
            return res.status(400).json({ msg: "Bad Request. Please provide user and password." });
        }

        // Obtenemos la conexión
        const usuarios = await getConnection();

        // Obtenemos la contraseña RSA almacenada en la base de datos
        const result = await usuarios.query(querysVerificarContrasena.obtenerRSA, [usuario]);

        // Liberamos la conexión
        usuarios.release();

        if (result.rows.length === 0) {
            return res.status(404).json({ msg: "User not found." });
        }

        const rsaAlmacenado = result.rows[0].contrasena_rsa;

        // Desencriptamos la contraseña almacenada y la comparamos con la ingresada
        const contrasenaDesencriptada = desencriptarRSA(rsaAlmacenado);
        const esCorrecta = contrasena === contrasenaDesencriptada;

        // Devolvemos el resultado
        res.json({ resultado: esCorrecta ? 1 : 0 });
    } catch (error) {
        res.status(500).send(error.message);
    }
};