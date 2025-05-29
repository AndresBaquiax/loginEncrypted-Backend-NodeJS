import { getConnection, querysUsuarios } from "../database/index.js";
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


// --------------------- GET ---------------------
export const getUsuarios = async (req, res) => {
    try {
        // Obtenemos la conexion
        const connection = await getConnection();
        const result = await connection.query(querysUsuarios.getUsuarios);
        // Liberamos la conexion
        connection.release();
        res.json(result.rows);
    } catch (error) {
        res.status(500).send(error.message);
    }
};

// --------------------- GET BY ID ---------------------
export const getUsuariosById = async (req, res) => {
    try {
        const { idusuario } = req.params;

        // Obtenemos la conexion
        const usuarios = await getConnection();

        // Ejecutamos la consulta
        const result = await usuarios.query(querysUsuarios.getUsuariosById, [idusuario]);

        // Liberamos la conexion
        usuarios.release();

        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).send(error.message);
    }
};

// --------------------- POST ---------------------
export const postUsuarios = async (req, res) => {
    try {
        const { nombre, apellido, email, usuario, contrasena_hash, contrasena_md5, contrasena_sha1, contrasena_rsa } = req.body;
        let { status } = req.body;

        // Validamos los datos
        if ( !nombre || !apellido || !email|| !usuario || !contrasena_hash || !contrasena_md5 || !contrasena_sha1 || !contrasena_rsa ) {
            return res.status(400).json({ msg: "Bad Request. Please fill all fields." });
        }
        
        const contrasenasha1 = encriptarSHA1(contrasena_sha1);
        const contrasenamd5 = encriptarMD5(contrasena_md5);
        const contrasenahash = hashearTexto(contrasena_hash);
        const contrasenarsa = encriptarRSA(contrasena_rsa);

        status = 1;

        // Obtenemos la conexion
        const usuarios = await getConnection();

        // Ejecutamos la consulta
        await usuarios.query(querysUsuarios.postUsuarios, [
            nombre, apellido, email, usuario, contrasenahash, contrasenamd5, contrasenasha1, status, contrasenarsa
        ]);

        // Liberamos la conexion
        usuarios.release();

        res.json({ msg: "User added successfully" });
    } catch (error) {
        res.status(500).send(error.message);
    }
};

// --------------------- PUT ---------------------
export const putUsuarios = async (req, res) => {
    try {
        const { idusuario } = req.params;
        const { nombre, apellido, email, usuario, contrasena_hash, contrasena_md5, contrasena_sha1, contrasena_rsa } = req.body;
        let { status } = req.body;

        // Validamos los datos
        if ( !nombre || !apellido || !email|| !usuario || !contrasena_hash || !contrasena_md5 || !contrasena_sha1 || !contrasena_rsa ) {
            return res.status(400).json({ msg: "Bad Request. Please fill all fields." });
        }

        const contrasenasha1 = encriptarSHA1(contrasena_sha1);
        const contrasenamd5 = encriptarMD5(contrasena_md5);
        const contrasenahash = hashearTexto(contrasena_hash);
        const contrasenarsa = encriptarRSA(contrasena_rsa);

        status = 1;

        // Obtenemos la conexion
        const usuarios = await getConnection();

        // Ejecutamos la consulta
        await usuarios.query(querysUsuarios.putUsuarios, [
            nombre, apellido, email, usuario, contrasenahash, contrasenamd5, contrasenasha1, status, contrasenarsa, idusuario
        ]);

        // Liberamos la conexion
        usuarios.release();

        res.json({ msg: "Service updated successfully" });
    } catch (error) {
        res.status(500).send(error.message);
    }
};

// --------------------- DELETE ---------------------
export const deleteUsuarios = async (req, res) => {
    try {
        const { idusuario } = req.params;

        // Obtenemos la conexion
        const usuarios = await getConnection();

        // Ejecutamos la consulta
        await usuarios.query(querysUsuarios.deleteUsuarios, [
            idusuario
        ]);

        // Liberamos la conexion
        usuarios.release();

        res.json({ msg: "Service deleted successfully" });
    } catch (error) {
        res.status(500).send(error.message);
    }
}