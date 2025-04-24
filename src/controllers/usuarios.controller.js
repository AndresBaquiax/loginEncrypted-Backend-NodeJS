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
        const { nombre, apellido, email, usuario, contrasena_hash, contrasena_md5, contrasena_sha1 } = req.body;
        let { status } = req.body;

        // Validamos los datos
        if ( !nombre || !apellido || !email|| !usuario || !contrasena_hash || !contrasena_md5 || !contrasena_sha1 ) {
            return res.status(400).json({ msg: "Bad Request. Please fill all fields." });
        }
        
        const contrasenasha1 = encriptarSHA1(contrasena_sha1);
        const contrasenamd5 = encriptarMD5(contrasena_md5);
        const contrasenahash = hashearTexto(contrasena_hash);

        status = 1;

        // Obtenemos la conexion
        const usuarios = await getConnection();

        // Ejecutamos la consulta
        await usuarios.query(querysUsuarios.postUsuarios, [
            nombre, apellido, email, usuario, contrasenahash, contrasenamd5, contrasenasha1, status
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
        const { nombre, apellido, email, usuario, contrasena_hash, contrasena_md5, contrasena_sha1 } = req.body;
        let { status } = req.body;

        // Validamos los datos
        if ( !nombre || !apellido || !email|| !usuario || !contrasena_hash || !contrasena_md5 || !contrasena_sha1 ) {
            return res.status(400).json({ msg: "Bad Request. Please fill all fields." });
        }

        const contrasenasha1 = encriptarSHA1(contrasena_sha1);
        const contrasenamd5 = encriptarMD5(contrasena_md5);
        const contrasenahash = hashearTexto(contrasena_hash);
        status = 1;

        // Obtenemos la conexion
        const usuarios = await getConnection();

        // Ejecutamos la consulta
        await usuarios.query(querysUsuarios.putUsuarios, [
            nombre, apellido, email, usuario, contrasenahash, contrasenamd5, contrasenasha1, status, idusuario
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