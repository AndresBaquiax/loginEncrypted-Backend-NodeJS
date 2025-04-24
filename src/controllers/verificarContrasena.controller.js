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