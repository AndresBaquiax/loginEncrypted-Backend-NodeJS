export const querysUsuarios = {
    getUsuarios: "SELECT * FROM usuarios WHERE status = 1",
    getUsuariosById: "SELECT * FROM usuarios WHERE idusuario = $1",
    postUsuarios: "INSERT INTO usuarios (nombre, apellido, email, usuario, contrasena_hash, contrasena_md5, contrasena_sha1, status) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 )",
    putUsuarios: "UPDATE usuarios SET nombre = $1, apellido = $2, email = $3, usuario = $4, contrasena_hash = $5, contrasena_md5 = $6, contrasena_sha1 = $7, status = $8 WHERE idusuario = $9",
    deleteUsuarios: "SELECT statusServicio($1)"
};

export const querysVerificarContrasena = {
    verificarHash: "SELECT verificarcontrasenahash($1, $2)",
    verificarMD5: "SELECT verificarContrasenaMD5($1, $2)",
    verificarSha1: "SELECT verificarContrasenaSHA1($1, $2)",
    obtenerhash: "SELECT contrasena_hash FROM usuarios WHERE usuario = $1"
};