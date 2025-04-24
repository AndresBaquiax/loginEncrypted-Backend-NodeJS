import { Router } from 'express';
import { verificarContrasenaSHA1, verificarContrasenaMD5, verificarContrasenaHash } from '../controllers/verificarContrasena.controller.js';

const router = Router();

router.post('/usuarios/verificarsha1', verificarContrasenaSHA1);
router.post('/usuarios/verificarmd5', verificarContrasenaMD5);
router.post('/usuarios/verificarhash', verificarContrasenaHash);

export default router;
