import { Router } from 'express';
import { verificarContrasenaSHA1, verificarContrasenaMD5, verificarContrasenaHash, verificarContrasenaRSA } from '../controllers/verificarContrasena.controller.js';

const router = Router();

router.post('/usuarios/verificarsha1', verificarContrasenaSHA1);
router.post('/usuarios/verificarmd5', verificarContrasenaMD5);
router.post('/usuarios/verificarhash', verificarContrasenaHash);
router.post('/usuarios/verificarrsa', verificarContrasenaRSA); // Assuming the same controller handles RSA verification

export default router;
