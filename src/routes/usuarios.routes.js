import { Router } from 'express';
import { getUsuarios, getUsuariosById, postUsuarios, putUsuarios, deleteUsuarios } from '../controllers/usuarios.controller.js';

const router = Router();

router.get('/usuarios', getUsuarios);
router.get('/usuarios/:idusuario', getUsuariosById);
router.post('/usuarios', postUsuarios);
router.put('/usuarios/:idusuario', putUsuarios);
router.delete('/usuarios/:idusuario', deleteUsuarios);

export default router;
