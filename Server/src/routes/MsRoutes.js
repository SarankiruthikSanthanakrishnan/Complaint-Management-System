import express from 'express';
import isAuthenticated from '../middleware/verifyToken.js';
import authorizedRoles from '../middleware/allowedRoles.js';
import forcePasswordChange from '../middleware/forcePasswordChange.js';
import { AddAdmin, getAllAdmins, getAdminById, updateAdmin, deleteAdmin } from '../controller/MasterAdminController.js';

const MsRoutes = express.Router();

MsRoutes.route('/admin/add').post(
    isAuthenticated,
    forcePasswordChange,
    authorizedRoles('MasterAdmin'),
    AddAdmin
);

MsRoutes.route('/admin/getAdmins').get(
    isAuthenticated,
    forcePasswordChange,
    authorizedRoles('MasterAdmin'),
    getAllAdmins
);

MsRoutes.route('/admin/:id')
    .get(
        isAuthenticated,
        forcePasswordChange,
        authorizedRoles('MasterAdmin'),
        getAdminById
    )
    .put(
        isAuthenticated,
        forcePasswordChange,
        authorizedRoles('MasterAdmin'),
        updateAdmin
    )
    .delete(
        isAuthenticated,
        forcePasswordChange,
        authorizedRoles('MasterAdmin'),
        deleteAdmin
    );

export default MsRoutes;
