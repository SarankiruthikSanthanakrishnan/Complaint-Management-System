import express from 'express';
import isAuthenticated from '../middleware/verifyToken.js';
import authorizedRoles from '../middleware/allowedRoles.js';
import forcePasswordChange from '../middleware/forcePasswordChange.js';
import {
  AddSingleTechnician,
  getAllTechnicians,
  getTechnicianById,
  updateTechnician,
  deleteTechnician,
  deleteMultipleTechnicians
} from '../controller/TechnicianController.js';

const TechnicianRoutes = express.Router();

TechnicianRoutes.route('/add').post(
  isAuthenticated,
  forcePasswordChange,
  authorizedRoles('Admin', 'MasterAdmin'),
  AddSingleTechnician
);

TechnicianRoutes.route('/getAll').get(
  isAuthenticated,
  forcePasswordChange,
  authorizedRoles('Admin', 'MasterAdmin'),
  getAllTechnicians
);

TechnicianRoutes.route('/delete-multiple').delete(
  isAuthenticated,
  forcePasswordChange,
  authorizedRoles('Admin', 'MasterAdmin'),
  deleteMultipleTechnicians
);

TechnicianRoutes.route('/:id')
  .get(
    isAuthenticated,
    forcePasswordChange,
    authorizedRoles('Admin', 'MasterAdmin'),
    getTechnicianById
  )
  .put(
    isAuthenticated,
    forcePasswordChange,
    authorizedRoles('Admin', 'MasterAdmin'),
    updateTechnician
  )
  .delete(
    isAuthenticated,
    forcePasswordChange,
    authorizedRoles('Admin', 'MasterAdmin'),
    deleteTechnician
  );

export default TechnicianRoutes;
