import express from 'express';
import isAuthenticated from '../middleware/verifyToken.js';
import {
  AddManyUser,
  AddSingleUser,
  getAllUsers,
  getUserById,
  updateSingleUser,
  deleteSingleUser,
  deleteMultipleUsers,
  updateManyUser,
} from '../controller/AdminController.js';
import ExcelUpload from '../middleware/ExcelUpload.js';
import authorizedRoles from '../middleware/allowedRoles.js';
import forcePasswordChange from '../middleware/forcePasswordChange.js';

const AdminRoutes = express.Router();

AdminRoutes.route('/user/add').post(
  isAuthenticated,
  forcePasswordChange,
  authorizedRoles('Admin', 'MasterAdmin'),
  AddSingleUser
);

AdminRoutes.route('/user/multiple').post(
  isAuthenticated,
  forcePasswordChange,
  authorizedRoles('Admin', 'MasterAdmin'),
  ExcelUpload.single('file'),
  AddManyUser
);

AdminRoutes.route('/user/getUsers').get(
  isAuthenticated,
  forcePasswordChange,
  authorizedRoles('Admin', 'MasterAdmin'),
  getAllUsers
);

AdminRoutes.route('/user/delete-multiple').delete(
  isAuthenticated,
  forcePasswordChange,
  authorizedRoles('Admin', 'MasterAdmin'),
  deleteMultipleUsers
);

AdminRoutes.route('/user/update-multiple').put(
  isAuthenticated,
  forcePasswordChange,
  authorizedRoles('Admin', 'MasterAdmin'),
  ExcelUpload.single('file'),
  updateManyUser
);

AdminRoutes.route('/user/:id')
  .get(
    isAuthenticated,
    forcePasswordChange,
    authorizedRoles('Admin', 'MasterAdmin'),
    getUserById
  )
  .put(
    isAuthenticated,
    forcePasswordChange,
    authorizedRoles('Admin', 'MasterAdmin'),
    updateSingleUser
  )
  .delete(
    isAuthenticated,
    forcePasswordChange,
    authorizedRoles('Admin', 'MasterAdmin'),
    deleteSingleUser
  );

export default AdminRoutes;
