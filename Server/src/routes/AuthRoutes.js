import express from 'express';
import {
  changePassword,
  forgotPassword,
  getAuthUser,
  login,
  logout,
  register,
  resetPassword,
  updateProfile,
  verifyRegNo,
} from '../controller/AuthController.js';
import isAuthenticated from '../middleware/verifyToken.js';
import ProfileUpload from '../middleware/ProfileUpload.js';

const AuthRoutes = express.Router();

AuthRoutes.route('/user/verify-regno').post(verifyRegNo);
AuthRoutes.route('/user/register').post(register);
AuthRoutes.route('/user/login').post(login);
AuthRoutes.route('/user/get-user').get(isAuthenticated, getAuthUser);
AuthRoutes.route('/user/logout').post(logout);
AuthRoutes.route('/user/updateProfile').put(
  isAuthenticated,
  ProfileUpload.single('file'),
  updateProfile
);
AuthRoutes.route('/user/forgot-password').post(forgotPassword);
AuthRoutes.route('/user/reset-password/:token').post(resetPassword);
AuthRoutes.route('/user/change-password').post(isAuthenticated, changePassword);

export default AuthRoutes;
