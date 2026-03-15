import express from 'express';
import {
  AddComplaint,
  getMyComplaints,
  getAllComplaints,
  getSingleComplaint,
} from '../controller/ComplaintController.js';
import isAuthenticated from '../middleware/verifyToken.js';
import EvidenceUpload from '../middleware/EvidenceUpload.js';
import authorizedRoles from '../middleware/allowedRoles.js';

const ComplaintRoutes = express.Router();

ComplaintRoutes.route('/user/add').post(
  isAuthenticated,
  EvidenceUpload.single('evidence'),
  AddComplaint
);
ComplaintRoutes.route('/user/get/self').get(isAuthenticated, getMyComplaints);
ComplaintRoutes.route('/admin/get/all').get(
  isAuthenticated,
  authorizedRoles('Admin', 'MasterAdmin'),
  getAllComplaints
);
ComplaintRoutes.route('/user/get/:complaint_code').get(
  isAuthenticated,
  getSingleComplaint
);
ComplaintRoutes.route('/admin/get').get(
  isAuthenticated,
  authorizedRoles('Admin', 'MasterAdmin'),
  getSingleComplaint
);

export default ComplaintRoutes;
