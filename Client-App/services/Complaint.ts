import api from './Api';

export const AddComplaint = (complaintData: Object) => {
  return api.post('/complaint/user/add', complaintData);
};
