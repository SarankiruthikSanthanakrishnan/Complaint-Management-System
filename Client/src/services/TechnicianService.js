import api from './api';

export const GetAllTechnicians = () => {
  return api.get('/technician/getAll');
};

export const GetTechnicianById = (id) => {
  return api.get(`/technician/${id}`);
};

export const UpdateTechnician = (id, technicianData) => {
  return api.put(`/technician/${id}`, technicianData);
};

export const DeleteTechnician = (id) => {
  return api.delete(`/technician/${id}`);
};
