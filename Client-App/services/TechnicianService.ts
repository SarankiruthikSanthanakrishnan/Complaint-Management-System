import api from './Api';

export const AddSingleTechnician = async (technicianData: any) => {
  return await api.post('/technician/add', technicianData);
};

export const GetAllTechnicians = async () => {
  return await api.get('/technician/getAll');
};

export const GetTechnicianById = async (id: string) => {
  return await api.get(`/technician/${id}`);
};

export const UpdateTechnician = async (id: string, technicianData: any) => {
  return await api.put(`/technician/${id}`, technicianData);
};

export const DeleteTechnician = async (id: string) => {
  return await api.delete(`/technician/${id}`);
};
