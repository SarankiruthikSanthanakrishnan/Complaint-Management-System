import api from './Api';

export const GetAllUsers = () => {
  return api.get('/admin/user/getUsers');
};

export const GetSingleUser = (id: number) => {
  return api.get(`/admin/user/${id}`);
};

export const UpdateSingleUser = (id: number) => {
  return api.put(`/admin/user/${id}`);
};

export const UpdateManyUser = () => {
  return api.put('/admin/user/update-multiple', {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};

export const DeleteSingleUser = (id: number) => {
  return api.delete(`/admin/user/${id}`);
};

export const DeleteMultipleUser = () => {
  return api.delete('/admin/user/delete-multiple', {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};
