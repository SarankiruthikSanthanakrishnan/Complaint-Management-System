import api from "./Api";

export const GetAllUsers = () => {
    return api.get('/admin/user/getUsers');
}

export const GetSingleUser = (id:number)=>{
    return api.get(`/admin/user/${id}`)
}
