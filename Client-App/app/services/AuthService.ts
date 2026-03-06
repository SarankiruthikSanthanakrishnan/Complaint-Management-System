import api from "./Api"


export const UserVerify = (data:string)=>{
   return   api.post('/auth/user/verify-regno', { reg_no: data });
}

export const UserRegister = (userData:Object)=>{
   return api.post('/auth/user/register',{userData});
}

export const UserLogin = (username:string,password:string)=>{
   return api.post('/auth/user/login',{username,password});
}

export const CurrentUser = ()=>{
   return api.get('/auth/user/get-user');
}

export const UserLogout = ()=>{
   return api.post('/auth/user/logout');
}

