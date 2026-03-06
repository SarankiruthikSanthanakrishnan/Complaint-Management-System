import api from "./api.js"

export const verifyRegNo = (reg_no)=>{
    return (
        api.post('/auth/user/verify-regno',{reg_no})
    )
}

export const login = (username,password)=>{
    return (
        api.post('/auth/user/login',{username,password})
    )
}

export const currentUser = ()=>{
    return (
        api.get('/auth/user/get-user')
    )
}


