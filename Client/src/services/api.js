import axios from 'axios'
import React from 'react'

const api = axios.create({
        baseURL:"http://10.28.207.123:4500/api/v1",
        withCredentials:true,
    })

export default api
