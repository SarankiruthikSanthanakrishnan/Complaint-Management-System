import jwt from 'jsonwebtoken';
import HandleError from '../helper/HandleError.js';

const isAuthenticated = (req, res, next) => {
  const authHead = req.headers.Authorization || req.headers.authorization;
  const token =
    (authHead && authHead.split(' ')[1]) || req.cookies.accessToken || '';
  if (!token) {
    return next(new HandleError('Unauthorized Access', 401));
  }
  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    console.log(error);
    return next(new HandleError('Invalid Token', 401));
  }
};

export default isAuthenticated;
