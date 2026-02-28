import jwt from 'jsonwebtoken';
import HandleError from '../helper/HandleError.js';

const isAuthenticated = (req, res, next) => {
  const token = req.cookies.token || '';
  if (!token) {
    return next(new HandleError('Unauthorized Access', 401));
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return next(new HandleError('Invalid Token', 401));
  }
};

export default isAuthenticated;
