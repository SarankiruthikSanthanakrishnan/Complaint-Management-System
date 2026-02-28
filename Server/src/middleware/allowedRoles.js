import HandleError from '../helper/HandleError.js';

const authorizedRoles = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new HandleError(
          "Forbidden You don't have permission to access this resource",
          403
        )
      );
    }
    next();
  };
};

export default authorizedRoles;
