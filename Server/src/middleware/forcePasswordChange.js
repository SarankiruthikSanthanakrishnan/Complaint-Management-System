const forcePasswordChange = (req, res, next) => {
  if (req.user?.must_change_password === true) {
    return res.status(403).json({
      success: false,
      message: 'Change your password to proceed',
    });
  }
  next();
};

export default forcePasswordChange;
