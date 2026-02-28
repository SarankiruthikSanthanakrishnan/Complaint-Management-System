import jwt from 'jsonwebtoken';

const sendToken = (options) => {
  const token = jwt.sign(
    {
      id: options.id,
      role: options.role,
      must_change_password: options.must_change_password,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN,
    }
  );
  return token;
};

export default sendToken;
