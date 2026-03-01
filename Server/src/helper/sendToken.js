import jwt from 'jsonwebtoken';

const sendToken = (options) => {
  const refreshToken = jwt.sign(
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
  const accessToken = jwt.sign(
    {
      id: options.id,
      role: options.role,
      must_change_password: options.must_change_password,
    },
    process.env.ACCESS_TOKEN_KEY,
    {
      expiresIn: process.env.ACCESS_EXPIRES_IN,
    }
  );
  return { refreshToken, accessToken };
};

export default sendToken;
