import jwt from 'jsonwebtoken';

export const createToken = (userId) => {
  const token = jwt.sign(
    { user: userId, type: 'password-reset' },
    process.env.RESET_KEY,
    {
      expiresIn: '5m',
    }
  );
  return token;
};
