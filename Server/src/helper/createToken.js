import crypto from 'crypto';

export const createToken = () => {
  const token = crypto.randomBytes(20).toString('hex');
  const resetToken = crypto.createHash('sha256').update(token).digest('hex');
  return { resetToken, token };
};
