import dotenv from 'dotenv';

const loadEnv = dotenv.config({
  path: './src/config/config.env',
  quiet: true,
});

export default loadEnv;
