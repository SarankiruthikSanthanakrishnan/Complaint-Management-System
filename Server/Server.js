import loadEnv from './src/config/env.js';
import app from './src/app.js';
import db from './src/config/db.js';
import ip from 'ip';

const port = process.env.PORT || 5000;

const networkIp = ip.address();

app.listen(port, (err) => {
  if (err) {
    console.log('Error in starting server:', err);
  }
  console.log(`Server is running on port http://localhost:${port}`);
  networkIp ? console.log(`Network Port : http://${networkIp}:${port}`):null;
});
