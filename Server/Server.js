import loadEnv from './src/config/env.js';
import app from './src/app.js';
import db from './src/config/db.js';

const port = process.env.PORT || 5000;

app.listen(port, (err) => {
  if (err) {
    console.log('Error in starting server:', err);
  }
  console.log(`Server is running on port http://localhost:${port}`);
});
