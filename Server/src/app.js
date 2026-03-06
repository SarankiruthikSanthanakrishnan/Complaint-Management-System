import express from 'express';
import HandleError from './helper/HandleError.js';
import AppHandler from './middleware/AppHandler.js';
import AuthRoutes from './routes/AuthRoutes.js';
import cookieParser from 'cookie-parser';
import cors from "cors"
import AdminRoutes from './routes/AdminRoutes.js';
import path from 'path';
import { fileURLToPath } from 'url';
import MsRoutes from './routes/MsRoutes.js';
import TechnicianRoutes from './routes/TechnicianRoutes.js';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

app.use(cors({
  origin:['http://localhost:5173','http://10.28.207.123:5173','exp://10.28.207.123:8081','http://10.28.207.123:8081','http://localhost:8081'],
  credentials:true
}
))
app.use(cookieParser());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/api/v1/auth', AuthRoutes);
app.use('/api/v1/admin', AdminRoutes);
app.use('/api/v1/msadmin',MsRoutes);
app.use('/api/v1/technician', TechnicianRoutes);

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.originalUrl}`,
  });
});

app.use(AppHandler);

export default app;
