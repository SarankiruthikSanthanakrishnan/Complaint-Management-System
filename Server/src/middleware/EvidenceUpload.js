import multer from 'multer';
import HandleError from '../helper/HandleError.js';

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'src/uploads/evidences/');
  },
  filename: (req, file, cb) => {
    const complaintCode = req.body.complaint_code;
    const extname = file.originalname.split('.').pop();
    const filename = `${complaintCode}_${Date.now()}.${extname}`;
    cb(null, filename);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg',
    'image/jpg',
    'image/png',
    'application/pdf',
  ];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new HandleError(
        'Invalid file type. Only JPEG, JPG, PNG, and PDF are allowed.',
        400
      ),
      false
    );
  }
};

const EvidenceUpload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 },
});

export default EvidenceUpload;
