import multer from 'multer';
import path from 'path';

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'src/uploads/');
  },
  filename: (req, file, cb) => {
    const extname = path.extname(file.originalname);
    const filename = `${req.user.id}${extname}`;
    cb(null, filename);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error('Invalid file type. Only JPEG, JPG, and PNG are allowed.'),
      false
    );
  }
};

const ProfileUpload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 0.5 * 1024 * 1024 },
});

export default ProfileUpload;
