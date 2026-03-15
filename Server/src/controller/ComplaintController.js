import db from '../config/db.js';
import HandleError from '../helper/HandleError.js';
import fs from 'fs';

export const AddComplaint = async (req, res, next) => {
  try {
    const { complaint_code, subject, description } = req.body;
    const userId = req.user.id;
    const evidence = req.file
      ? `/uploads/evidences/${req.file.filename}`
      : null;

    if (!subject) {
      return next(new HandleError('Subject is required', 400));
    }
    if (!description) {
      return next(new HandleError('Description is required', 400));
    }

    if (!evidence) {
      return next(
        new HandleError('Evidence is required Please Upload the Evidence', 400)
      );
    }

    const existingComplaint = await db.query(
      'SELECT * FROM complaints WHERE complaint_code = $1',
      [complaint_code]
    );

    if (existingComplaint.rows.length > 0) {
      return next(new HandleError('Complaint code already exists', 400));
    }

    const result = await db.query(
      'INSERT INTO complaints (complaint_code, subject, description, evidence_before, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [complaint_code, subject, description, evidence, userId]
    );
    const complaint = result.rows[0];
    res.status(201).json({
      success: true,
      message: 'Complaint added successfully',
      complaint: {
        complaintID: complaint.complaint_code,
        status: complaint.status,
        subject: complaint.subject,
      },
    });
  } catch (error) {
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) {
          console.error('Error deleting file:', err);
        } else {
          console.log('File deleted successfully');
        }
      });
    }
    console.log(error);
    return next(new HandleError('Adding Complaint Failed', 500));
  }
};

export const getMyComplaints = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const result = await db.query(
      'SELECT complaint_code, subject, status FROM complaints WHERE user_id = $1',
      [userId]
    );
    const complaints = result.rows;
    res.status(200).json({
      success: true,
      complaints,
    });
  } catch (error) {
    return next(new HandleError('Failed to fetch complaints', 500));
  }
};

export const getAllComplaints = async (req, res, next) => {
  try {
    const result = await db.query(
      'SELECT complaint_code, subject, description , status FROM complaints'
    );
    const complaints = result.rows;
    res.status(200).json({
      success: true,
      complaints,
    });
  } catch (error) {
    return next(new HandleError('Failed to fetch complaints', 500));
  }
};

export const getSingleComplaint = async (req, res, next) => {
  try {
    const complaint_code =
      req.query.complaint_code || req.params.complaint_code;
    if (!complaint_code) {
      return next(new HandleError('Complaint code is required', 400));
    }
    const result = await db.query(
      'SELECT complaint_code, subject, description , status FROM complaints WHERE complaint_code = $1',
      [complaint_code]
    );
    const complaint = result.rows[0];
    if (!complaint) {
      return next(new HandleError('Complaint not found', 404));
    }
    res.status(200).json({
      success: true,
      complaint,
    });
  } catch (error) {
    return next(new HandleError('Failed to fetch complaint', 500));
  }
};
