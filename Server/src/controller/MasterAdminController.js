import HandleError from '../helper/HandleError.js';
import db from '../config/db.js';
import bcrypt from 'bcryptjs';

// Add a single Admin user
export const AddAdmin = async (req, res, next) => {
  try {
    const { username, full_name, email, contact, department } = req.body;

    if(!username || username.trim() === ''){
      return next(new HandleError('Username is required', 400));
    }
    if(!full_name || full_name.trim() === ''){
      return next(new HandleError('Full Name is required', 400));
    }
    if(!email || email.trim() === ''){
      return next(new HandleError('Email is required', 400));
    }
    if(!contact || contact.trim() === ''){
      return next(new HandleError('Contact is required', 400));
    }
    if(!department || department.trim() === ''){
      return next(new HandleError('Department is required', 400));
    }

    if(!email.includes('@')){
      return next(new HandleError('Invalid email', 400));
    }

    const existingUser = await db.query(
      'SELECT id FROM users WHERE username=$1 OR email=$2',
      [username, email]
    );

    if (existingUser.rowCount > 0) {
      return next(new HandleError('Username or Email already exists', 400));
    }

    const password_hash = await bcrypt.hash('Admin@1234', 10);

    await db.query(
      `INSERT INTO users (username, full_name, email, contact, role, department, password_hash, must_change_password)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [username, full_name, email, contact, 'Admin', department, password_hash, true]
    );

    res.status(201).json({
      success: true,
      message: 'Admin added successfully',
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to add admin', 500));
  }
};

// Get all Admin users
export const getAllAdmins = async (req, res, next) => {
  try {
    const admins = await db.query(
      "SELECT id, username, full_name, email, contact, role, department FROM users WHERE role = 'Admin'"
    );

    return res.status(200).json({
      success: true,
      admins: admins.rows,
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to fetch admins', 500));
  }
};

// Get a single Admin by ID
export const getAdminById = async (req, res, next) => {
  try {
    const adminId = req.params.id;
    const admin = await db.query(
      "SELECT id, username, full_name, email, contact, role, department FROM users WHERE id=$1 AND role='Admin'",
      [adminId]
    );

    if (admin.rowCount === 0) {
      return next(new HandleError('Admin not found', 404));
    }

    return res.status(200).json({
      success: true,
      admin: admin.rows[0],
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to fetch admin', 500));
  }
};

// Update an Admin
export const updateAdmin = async (req, res, next) => {
  try {
    const adminId = req.params.id;
    const { full_name, email, contact, department } = req.body;

    if(!email){
      return next(new HandleError('Email is required', 400));
    }
    if(!full_name || full_name.trim() === ''){
      return next(new HandleError('Full Name is required', 400));
    }
    if(!contact || contact.trim() === ''){
      return next(new HandleError('Contact is required', 400));
    }
    if(!department || department.trim() === ''){
      return next(new HandleError('Department is required', 400));
    }

    if(!email.includes('@')){
      return next(new HandleError('Invalid email', 400));
    }

    const existingUser = await db.query("SELECT id, role FROM users WHERE id=$1 AND role='Admin'", [adminId]);

    if (existingUser.rowCount === 0) {
      return next(new HandleError('Admin not found', 404));
    }

    await db.query(
      `UPDATE users SET full_name=$1, email=$2, contact=$3, department=$4 WHERE id=$5`,
      [full_name, email, contact, department, adminId]
    );

    return res.status(200).json({
      success: true,
      message: 'Admin updated successfully',
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to update admin', 500));
  }
};

// Delete a single Admin
export const deleteAdmin = async (req, res, next) => {
  try {
    const adminId = req.params.id;
    const existingUser = await db.query("SELECT id, role FROM users WHERE id=$1 AND role='Admin'", [adminId]);

    if (existingUser.rowCount === 0) {
      return next(new HandleError('Admin not found', 404));
    }

    await db.query('DELETE FROM users WHERE id=$1', [adminId]);

    return res.status(200).json({
      success: true,
      message: 'Admin deleted successfully',
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to delete admin', 500));
  }
};

// Delete multiple Admins
export const deleteMultipleAdmins = async (req, res, next) => {
  try {
    const { adminIds } = req.body;

    if (!adminIds || !Array.isArray(adminIds) || adminIds.length === 0) {
      return next(new HandleError('Please provide an array of admin IDs to delete', 400));
    }

    const existingUsers = await db.query(
      "SELECT id FROM users WHERE id = ANY($1::int[]) AND role='Admin'",
      [adminIds]
    );

    if (existingUsers.rowCount === 0) {
      return next(new HandleError('No admins found to delete or invalid IDs provided', 404));
    }

    await db.query('DELETE FROM users WHERE id = ANY($1::int[]) AND role=$2', [adminIds, 'Admin']);

    return res.status(200).json({
      success: true,
      message: `${existingUsers.rowCount} admins deleted successfully`,
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to delete admins', 500));
  }
};
