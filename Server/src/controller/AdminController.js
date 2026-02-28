import HandleError from '../helper/HandleError.js';
import db from '../config/db.js';
import bcrypt from 'bcryptjs';
import XLSX from 'xlsx';

export const AddSingleUser = async (req, res, next) => {
  try {
    const { username, full_name, email, contact, role, department } = req.body;
    const allowedRoles = ['Faculty', 'Incharge', 'Technician'];
    if (!allowedRoles.includes(role)) {
      return next(
        new HandleError(
          'Invalid role. Only Faculty/Incharge/Technician allowed',
          400
        )
      );
    }
    if (!username || !full_name || !email || !contact || !role || !department) {
      return next(new HandleError('All fields are required', 400));
    }
    const existingUser = await db.query(
      'SELECT id FROM users WHERE username=$1 OR email=$2',
      [username, email]
    );
    if (existingUser.rowCount > 0) {
      return next(new HandleError('Username or Email already exists', 400));
    }

    const password_hash = await bcrypt.hash('User@1234', 10);
    await db.query(
      `INSERT INTO users (username, full_name, email, contact, role, department, password_hash,must_change_password)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [username, full_name, email, contact, role, department, password_hash, true]
    );
    res.status(201).json({
      success: true,
      message: 'User added successfully',
    });
  } catch (error) {
    return next(new HandleError('Unable to add user', 500));
  }
};

export const AddManyUser = async (req, res, next) => {
  try {
    const password = 'User@1234';
    const password_hash = await bcrypt.hash(password, 10);

    const file = req.file;
    if (!file) return next(new HandleError('No file uploaded', 400));

    const workbook = XLSX.read(file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];

    const jsonData = XLSX.utils.sheet_to_json(worksheet, { defval: '' });

    if (jsonData.length === 0) {
      return next(new HandleError('Excel file is empty', 400));
    }

    const allowedRoles = ['Faculty', 'Incharge', 'Technician'];


    for (let i = 0; i < jsonData.length; i++) {
      const role = String(jsonData[i].Role).trim();

      if (!allowedRoles.includes(role)) {
        return next(
          new HandleError(
            `Invalid role "${role}" found in Excel row ${i + 2}. Only Faculty/Incharge/Technician allowed.`,
            400
          )
        );
      }
    }

    let inserted = 0;
    let skipped = 0;

    for (const user of jsonData) {
      const username = String(user.Username).trim();
      const email = String(user.Email).trim();

      const existingUser = await db.query(
        'SELECT id FROM users WHERE username=$1 OR email=$2',
        [username, email]
      );

      if (existingUser.rowCount > 0) {
        skipped++;
        continue;
      }
      await db.query(
        `INSERT INTO users (username, full_name, email, contact, role, department, password_hash, must_change_password)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          username,
          user.Full_name,
          email,
          user.Contact,
          user.Role,
          user.Department,
          password_hash,
          true,
        ]
      );

      inserted++;
    }

    return res.status(201).json({
      success: true,
      message: 'Users upload completed',
      inserted,
      skipped,
    });
  } catch (error) {
    return next(
      new HandleError(error.message || 'Unable to upload users', 500)
    );
  }
};

export const getAllUsers = async (req, res, next) => {
  try {
    const users = await db.query(
      'SELECT id, username, full_name, email, contact, role, department FROM users'
    );
    return res.status(200).json({
      success: true,
      users: users.rows,
    });
  } catch (error) {
    return next(new HandleError(error.message || 'Unable to fetch users', 500));
  }
};

export const getUserById = async (req, res, next) => {
  try {
    const userId = req.params.id;
    const user = await db.query(
      'SELECT id, username, full_name, email, contact, role, department FROM users WHERE id=$1',
      [userId]
    );
    if (user.rowCount === 0) {
      return next(new HandleError('User not found', 404));
    }
    return res.status(200).json({
      success: true,
      user: user.rows[0],
    });
  } catch (error) {
    return next(new HandleError(error.message || 'Unable to fetch user', 500));
  }
};

export const updateSingleUser = async (req, res, next) => {
  try {
    const userId = req.params.id;
    const { full_name, email, contact, role, department } = req.body;

    if(!email){
      return next(new HandleError('Email is required', 400));
    }
    if(!full_name || full_name.trim() === ''){
      return next(new HandleError('Full Name is required', 400));
    }
    if(!contact || contact.trim() === ''){
      return next(new HandleError('Contact is required', 400));
    }
    if(!role || role.trim() === ''){
      return next(new HandleError('Role is required', 400));
    }
    if(!department || department.trim() === ''){
      return next(new HandleError('Department is required', 400));
    }

    if(!email.includes('@')){
      return next(new HandleError('Invalid email', 400));
    }

    const allowedRoles = ['Admin','MasterAdmin','Faculty', 'Incharge', 'Technician', 'Student'];
    if (!allowedRoles.includes(role)) {
      return next(
        new HandleError(
          'Invalid role. Only Admin/MasterAdmin/Faculty/Incharge/Technician/Student allowed',
          400
        )
      );
    }

    const existingUser = await db.query('SELECT id, role FROM users WHERE id=$1', [userId]);
    if (existingUser.rowCount === 0) {
      return next(new HandleError('User not found', 404));
    }

    if (existingUser.rows[0].role === 'MasterAdmin') {
      return next(new HandleError('Cannot update a MasterAdmin user', 403));
    }

    await db.query(
      `UPDATE users SET full_name=$1, email=$2, contact=$3, role=$4, department=$5 WHERE id=$6`,
      [full_name, email, contact, role, department, userId]
    );

    return res.status(200).json({
      success: true,
      message: 'User updated successfully',
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to Update User', 500));
  }
};

export const updateManyUser = async (req, res, next) => {
  try {
    const file = req.file;
    if (!file) {
      return next(new HandleError('File Not Yet Uploaded', 400));
    }

    const workBook = XLSX.read(file.buffer, { type: 'buffer' });
    const sheetName = workBook.SheetNames[0];
    const workSheet = workBook.Sheets[sheetName];

    const jsonData = XLSX.utils.sheet_to_json(workSheet, { defval: '' });

    if (jsonData.length === 0) {
      return next(new HandleError('Excel file is empty', 400));
    }

    const allowedRoles = ['Faculty', 'Incharge', 'Technician'];

    for (let i = 0; i < jsonData.length; i++) {
      const role = String(jsonData[i].Role || '').trim();

      if (role && !allowedRoles.includes(role)) {
        return next(
          new HandleError(
            `Invalid role "${role}" found in Excel row ${i + 2}. Only Faculty/Incharge/Technician allowed.`,
            400
          )
        );
      }
    }

    let updated = 0;
    let notFound = 0;

    for (const user of jsonData) {
      const username = String(user.Username || '').trim();
      const email = String(user.Email || '').trim();
      const full_name = String(user.Full_name || '').trim();
      const contact = String(user.Contact || '').trim();
      const role = String(user.Role || '').trim();
      const department = String(user.Department || '').trim();

      if (!username && !email) {
        continue;
      }

      const existingUser = await db.query(
        'SELECT id, role FROM users WHERE username=$1 OR email=$2',
        [username, email]
      );

      if (existingUser.rowCount === 0) {
        notFound++;
        continue;
      }

      if (['Admin'].includes(existingUser.rows[0].role)) {
        continue;
      }

      const userId = existingUser.rows[0].id;

      await db.query(
        `UPDATE users SET full_name=$1, email=$2, contact=$3, role=$4, department=$5 WHERE id=$6`,
        [full_name, email, contact, role, department, userId]
      );

      updated++;
    }

    return res.status(200).json({
      success: true,
      message: 'Users update completed',
      updated,
      notFound,
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to Update Users', 500));
  }
};

export const deleteSingleUser = async (req, res, next) => {
  try {
    const userId = req.params.id;
    const existingUser = await db.query('SELECT id, role FROM users WHERE id=$1', [userId]);

    if (existingUser.rowCount === 0) {
      return next(new HandleError('User not found', 404));
    }
    if (['Admin', 'MasterAdmin'].includes(existingUser.rows[0].role)) {
      return next(new HandleError('Cannot delete an Admin or MasterAdmin user', 403));
    }

    await db.query('DELETE FROM users WHERE id=$1', [userId]);

    return res.status(200).json({
      success: true,
      message: 'User deleted successfully',
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to Delete User', 500));
  }
};

export const deleteMultipleUsers = async (req, res, next) => {
  try {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return next(new HandleError('Please provide an array of user IDs to delete', 400));
    }

    const existingUsers = await db.query(
      'SELECT id, role FROM users WHERE id = ANY($1::int[])',
      [userIds]
    );

    if (existingUsers.rowCount === 0) {
      return next(new HandleError('No users found to delete', 404));
    }

    const hasAdmin = existingUsers.rows.some((user) => ['Admin', 'MasterAdmin'].includes(user.role));

    if (hasAdmin) {
      return next(new HandleError('Cannot delete Admin or MasterAdmin users. Please remove them from selection.', 403));
    }

    await db.query('DELETE FROM users WHERE id = ANY($1::int[])', [userIds]);

    return res.status(200).json({
      success: true,
      message: `${existingUsers.rowCount} users deleted successfully`,
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to Delete Users', 500));
  }
};


