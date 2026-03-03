import HandleError from '../helper/HandleError.js';
import db from '../config/db.js';
import bcrypt from 'bcryptjs';

// Add a single Technician
export const AddSingleTechnician = async (req, res, next) => {
  try {
    const { username, full_name, email, contact, department, technician_code, specialization } = req.body;

    if (!username || !full_name || !email || !contact || !department || !technician_code || !specialization) {
      return next(new HandleError('All fields are required', 400));
    }

    const existingUser = await db.query(
      'SELECT id FROM users WHERE username=$1 OR email=$2',
      [username, email]
    );

    if (existingUser.rowCount > 0) {
      return next(new HandleError('Username or Email already exists', 400));
    }

    const existingTech = await db.query(
      'SELECT id FROM technicians WHERE technician_code=$1',
      [technician_code]
    );

    if (existingTech.rowCount > 0) {
      return next(new HandleError('Technician code already exists', 400));
    }

    const password_hash = await bcrypt.hash('Tech@1234', 10);

    await db.query('BEGIN');

    const userResult = await db.query(
      `INSERT INTO users (username, full_name, email, contact, role, department, password_hash, must_change_password)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [username, full_name, email, contact, 'Technician', department, password_hash, true]
    );

    const userId = userResult.rows[0].id;

    await db.query(
      `INSERT INTO technicians (user_id, technician_code, department, phone, specialization)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, technician_code, department, contact, specialization]
    );

    await db.query('COMMIT');

    res.status(201).json({
      success: true,
      message: 'Technician added successfully',
    });
  } catch (error) {
    await db.query('ROLLBACK');
    console.error(error);
    return next(new HandleError('Unable to add technician', 500));
  }
};

// Get all Technicians
export const getAllTechnicians = async (req, res, next) => {
  try {
    const query = `
      SELECT t.id, t.user_id, t.technician_code, t.department, t.phone, t.specialization, t.status, t.active,
             u.username, u.full_name, u.email
      FROM technicians t
      JOIN users u ON t.user_id = u.id
    `;
    const technicians = await db.query(query);

    return res.status(200).json({
      success: true,
      technicians: technicians.rows,
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to fetch technicians', 500));
  }
};

// Get a single Technician by ID
export const getTechnicianById = async (req, res, next) => {
  try {
    const technicianId = req.params.id;
    const query = `
      SELECT t.id, t.user_id, t.technician_code, t.department, t.phone, t.specialization, t.status, t.active,
             u.username, u.full_name, u.email
      FROM technicians t
      JOIN users u ON t.user_id = u.id
      WHERE t.id = $1
    `;
    const technician = await db.query(query, [technicianId]);

    if (technician.rowCount === 0) {
      return next(new HandleError('Technician not found', 404));
    }

    return res.status(200).json({
      success: true,
      technician: technician.rows[0],
    });
  } catch (error) {
    console.error(error);
    return next(new HandleError('Unable to fetch technician', 500));
  }
};

// Update a Technician
export const updateTechnician = async (req, res, next) => {
  try {
    const technicianId = req.params.id;
    const { full_name, email, contact, department, specialization, status, active } = req.body;

    if (!email || !full_name || !contact || !department || !specialization) {
      return next(new HandleError('All fields (except status/active) are required', 400));
    }

    if (!email.includes('@')) {
      return next(new HandleError('Invalid email', 400));
    }

    const technician = await db.query('SELECT user_id FROM technicians WHERE id=$1', [technicianId]);

    if (technician.rowCount === 0) {
      return next(new HandleError('Technician not found', 404));
    }

    const userId = technician.rows[0].user_id;

    await db.query('BEGIN');

    // Update users table
    await db.query(
      `UPDATE users SET full_name=$1, email=$2, contact=$3, department=$4 WHERE id=$5`,
      [full_name, email, contact, department, userId]
    );

    // Update technicians table
    await db.query(
      `UPDATE technicians SET department=$1, phone=$2, specialization=$3, status=COALESCE($4, status), active=COALESCE($5, active), updated_at=CURRENT_TIMESTAMP WHERE id=$6`,
      [department, contact, specialization, status || null, active !== undefined ? active : null, technicianId]
    );

    await db.query('COMMIT');

    return res.status(200).json({
      success: true,
      message: 'Technician updated successfully',
    });
  } catch (error) {
    await db.query('ROLLBACK');
    console.error(error);
    return next(new HandleError('Unable to update technician', 500));
  }
};

// Delete a single Technician
export const deleteTechnician = async (req, res, next) => {
  try {
    const technicianId = req.params.id;

    // We get the user_id from technicians table
    const technician = await db.query('SELECT user_id FROM technicians WHERE id=$1', [technicianId]);

    if (technician.rowCount === 0) {
      return next(new HandleError('Technician not found', 404));
    }

    const userId = technician.rows[0].user_id;

    await db.query('BEGIN');

    // Deleting from users table will cascade delete technicians table because of 'ON DELETE CASCADE'
    await db.query('DELETE FROM users WHERE id=$1', [userId]);

    await db.query('COMMIT');

    return res.status(200).json({
      success: true,
      message: 'Technician deleted successfully',
    });
  } catch (error) {
    await db.query('ROLLBACK');
    console.error(error);
    return next(new HandleError('Unable to delete technician', 500));
  }
};

// Delete multiple Technicians
export const deleteMultipleTechnicians = async (req, res, next) => {
  try {
    const { technicianIds } = req.body;

    if (!technicianIds || !Array.isArray(technicianIds) || technicianIds.length === 0) {
      return next(new HandleError('Please provide an array of technician IDs to delete', 400));
    }

    // Get all user_ids associated with these technicians
    const technicians = await db.query(
      'SELECT user_id FROM technicians WHERE id = ANY($1::int[])',
      [technicianIds]
    );

    if (technicians.rowCount === 0) {
      return next(new HandleError('No technicians found to delete', 404));
    }

    const userIds = technicians.rows.map(t => t.user_id);

    await db.query('BEGIN');

    // Cascade delete handles deleting from technicians table
    await db.query('DELETE FROM users WHERE id = ANY($1::int[])', [userIds]);

    await db.query('COMMIT');

    return res.status(200).json({
      success: true,
      message: `${technicians.rowCount} technicians deleted successfully`,
    });
  } catch (error) {
    await db.query('ROLLBACK');
    console.error(error);
    return next(new HandleError('Unable to delete technicians', 500));
  }
};
