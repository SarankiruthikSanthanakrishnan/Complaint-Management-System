import db from '../config/db.js';
import HandleError from '../helper/HandleError.js';
import sendEmail from '../helper/sendEmail.js';
import sendToken from '../helper/sendToken.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import ip from 'ip';
import bcrypt from 'bcryptjs';
import { createToken } from '../helper/createToken.js';

const ipAddress = ip.address();

export const verifyRegNo = async (req, res, next) => {
  try {
    const { reg_no } = req.body;
    if (!reg_no || reg_no.trim() === '') {
      return next(new HandleError('Registration number is required', 400));
    }
    const userRes = await db.query(
      'select reg_no,student_name,department from students where reg_no=$1',
      [reg_no]
    );
    if (userRes.rowCount === 0) {
      return next(new HandleError('Registration number not found', 404));
    }
    res.status(200).json({
      success: true,
      message: 'Student Found',
      student: userRes.rows[0],
    });
  } catch (error) {
    return next(
      new HandleError('Verification Failed, Try Again after Sometime', 500)
    );
  }
};

export const register = async (req, res, next) => {
  try {
    const { reg_no, password, confirmpassword } = req.body;

    if (!reg_no || reg_no.trim() === '') {
      return next(new HandleError('Registration number is required', 400));
    }
    if (!password || password.trim() === '') {
      return next(new HandleError('Password is required', 400));
    }
    if (!confirmpassword || confirmpassword.trim() === '') {
      return next(new HandleError('Confirm Password is required', 400));
    }

    if (password !== confirmpassword)
      return next(new HandleError('Password mismatch', 400));

    const studentRes = await db.query(
      `SELECT reg_no, student_name, department, contact_mail, contact_number, active
       FROM students WHERE reg_no=$1`,
      [reg_no]
    );

    if (studentRes.rowCount === 0) {
      return next(new HandleError('Invalid reg no', 404));
    }

    const student = studentRes.rows[0];

    if (student.active === true) {
      return next(new HandleError('User already registered', 400));
    }

    //already exists in users table?
    const existingUser = await db.query(
      'SELECT id FROM users WHERE username=$1',
      [reg_no]
    );

    if (existingUser.rowCount > 0) {
      return next(new HandleError('User already exists', 409));
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    try {
      await db.query('BEGIN');
      await db.query(
        `INSERT INTO users (username, full_name, email, contact, department, password_hash, role)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [
          student.reg_no,
          student.student_name,
          student.contact_mail,
          student.contact_number,
          student.department,
          hashedPassword,
          'Student',
        ]
      );

      await db.query('UPDATE students SET active=true WHERE reg_no=$1', [
        reg_no,
      ]);
      await db.query('COMMIT');
    } catch (dbError) {
      await db.query('ROLLBACK');
      throw dbError;
    }
    try {
      await sendEmail({
        email: student.contact_mail,
        subject: 'Registration Successful',
        message: `Dear ${student.student_name},\n\nYour registration was successful. You can now log in using your registration number.\n\nBest regards,\nComplaint Management System Team`,
      });
      return res.status(201).json({
        success: true,
        message: 'Registered successfully . Please login now.',
      });
    } catch (error) {
      return next(new HandleError('Registered but failed to send email', 500));
    }
  } catch (error) {
    console.log(error);
    return next(new HandleError(error.message, 500));
  }
};

export const login = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return next(
        new HandleError('Please provide email/username and password', 400)
      );
    }
    const userRes = await db.query(
      'select id,username,password_hash,role,active,must_change_password from users where username=$1 or email=$1',
      [username]
    );
    if (userRes.rowCount === 0) {
      return next(new HandleError('User not Found', 404));
    }
    const user = userRes.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return next(new HandleError('Invalid Credentials', 401));
    }
    if (user.active === false) {
      return next(
        new HandleError('Account is deactivated. Contact Admin.', 403)
      );
    }
    const { accessToken, refreshToken } = sendToken({
      id: user.id,
      role: user.role,
      must_change_password: user.must_change_password,
    });

    const isProduction = process.env.SECURE === 'production';
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      maxAge: process.env.COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000,
      sameSite: isProduction ? 'none' : 'lax',
    });
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: isProduction,
      maxAge: process.env.ACCESS_EXPIRES_IN.slice(0, 2) * 60 * 1000,
      sameSite: isProduction ? 'none' : 'lax',
    });
    res.status(200).json({
      success: true,
      message: 'Login Successfully',
      accessToken: accessToken,
      refreshToken: refreshToken,
    });
  } catch (error) {
    console.log(error);

    return next(new HandleError('Login Failed ,Try Again After Sometime', 500));
  }
};

export const refreshController = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return next(
        new HandleError('Refresh Token not Found, Please Login Again', 401)
      );
    }
    const decoded = await jwt.verify(refreshToken, process.env.JWT_SECRET);
    const userRes = await db.query(
      'select id,role,must_change_password from users where id=$1',
      [decoded.id]
    );
    if (userRes.rowCount === 0) {
      return next(new HandleError('User not Found', 404));
    }
    const user = userRes.rows[0];
    const newAccessToken = jwt.sign(
      {
        id: user.id,
        role: user.role,
        must_change_password: user.must_change_password,
      },
      process.env.ACCESS_TOKEN_KEY,
      { expiresIn: process.env.ACCESS_EXPIRES_IN || '15m' }
    );
    const isProduction = process.env.SECURE === 'production';
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: isProduction,
      maxAge: process.env.ACCESS_EXPIRES_IN.slice(0, 2) * 60 * 1000,
      sameSite: isProduction ? 'none' : 'lax',
    });
    res.status(200).json({
      success: true,
      message: 'Access Token Refreshed',
      accessToken: newAccessToken,
    });
  } catch (error) {
    console.log(error);
    return next(new HandleError('Internal Server Error', 500));
  }
};

export const logout = (req, res, next) => {
  try {
    const isProduction = process.env.SECURE === 'production';
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
    });
    res.clearCookie('accessToken', {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
    });

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    return next(new HandleError('Failed to logout', 500));
  }
};

export const getAuthUser = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const userRes = await db.query(
      'select id,username,full_name,email,contact,department,role,profile_image from users where id=$1',
      [userId]
    );
    if (userRes.rowCount === 0) {
      return next(new HandleError('User not found', 404));
    }
    res.status(200).json({
      success: true,
      user: userRes.rows[0],
    });
  } catch (error) {
    return next(new HandleError('Unable to Fetch User', 500));
  }
};

export const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      return next(new HandleError('Email is required', 400));
    }

    const userRes = await db.query(
      'SELECT id, full_name FROM users WHERE email=$1',
      [email]
    );

    if (userRes.rowCount === 0) {
      return next(new HandleError('User not found', 404));
    }

    const user = userRes.rows[0];

    // JWT token create
    const token = jwt.sign(
      {
        user: user.id,
        type: 'password-reset',
      },
      process.env.RESET_KEY,
      { expiresIn: '5m' }
    );

    // reset link
    const resetUrl = `${req.protocol}://${req.get(
      'host'
    )}/reset-password?token=${token}`;

    const message = `Dear ${user.full_name},

You requested a password reset.

Please click the following link:

${resetUrl}

This link will expire in 5 minutes.

If you did not request this, please ignore this email.

Best regards,
Complaint Management System Team`;

    await sendEmail({
      email: email,
      subject: 'Password Reset Request',
      message: message,
    });

    res.status(200).json({
      success: true,
      message: 'Password reset email sent',
    });
  } catch (error) {
    console.log(error);
    return next(new HandleError('Internal Server Error', 500));
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    const { token } = req.query;
    const { password, confirmpassword } = req.body;

    if (!token) {
      return next(new HandleError('Token missing', 400));
    }

    if (!password || !confirmpassword) {
      return next(new HandleError('Password fields required', 400));
    }

    if (password !== confirmpassword) {
      return next(new HandleError('Password mismatch', 400));
    }

    let decoded;

    try {
      decoded = jwt.verify(token, process.env.RESET_KEY);
    } catch (err) {
      return next(new HandleError('Invalid or expired token', 400));
    }

    if (decoded.type !== 'password-reset') {
      return next(new HandleError('Invalid reset token', 400));
    }

    const userRes = await db.query('SELECT id FROM users WHERE id=$1', [
      decoded.user,
    ]);

    if (userRes.rowCount === 0) {
      return next(new HandleError('User not found', 404));
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await db.query('UPDATE users SET password_hash=$1 WHERE id=$2', [
      hashedPassword,
      decoded.user,
    ]);

    res.status(200).json({
      success: true,
      message: 'Password reset successfully',
    });
  } catch (err) {
    console.log(err);
    next(new HandleError('Internal Server Error', 500));
  }
};

export const changePassword = async (req, res, next) => {
  try {
    const { password, confirmpassword } = req.body;

    if (!password || !confirmpassword) {
      return next(new HandleError('Password fields required', 400));
    }

    if (password !== confirmpassword) {
      return next(new HandleError('Password mismatch', 400));
    }

    if (!req.user?.id) {
      return next(new HandleError('Unauthorized. Please login again.', 401));
    }

    const userId = req.user.id;
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.query(
      'UPDATE users SET password_hash=$1, must_change_password=false WHERE id=$2',
      [hashedPassword, userId]
    );

    if (result.rowCount === 0) {
      return next(new HandleError('User not found', 404));
    }

    return res.status(200).json({
      success: true,
      message: 'Password changed successfully',
      logout: true,
    });
  } catch (error) {
    return next(
      new HandleError(error.message || 'Failed to change password', 500)
    );
  }
};

export const updateProfile = async (req, res, next) => {
  const profile_image = req.file ? `/uploads/${req.file.filename}` : null;
  try {
    const userId = req.user.id;
    const { full_name, contact } = req.body;
    if (!full_name || !contact) {
      return next(new HandleError('Full name and contact are required', 400));
    }

    await db.query(
      'update users set full_name=$1, contact=$2, profile_image=$3 where id=$4',
      [full_name, contact, profile_image, userId]
    );
    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
    });
  } catch (error) {
    console.log(error);
    return next(new HandleError('Profile Updation Failed', 500));
  }
};
