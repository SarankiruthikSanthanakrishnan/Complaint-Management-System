import db from '../config/db.js';
import { createToken } from '../helper/createToken.js';
import HandleError from '../helper/HandleError.js';
import sendEmail from '../helper/sendEmail.js';
import sendToken from '../helper/sendToken.js';
import crypto from 'crypto';
import  jwt from 'jsonwebtoken';

import bcrypt from 'bcryptjs';

export const verifyRegNo = async (req, res, next) => {
  try {
    const { reg_no } = req.body;
    if(!reg_no || reg_no.trim() === ''){
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

    if(!reg_no || reg_no.trim() === ''){
      return next(new HandleError('Registration number is required', 400));
    }
    if(!password || password.trim() === ''){
      return next(new HandleError('Password is required', 400));
    }
    if(!confirmpassword || confirmpassword.trim() === ''){
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

    await db.query('UPDATE students SET active=true WHERE reg_no=$1', [reg_no]);
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
    const {accessToken,refreshToken} = sendToken({
      id: user.id,
      role: user.role,
      must_change_password: user.must_change_password,
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: false,
      maxAge: process.env.COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
    });
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: false,
      maxAge: (process.env.ACCESS_EXPIRES_IN).slice(0,2) * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
    });
    res.status(200).json({
      success: true,
      message: 'Login Successfully',
    });
  } catch (error) {
    console.log(error);

    return next(new HandleError('Login Failed ,Try Again After Sometime', 500));
  }
};

export const refreshController = async(req,res,next)=>{
  try {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken){
      return next(new HandleError('Refresh Token not Found, Please Login Again',401))
    }
    const decoded = await jwt.verify(refreshToken,process.env.JWT_SECRET_KEY)
    next();
    const userRes = await  db.query('select id,role,must_change_password from users where id=$1',[decoded.id]);
    if(userRes.rowCount === 0){
      return next(new HandleError('User not Found',404));
    }
    const user = userRes.rows[0];
    const newAccessToken = jwt.sign({id:user.id,role:user.role,must_change_password:user.must_change_password},process.env.JWT_SECRET_KEY,{expiresIn:process.env.ACCESS_EXPIRES_IN || '15m'}
    );

    res.cookie('accessToken',newAccessToken,{
      httpOnly:true,
      secure:false,
      maxAge:(process.env.ACCESS_EXPIRES_IN).slice(0,2) * 24 * 60 * 60 * 1000,
      sameSite:'lax',
    });
    res.status(200).json({
      success:true,
      message:"Access Token Refreshed"
    });


  } catch (error) {
      console.log(error);
      return next(new HandleError('Internal Server Error',500));
  }
}

export const logout = (req, res, next) => {
  try {
    res.clearCookie('token', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
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
      'select id,username,full_name,email,contact,department,role from users where id=$1',
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
    const userRes = await db.query(
      'select id,full_name from users where email=$1',
      [email]
    );
    if (userRes.rowCount === 0) {
      return next(new HandleError('User not found', 404));
    }
    const user = userRes.rows[0];
    const { token, resetToken } = await createToken();
    const expireTime = new Date(Date.now() + 15 * 60 * 1000);
    await db.query(
      'update users set reset_token=$1, reset_token_expiry=$2 where id=$3',
      [resetToken, expireTime, user.id]
    );
    const resetUrl = `${req.protocol}://${req.host}/api/v1/auth/user/reset-password/${token}`;
    const message = `Dear ${user.full_name},\n\nYou requested a password reset. Please click on the following link to reset your password:\n\n${resetUrl}\n\nThis link will expire in 15 minutes.\n\nIf you did not request this, please ignore this email.\n\nBest regards,\nComplaint Management System Team`;
    try {
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
      next(new HandleError('Failed to send email', 500));
    }
  } catch (error) {
    return next(new HandleError('Internal Server Error', 500));
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    const { token } = req.params;
    const { password, confirmpassword } = req.body;
    if (!password || !confirmpassword) {
      return next(new HandleError('Password fields required', 400));
    }
    if (password !== confirmpassword) {
      return next(new HandleError('Password mismatch', 400));
    }

    const resetToken = crypto.createHash('sha256').update(token).digest('hex');

    const userRes = await db.query(
      'select id,reset_token_expiry from users where reset_token=$1',
      [resetToken]
    );
    if (userRes.rowCount === 0) {
      return next(new HandleError('Invalid or expired token', 400));
    }
    const user = userRes.rows[0];
    if (user.reset_token_expiry < new Date()) {
      return next(new HandleError('Token has expired', 400));
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query(
      'update users set password_hash=$1, reset_token=null, reset_token_expiry=null where id=$2',
      [hashedPassword, user.id]
    );
    res.status(200).json({
      success: true,
      message: 'Password reset successfully',
    });
  } catch (error) {
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
    return next(new HandleError('Profile Updation Failed', 500));
  }
};
