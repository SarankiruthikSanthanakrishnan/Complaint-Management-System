import React, { useEffect } from 'react';

const ResetPassword = () => {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');

    const isMobile = /Android|iPhone|iPad/i.test(navigator.userAgent);

    if (isMobile) {
      window.location.href = `exp://10.229.247.123:8081/--/auth/PasswordReset?token=${token}`;
    }
  }, []);

  return (
    <div style={{ textAlign: 'center', marginTop: '50px' }}>
      <h2>Reset Password</h2>
      <p>If you are using mobile, the app will open automatically.</p>
    </div>
  );
};

export default ResetPassword;
