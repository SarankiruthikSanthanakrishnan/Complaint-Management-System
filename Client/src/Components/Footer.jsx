import React from 'react'

const Footer = () => {
  return (
    <footer className="bg-gray-800 text-white text-center py-3">
      <p>© {new Date().getFullYear()} Complaint Management System</p>
    </footer>
  );
};

export default Footer
