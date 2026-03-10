import React from 'react';
import Navbar from './Components/Navbar';
import Footer from './Components/Footer';
import { Route, Routes } from 'react-router-dom';
import Login from './Components/Login';
import Home from './Screens/user/Home';
import ResetPassword from './Screens/user/ResetPassword';

const App = () => {
  return (
    <>
      <Navbar />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/home" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/reset-password" element={<ResetPassword />} />
      </Routes>

      <Footer />
    </>
  );
};

export default App;
