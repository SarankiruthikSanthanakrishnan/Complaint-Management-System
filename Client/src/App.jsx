import React from 'react';
import Navbar from './Components/Navbar';
import Footer from './Components/Footer';
import { Route, Routes } from 'react-router-dom';
import Home from './(users)/Home';
import MyComplaint from './(users)/MyComplaint';
import RaiseComplaint from './(users)/RaiseComplaint';
import Profile from './(users)/Profile';
import Dashboard from './(admin)/Dashboard';
import Settings from './(admin)/Settings';
import Reports from './(admin)/Reports';
import Users from './(admin)/Users';
import Technicians from './(admin)/Technicians';
import Dashboard from './(technician)/TechnicianDashboard';

const App = () => {
  return (
    <>
      <Navbar />
      <Routes>
        {/* UserRoutes */}
        <Route path="/" element={<Home />} />
        <Route path="/home" element={<Home />} />
        <Route path="/my-complaints" element={<MyComplaint />} />
        <Route path="/raise-complaint" element={<RaiseComplaint />} />
        <Route path="/profile" element={<Profile />} />

        {/* AdminRoutes */}
        <Route path="/admin/dashboard" element={<Dashboard />} />
        <Route path="/admin/profile" element={<Settings />} />
        <Route path="/admin/reports" element={<Reports />} />
        <Route path="/admin/users" element={<Users />} />
        <Route path="/admin/technicians" element={<Technicians />} />
        <Route path="/admin/complaints" element={<Dashboard />} />

        {/* TechnicianRoutes */}

        <Route path="/technician/dashboard" element={<Dashboard />} />
      </Routes>

      <Footer />
    </>
  );
};

export default App;
