import React from 'react';
import Navbar from './Components/(users)/Navbar';

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
import Complaints from './(admin)/Complaints';
import TechincianDashboard from './(technician)/TechnicianDashboard';
import Notification from './(users)/Notification';
import { SingleUser } from './(admin)/SingleUser';
import SingleTechnicians from './(admin)/SingleTechnicians';

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
        <Route path="/admin/complaints" element={<Complaints />} />
        <Route path="/notifications" element={<Notification />} />
        <Route path="/admin/users/1" element={<SingleUser />} />
        <Route path="/admin/technicians/1" element={<SingleTechnicians />} />

        {/* TechnicianRoutes */}

        <Route path="/technician/dashboard" element={<TechincianDashboard />} />
        <Route path="/technician/notifications" element={<Notification />} />
      </Routes>
    </>
  );
};

export default App;
