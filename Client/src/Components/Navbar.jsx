import React, { useEffect } from "react";
import { NavLink } from "react-router-dom";
import { useAuth } from "./Auth";

function Navbar() {

const {user,isVerifed,loading,VerifyUser,UserLogin} = useAuth();

useEffect(()=>{
  const LoginUser = async ()=>{
    await UserLogin("AD001","12345");
  }
  LoginUser();
},[]);



  return (
   <nav className="bg-blue-600 px-3 py-4 flex justify-between items-center text-white shadow-lg">
    <ul className="flex space-x-4">
      {loading ? (
        <p>Loading...</p>
      ) : user?.role === "Student" ? (
        <>
        <NavLink to="/">Logo</NavLink>
        <NavLink to="/">Home</NavLink>
        <NavLink to="/raise-complaint">Raise Complaint</NavLink>
        <NavLink to="/my-complaints">My Complaints</NavLink>
        <NavLink to="/notifications">Notifications</NavLink>
        <NavLink to="/profile">Profile</NavLink>
        <NavLink to="/logout">Logout</NavLink>
        </>
      )  : user?.role === "Technician" ? (
        <>
         <NavLink to="/dashboard" >Dashboard</NavLink>
        <NavLink to="/assigned-tasks" >Assigned Tasks</NavLink>
        <NavLink to="/update-status" >Update Status</NavLink>
        <NavLink to="/notifications" >Notifications</NavLink>
        <NavLink to="/profile" >Profile</NavLink>
        </>
      ) :  user?.role === "Admin" || user?.role === "MasterAdmin" ? (
        <>
        <NavLink to="/dashboard" >Dashboard</NavLink>
        <NavLink to="/users" >Users</NavLink>
        <NavLink to="/technicians" >Technicians</NavLink>
        <NavLink to="/departments" >Departments</NavLink>
        <NavLink to="/complaints" >Complaints</NavLink>
        <NavLink to="/reports" >Reports</NavLink>
        <NavLink to="/settings" >Settings</NavLink>
        {
         user ? <NavLink to="/logout">Logout</NavLink> : <NavLink to="/login">Login</NavLink>
        }
        </>
      ) : null}
    </ul>
   </nav>
  );
}

export default Navbar;
