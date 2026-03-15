import React, { useState } from 'react';
import {
  BarChart3,
  Bell,
  FileText,
  LayoutDashboard,
  Menu,
  Search,
  Settings,
  User,
  UserCog,
  Users,
  X,
} from 'lucide-react';
import { NavLink } from 'react-router-dom';

const AppLayout = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const [isAdmin] = useState(true);
  const [isTechnician] = useState(false);
  const [isUser] = useState(false);

  const Adminnavs = [
    { name: 'Dashboard', icon: LayoutDashboard, path: '/admin/dashboard' },
    { name: 'Users', icon: Users, path: '/admin/users' },
    { name: 'Technicians', icon: UserCog, path: '/admin/technicians' },
    { name: 'Complaints', icon: FileText, path: '/admin/complaints' },
    { name: 'Reports', icon: BarChart3, path: '/admin/reports' },
    { name: 'Settings', icon: Settings, path: '/admin/settings' },
    { name: 'Profile', icon: User, path: '/admin/profile' },
  ];

  const Techniciannavs = [
    { name: 'Dashboard', icon: LayoutDashboard, path: '/technician/dashboard' },
    { name: 'Notifications', icon: Bell, path: '/technician/notifications' },
    {
      name: 'Assigned Tasks',
      icon: FileText,
      path: '/technician/assigned-tasks',
    },
    { name: 'Profile', icon: User, path: '/technician/profile' },
  ];

  const Usernavs = [
    { name: 'Home', icon: LayoutDashboard, path: '/home' },
    { name: 'My Complaints', icon: FileText, path: '/my-complaints' },
    { name: 'Raise Complaint', icon: UserCog, path: '/raise-complaint' },
    { name: 'Notifications', icon: Bell, path: '/notifications' },
    { name: 'Settings', icon: Settings, path: '/profile' },
  ];

  let navItems = [];

  if (isAdmin) {
    navItems = Adminnavs;
  } else if (isTechnician) {
    navItems = Techniciannavs;
  } else if (isUser) {
    navItems = Usernavs;
  }

  return (
    <nav className="sticky top-0 z-50 border-b bg-white">
      <div className="max-w-7xl mx-auto flex items-center justify-between px-4 py-3">
        {/* LOGO */}
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 flex items-center justify-center rounded-xl bg-sky-100 text-sky-700">
            <UserCog size={20} />
          </div>

          <div>
            <p className="font-semibold text-slate-900">SKNEXUS</p>
            <p className="text-xs text-slate-500">Complaint Management</p>
          </div>
        </div>

        {/* SEARCH */}
        <div className="hidden lg:flex items-center gap-2 border rounded-full px-3 py-2 bg-slate-50">
          <Search size={16} className="text-slate-500" />
          <input
            type="text"
            placeholder="Search modules"
            className="bg-transparent outline-none text-sm w-44"
          />
        </div>

        {/* DESKTOP NAV */}
        <div className="hidden lg:flex items-center gap-2">
          {navItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition ${
                  isActive
                    ? 'bg-sky-600 text-white'
                    : 'text-slate-600 hover:bg-slate-100'
                }`
              }
            >
              <item.icon size={16} />
              {item.name}
            </NavLink>
          ))}
        </div>

        {/* RIGHT SIDE */}
        <div className="flex items-center gap-3">
          {/* NOTIFICATION */}
          <button className="relative p-2 rounded-lg border hover:bg-slate-100">
            <Bell size={18} />
            <span className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full"></span>
          </button>

          {/* PROFILE */}
          <div className="hidden md:flex items-center gap-2 border rounded-lg px-2 py-1">
            <div className="w-8 h-8 rounded bg-sky-600 text-white flex items-center justify-center font-semibold">
              S
            </div>

            <div className="text-sm">
              <p className="font-medium">Sathya</p>
              <p className="text-xs text-gray-500">
                {isAdmin ? 'Admin' : isTechnician ? 'Technician' : 'User'}
              </p>
            </div>
          </div>

          {/* MOBILE MENU BUTTON */}
          <button
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="lg:hidden p-2 border rounded-lg"
          >
            {isMenuOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </div>

      {/* MOBILE MENU */}
      {isMenuOpen && (
        <div className="lg:hidden border-t bg-white px-4 py-3">
          <div className="flex items-center gap-2 border rounded-lg px-3 py-2 mb-3">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search modules"
              className="w-full outline-none text-sm"
            />
          </div>

          <div className="grid grid-cols-2 gap-2">
            {navItems.map((item) => (
              <NavLink
                key={item.name}
                to={item.path}
                onClick={() => setIsMenuOpen(false)}
                className={({ isActive }) =>
                  `flex items-center gap-2 px-3 py-2 rounded-lg text-sm ${
                    isActive
                      ? 'bg-sky-600 text-white'
                      : 'bg-slate-100 text-slate-700'
                  }`
                }
              >
                <item.icon size={16} />
                {item.name}
              </NavLink>
            ))}
          </div>
        </div>
      )}
    </nav>
  );
};

export default AppLayout;
