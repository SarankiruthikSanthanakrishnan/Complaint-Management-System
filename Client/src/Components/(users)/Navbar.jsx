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
import { NavLink, Outlet } from 'react-router-dom';

const AppLayout = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, path: '/dashboard' },
    { name: 'Users', icon: Users, path: '/users' },
    { name: 'Technicians', icon: UserCog, path: '/technicians' },
    { name: 'Complaints', icon: FileText, path: '/complaints' },
    { name: 'Reports', icon: BarChart3, path: '/reports' },
    { name: 'Settings', icon: Settings, path: '/settings' },
    { name: 'Profile', icon: User, path: '/profile' },
  ];

  return (
    <div className="min-h-screen bg-slate-50 text-gray-900">
      <nav className="sticky top-0 z-50 border-b border-slate-200 bg-white/90 backdrop-blur-lg">
        <div className="mx-auto flex w-full max-w-7xl items-center justify-between px-4 py-3 md:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-100 text-sky-700">
              <UserCog size={20} />
            </div>
            <div className="leading-tight">
              <p className="text-base font-semibold text-slate-900">SKNEXUS</p>
              <p className="text-xs text-slate-500">Complaint Management</p>
            </div>
          </div>

          <div className="hidden items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-2 lg:flex">
            <Search size={16} className="text-slate-500" />
            <input
              type="text"
              placeholder="Search modules"
              className="w-44 bg-transparent text-sm text-slate-700 placeholder:text-slate-400 outline-none"
            />
          </div>

          <div className="hidden items-center gap-1 rounded-2xl border border-slate-200 bg-slate-50 p-1 lg:flex">
            {navItems.map((item) => (
              <NavLink
                key={item.name}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium transition-all duration-300 ${
                    isActive
                      ? 'bg-sky-600 text-white shadow-sm'
                      : 'text-slate-600 hover:bg-white hover:text-slate-900'
                  }`
                }
              >
                <item.icon size={16} />
                {item.name}
              </NavLink>
            ))}
          </div>

          <div className="flex items-center gap-3">
            <button className="relative rounded-xl border border-slate-200 p-2 text-slate-600 hover:bg-slate-100">
              <Bell size={18} />
              <span className="absolute -right-1 -top-1 h-2.5 w-2.5 rounded-full bg-rose-500" />
            </button>
            <div className="hidden items-center gap-2 rounded-xl border border-slate-200 bg-white px-2 py-1.5 md:flex">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-600 text-sm font-semibold text-white">
                S
              </div>
              <div className="pr-1 text-left leading-tight">
                <p className="text-sm font-medium text-slate-800">Sathya</p>
                <p className="text-xs text-slate-500">Admin</p>
              </div>
            </div>
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="rounded-xl border border-slate-200 p-2 text-slate-700 lg:hidden"
              aria-label="Toggle navigation"
            >
              {isMenuOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>

        {isMenuOpen && (
          <div className="border-t border-slate-200 bg-white px-4 py-3 lg:hidden">
            <div className="mb-3 flex items-center gap-2 rounded-xl border border-slate-200 px-3 py-2">
              <Search size={16} className="text-slate-500" />
              <input
                type="text"
                placeholder="Search modules"
                className="w-full bg-transparent text-sm text-slate-700 placeholder:text-slate-400 outline-none"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              {navItems.map((item) => (
                <NavLink
                  key={item.name}
                  to={item.path}
                  onClick={() => setIsMenuOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium transition-all ${
                      isActive
                        ? 'bg-sky-600 text-white'
                        : 'border border-slate-200 bg-slate-50 text-slate-700'
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

      <main className="mx-auto flex w-full max-w-7xl flex-grow px-4 py-10 md:px-8">
        <Outlet />
      </main>
    </div>
  );
};

export default AppLayout;
