import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { GetAllUsers } from '../services/AuthService';

/**
 * @typedef {Object} User
 * @property {number} id
 * @property {string} username
 * @property {string} full_name
 * @property {string} email
 * @property {string} password
 * @property {'Admin' | 'MasterAdmin' | 'Faculty' | 'Student' | 'Technician'} role
 * @property {string} profile_image
 * @property {string} contact
 * @property {string} [department]
 */

const roleStyles = {
  Admin: 'bg-amber-100 text-amber-800',
  MasterAdmin: 'bg-rose-100 text-rose-800',
  Faculty: 'bg-sky-100 text-sky-800',
  Student: 'bg-emerald-100 text-emerald-800',
  Technician: 'bg-violet-100 text-violet-800',
};

const emptyUsers = [];

const normalizeUsers = (payload) => {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (Array.isArray(payload?.users)) {
    return payload.users;
  }

  if (Array.isArray(payload?.data?.users)) {
    return payload.data.users;
  }

  if (Array.isArray(payload?.data)) {
    return payload.data;
  }

  return emptyUsers;
};

const formatRoleCount = (users, role) =>
  users.filter((user) => user.role === role).length;

const Users = () => {
  const navigate = useNavigate();
  const [users, setUsers] = useState(emptyUsers);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRole, setSelectedRole] = useState('All');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let isMounted = true;

    const fetchUsers = async () => {
      setLoading(true);
      setError('');

      try {
        const response = await GetAllUsers();
        if (!isMounted) {
          return;
        }

        setUsers(normalizeUsers(response?.data));
      } catch (fetchError) {
        if (!isMounted) {
          return;
        }

        setUsers(emptyUsers);
        setError(
          fetchError?.response?.data?.message ||
            fetchError?.message ||
            'Unable to load users.'
        );
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchUsers();

    return () => {
      isMounted = false;
    };
  }, []);

  const filteredUsers = users.filter((user) => {
    const searchValue = searchTerm.trim().toLowerCase();
    const matchesSearch =
      searchValue === '' ||
      user.full_name?.toLowerCase().includes(searchValue) ||
      user.username?.toLowerCase().includes(searchValue) ||
      user.email?.toLowerCase().includes(searchValue) ||
      user.contact?.toLowerCase().includes(searchValue) ||
      user.department?.toLowerCase().includes(searchValue);

    const matchesRole = selectedRole === 'All' || user.role === selectedRole;

    return matchesSearch && matchesRole;
  });

  const totalUsers = users.length;
  const roleOptions = [
    'All',
    'Admin',
    'MasterAdmin',
    'Faculty',
    'Student',
    'Technician',
  ];

  return (
    <section className="min-h-screen bg-slate-100 px-4 py-6 sm:px-6 lg:px-10">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <div className="overflow-hidden rounded-3xl bg-linear-to-r from-slate-900 via-slate-800 to-cyan-800 px-6 py-8 text-white shadow-lg sm:px-8">
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-200">
            Admin Panel
          </p>
          <div className="mt-4 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <h1 className="text-3xl font-semibold sm:text-4xl">Users</h1>
              <p className="mt-2 max-w-2xl text-sm text-slate-200 sm:text-base">
                View, search, and monitor all registered users across roles and
                departments.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="rounded-2xl bg-white/10 p-4 backdrop-blur-sm">
                <p className="text-xs text-slate-200">Total</p>
                <p className="mt-2 text-2xl font-semibold">{totalUsers}</p>
              </div>
              <div className="rounded-2xl bg-white/10 p-4 backdrop-blur-sm">
                <p className="text-xs text-slate-200">Students</p>
                <p className="mt-2 text-2xl font-semibold">
                  {formatRoleCount(users, 'Student')}
                </p>
              </div>
              <div className="rounded-2xl bg-white/10 p-4 backdrop-blur-sm">
                <p className="text-xs text-slate-200">Faculty</p>
                <p className="mt-2 text-2xl font-semibold">
                  {formatRoleCount(users, 'Faculty')}
                </p>
              </div>
              <div className="rounded-2xl bg-white/10 p-4 backdrop-blur-sm">
                <p className="text-xs text-slate-200">Technicians</p>
                <p className="mt-2 text-2xl font-semibold">
                  {formatRoleCount(users, 'Technician')}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-3xl bg-white p-5 shadow-sm ring-1 ring-slate-200 sm:p-6">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex-1">
              <label
                htmlFor="user-search"
                className="mb-2 block text-sm font-medium text-slate-700"
              >
                Search users
              </label>
              <input
                id="user-search"
                type="text"
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                placeholder="Search by name, username, email, contact, or department"
                className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:bg-white"
              />
            </div>

            <div className="w-full lg:max-w-xs">
              <label
                htmlFor="role-filter"
                className="mb-2 block text-sm font-medium text-slate-700"
              >
                Filter by role
              </label>
              <select
                id="role-filter"
                value={selectedRole}
                onChange={(event) => setSelectedRole(event.target.value)}
                className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:bg-white"
              >
                {roleOptions.map((role) => (
                  <option key={role} value={role}>
                    {role}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <div className="overflow-hidden rounded-3xl bg-white shadow-sm ring-1 ring-slate-200">
          <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4 sm:px-6">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">
                User Directory
              </h2>
              <p className="text-sm text-slate-500">
                {filteredUsers.length} of {totalUsers} users shown
              </p>
            </div>
          </div>

          {loading ? (
            <div className="px-6 py-16 text-center text-sm text-slate-500">
              Loading users...
            </div>
          ) : error ? (
            <div className="px-6 py-16 text-center">
              <p className="text-sm font-medium text-rose-600">{error}</p>
            </div>
          ) : filteredUsers.length === 0 ? (
            <div className="px-6 py-16 text-center text-sm text-slate-500">
              No users found for the current filters.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                      User
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Username
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Contact
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Department
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Role
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 bg-white">
                  {filteredUsers.map((user) => (
                    <tr
                      key={user.id}
                      className="cursor-pointer transition hover:bg-slate-50"
                      onClick={() => navigate(`/admin/users/${user.id}`)}
                    >
                      <td className="px-6 py-4">
                        <div>
                          <p className="font-medium text-slate-900">
                            {user.full_name || 'Unnamed user'}
                          </p>
                          <p className="text-sm text-slate-500">
                            {user.email || 'No email available'}
                          </p>
                          <p className="mt-2 text-xs font-medium uppercase tracking-[0.2em] text-cyan-700">
                            Click to view details
                          </p>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-700">
                        {user.username || '-'}
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-700">
                        {user.contact || '-'}
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-700">
                        {user.department || '-'}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${roleStyles[user.role] || 'bg-slate-100 text-slate-700'}`}
                        >
                          {user.role || 'Unknown'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};

export default Users;
