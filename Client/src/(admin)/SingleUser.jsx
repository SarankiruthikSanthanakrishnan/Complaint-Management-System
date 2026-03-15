import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const roleStyles = {
  Admin: 'bg-amber-100 text-amber-800',
  MasterAdmin: 'bg-rose-100 text-rose-800',
  Faculty: 'bg-sky-100 text-sky-800',
  Student: 'bg-emerald-100 text-emerald-800',
  Technician: 'bg-violet-100 text-violet-800',
};

const infoCards = [
  { key: 'username', label: 'Username' },
  { key: 'full_name', label: 'Full Name' },
  { key: 'email', label: 'Email Address' },
  { key: 'contact', label: 'Contact Number' },
  { key: 'role', label: 'Role' },
  { key: 'department', label: 'Department' },
];

const dummyUser = {
  id: 1,
  username: 'tech_saran',
  full_name: 'Saran Kiruthik',
  email: 'saran@example.com',
  contact: '9876543210',
  role: 'Technician',
  department: 'IT Support',
  profile_image: 'https://i.pravatar.cc/200',
};

const getInitials = (fullName = '') => {
  const parts = fullName.split(' ').filter(Boolean).slice(0, 2);
  if (parts.length === 0) return 'U';
  return parts.map((p) => p[0]?.toUpperCase()).join('');
};

export const SingleUser = () => {
  const navigate = useNavigate();

  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // simulate API call
    setTimeout(() => {
      setUser(dummyUser);
      setLoading(false);
    }, 500);
  }, []);

  return (
    <section className="min-h-screen bg-slate-100 px-4 py-6">
      <div className="mx-auto max-w-4xl">
        <button
          onClick={() => navigate('/admin/users')}
          className="mb-6 rounded-full border px-4 py-2 text-sm bg-white"
        >
          Back to users
        </button>

        {loading ? (
          <div className="bg-white p-10 rounded-xl text-center">
            Loading user details...
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="bg-slate-900 text-white rounded-2xl p-6 flex items-center gap-4">
              {user.profile_image ? (
                <img
                  src={user.profile_image}
                  alt={user.full_name}
                  className="w-20 h-20 rounded-xl object-cover"
                />
              ) : (
                <div className="w-20 h-20 rounded-xl bg-white/20 flex items-center justify-center text-xl font-bold">
                  {getInitials(user.full_name)}
                </div>
              )}

              <div>
                <h1 className="text-2xl font-bold">{user.full_name}</h1>
                <p className="text-sm text-slate-200">{user.email}</p>
              </div>
            </div>

            {/* Details */}
            <div className="grid grid-cols-2 gap-4 mt-6">
              {infoCards.map((item) => (
                <div key={item.key} className="bg-white rounded-xl p-4 border">
                  <p className="text-xs text-slate-500 uppercase">
                    {item.label}
                  </p>

                  {item.key === 'role' ? (
                    <span
                      className={`mt-2 inline-flex rounded-full px-3 py-1 text-xs font-semibold ${
                        roleStyles[user.role] || 'bg-gray-100'
                      }`}
                    >
                      {user.role}
                    </span>
                  ) : (
                    <p className="mt-2 font-medium">{user[item.key] || '-'}</p>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </section>
  );
};

export default SingleUser;
