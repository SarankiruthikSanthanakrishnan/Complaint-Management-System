import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

const DUMMY_TECHNICIANS = [
  {
    id: 1,
    user_id: 101,
    technician_code: 'TECH-001',
    username: 'ravi_kumar',
    full_name: 'Ravi Kumar',
    email: 'ravi.kumar@college.edu',
    phone: '+91 98765 43210',
    department: 'Electrical',
    specialization: 'Electrical Wiring & Panel Repairs',
    status: 'Available',
    active: true,
    role: 'Technician',
    profile_image: '',
    contact: '+91 98765 43210',
  },
  {
    id: 2,
    user_id: 102,
    technician_code: 'TECH-002',
    username: 'suresh_m',
    full_name: 'Suresh Muthusamy',
    email: 'suresh.m@college.edu',
    phone: '+91 91234 56789',
    department: 'Plumbing',
    specialization: 'Pipe Fitting & Water Supply Systems',
    status: 'Busy',
    active: true,
    role: 'Technician',
    profile_image: '',
    contact: '+91 91234 56789',
  },
  {
    id: 3,
    user_id: 103,
    technician_code: 'TECH-003',
    username: 'anbu_s',
    full_name: 'Anbu Selvan',
    email: 'anbu.s@college.edu',
    phone: '+91 87654 32109',
    department: 'Civil',
    specialization: 'Structural Maintenance & Masonry',
    status: 'Assigned',
    active: true,
    role: 'Technician',
    profile_image: '',
    contact: '+91 87654 32109',
  },
  {
    id: 4,
    user_id: 104,
    technician_code: 'TECH-004',
    username: 'priya_it',
    full_name: 'Priya Lakshmi',
    email: 'priya.it@college.edu',
    phone: '+91 99887 76655',
    department: 'IT Infrastructure',
    specialization: 'Network & Server Administration',
    status: 'Available',
    active: true,
    role: 'Technician',
    profile_image: '',
    contact: '+91 99887 76655',
  },
  {
    id: 5,
    user_id: 105,
    technician_code: 'TECH-005',
    username: 'karthi_ac',
    full_name: 'Karthikeyan Arumugam',
    email: 'karthi.ac@college.edu',
    phone: '+91 93456 78901',
    department: 'HVAC',
    specialization: 'AC Servicing & Cooling Systems',
    status: 'Inactive',
    active: false,
    role: 'Technician',
    profile_image: '',
    contact: '+91 93456 78901',
  },
];

const statusStyles = {
  available: 'bg-emerald-100 text-emerald-800',
  busy: 'bg-amber-100 text-amber-800',
  inactive: 'bg-slate-200 text-slate-700',
  assigned: 'bg-sky-100 text-sky-800',
};

const detailFields = [
  { key: 'username', label: 'Username' },
  { key: 'full_name', label: 'Full Name' },
  { key: 'email', label: 'Email Address' },
  { key: 'role', label: 'Role' },
  { key: 'technician_code', label: 'Technician Code' },
  { key: 'department', label: 'Department' },
  { key: 'specialization', label: 'Specialization' },
  { key: 'phone', label: 'Phone Number' },
  { key: 'status', label: 'Status' },
];

const getInitials = (fullName = '') => {
  const parts = fullName.split(' ').filter(Boolean).slice(0, 2);

  if (parts.length === 0) {
    return 'T';
  }

  return parts.map((part) => part[0]?.toUpperCase()).join('');
};

const getStatusTone = (status) =>
  statusStyles[String(status || '').toLowerCase()] ||
  'bg-slate-100 text-slate-700';

const SingleTechnicians = () => {
  const navigate = useNavigate();
  const { id } = useParams();
  const [technician, setTechnician] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let isMounted = true;

    const fetchTechnician = () => {
      if (!id) {
        setTechnician(DUMMY_TECHNICIANS[0]);
        setLoading(false);
        return;
      }

      setLoading(true);
      setError('');

      const found = DUMMY_TECHNICIANS.find((t) => String(t.id) === String(id));

      if (!isMounted) return;

      if (found) {
        setTechnician(found);
      } else {
        setTechnician(null);
        setError(`No technician found with id "${id}".`);
      }

      setLoading(false);
    };

    fetchTechnician();

    return () => {
      isMounted = false;
    };
  }, [id]);

  return (
    <section className="min-h-screen bg-slate-100 px-4 py-6">
      <div className="mx-auto max-w-4xl">
        <button
          type="button"
          onClick={() => navigate('/admin/technicians')}
          className="mb-6 rounded-full border px-4 py-2 text-sm bg-white"
        >
          Back to technicians
        </button>

        {loading ? (
          <div className="bg-white p-10 rounded-xl text-center">
            Loading technician details...
          </div>
        ) : error ? (
          <div className="bg-white p-10 rounded-xl text-center shadow-sm">
            <p className="text-sm font-medium text-rose-600">{error}</p>
          </div>
        ) : !technician ? (
          <div className="bg-white p-10 rounded-xl text-center text-sm text-slate-500">
            Technician details are not available.
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="bg-slate-900 text-white rounded-2xl p-6 flex items-center gap-4">
              <div className="flex items-center gap-4">
                {technician.profile_image ? (
                  <img
                    src={technician.profile_image}
                    alt={technician.full_name || 'Technician'}
                    className="w-20 h-20 rounded-xl object-cover"
                  />
                ) : (
                  <div className="w-20 h-20 rounded-xl bg-white/20 flex items-center justify-center text-xl font-bold">
                    {getInitials(technician.full_name)}
                  </div>
                )}

                <div>
                  <h1 className="text-2xl font-bold">
                    {technician.full_name || 'Unnamed technician'}
                  </h1>
                  <p className="text-sm text-slate-200">
                    {technician.email || 'No email available'}
                  </p>
                </div>
              </div>
            </div>

            {/* Details */}
            <div className="grid grid-cols-2 gap-4 mt-6">
              {detailFields.map((field) => (
                <div key={field.key} className="bg-white rounded-xl p-4 border">
                  <p className="text-xs uppercase text-slate-500">
                    {field.label}
                  </p>
                  {field.key === 'status' ? (
                    <span
                      className={`mt-2 inline-flex rounded-full px-3 py-1 text-xs font-semibold ${getStatusTone(technician.status)}`}
                    >
                      {technician.status || 'Unknown'}
                    </span>
                  ) : field.key === 'role' ? (
                    <span className="mt-2 inline-flex rounded-full bg-violet-100 px-3 py-1 text-xs font-semibold text-violet-800">
                      {technician.role || 'Technician'}
                    </span>
                  ) : (
                    <p className="mt-2 font-medium text-slate-900">
                      {technician[field.key] || '-'}
                    </p>
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

export default SingleTechnicians;
