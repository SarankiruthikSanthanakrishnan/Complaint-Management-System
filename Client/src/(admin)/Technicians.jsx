import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { GetAllTechnicians } from '../services/TechnicianService';

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
 */

/**
 * @typedef {User & {
 *  user_id: number,
 *  technician_code: string,
 *  department: string,
 *  phone: string,
 *  specialization: string,
 *  status: string,
 *  active: boolean
 * }} Technician
 */

const statusStyles = {
  available: 'bg-emerald-100 text-emerald-800',
  busy: 'bg-amber-100 text-amber-800',
  inactive: 'bg-slate-200 text-slate-700',
  assigned: 'bg-sky-100 text-sky-800',
};

const emptyTechnicians = [];

const normalizeTechnicians = (payload) => {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (Array.isArray(payload?.technicians)) {
    return payload.technicians;
  }

  if (Array.isArray(payload?.data?.technicians)) {
    return payload.data.technicians;
  }

  if (Array.isArray(payload?.data)) {
    return payload.data;
  }

  return emptyTechnicians;
};

const getStatusTone = (status) =>
  statusStyles[String(status || '').toLowerCase()] ||
  'bg-slate-100 text-slate-700';

const getInitials = (fullName = '') => {
  const parts = fullName.split(' ').filter(Boolean).slice(0, 2);

  if (parts.length === 0) {
    return 'T';
  }

  return parts.map((part) => part[0]?.toUpperCase()).join('');
};

const countByStatus = (technicians, status) =>
  technicians.filter(
    (technician) => String(technician.status || '').toLowerCase() === status
  ).length;

const Technicians = () => {
  const navigate = useNavigate();
  const [technicians, setTechnicians] = useState(emptyTechnicians);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('All');

  useEffect(() => {
    let isMounted = true;

    const fetchTechnicians = async () => {
      setLoading(true);
      setError('');

      try {
        const response = await GetAllTechnicians();

        if (!isMounted) {
          return;
        }

        setTechnicians(normalizeTechnicians(response?.data));
      } catch (fetchError) {
        if (!isMounted) {
          return;
        }

        setTechnicians(emptyTechnicians);
        setError(
          fetchError?.response?.data?.message ||
            fetchError?.message ||
            'Unable to load technicians.'
        );
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchTechnicians();

    return () => {
      isMounted = false;
    };
  }, []);

  const filteredTechnicians = technicians.filter((technician) => {
    const searchValue = searchTerm.trim().toLowerCase();
    const matchesSearch =
      searchValue === '' ||
      technician.full_name?.toLowerCase().includes(searchValue) ||
      technician.username?.toLowerCase().includes(searchValue) ||
      technician.email?.toLowerCase().includes(searchValue) ||
      technician.department?.toLowerCase().includes(searchValue) ||
      technician.specialization?.toLowerCase().includes(searchValue) ||
      technician.technician_code?.toLowerCase().includes(searchValue) ||
      technician.phone?.toLowerCase().includes(searchValue);

    const normalizedStatus = String(technician.status || '').toLowerCase();
    const matchesStatus =
      selectedStatus === 'All' ||
      normalizedStatus === selectedStatus.toLowerCase();

    return matchesSearch && matchesStatus;
  });

  const activeTechnicians = technicians.filter(
    (technician) => technician.active === true
  ).length;

  return (
    <section className="min-h-screen bg-slate-50 px-4 py-6 sm:px-6 lg:px-10">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <div className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-xl shadow-slate-200/60">
          <div className="grid gap-6 px-6 py-8 sm:px-8 lg:grid-cols-[1.2fr_0.8fr] lg:items-end">
            <div>
              <p className="text-sm font-medium uppercase tracking-[0.35em] text-cyan-700">
                Admin Control Room
              </p>
              <h1 className="mt-4 max-w-2xl text-3xl font-semibold tracking-tight text-slate-950 sm:text-5xl">
                Technician operations at a glance.
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-600 sm:text-base">
                Track availability, monitor specialization coverage, and review
                the current technician roster from a single screen.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-3xl bg-slate-950 px-5 py-4 text-white">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-300">
                  Total Technicians
                </p>
                <p className="mt-3 text-3xl font-semibold">
                  {technicians.length}
                </p>
              </div>
              <div className="rounded-3xl bg-cyan-500 px-5 py-4 text-slate-950">
                <p className="text-xs uppercase tracking-[0.2em] text-cyan-950/70">
                  Active Now
                </p>
                <p className="mt-3 text-3xl font-semibold">
                  {activeTechnicians}
                </p>
              </div>
              <div className="rounded-3xl border border-emerald-200 bg-emerald-50 px-5 py-4">
                <p className="text-xs uppercase tracking-[0.2em] text-emerald-700">
                  Available
                </p>
                <p className="mt-3 text-3xl font-semibold text-emerald-950">
                  {countByStatus(technicians, 'available')}
                </p>
              </div>
              <div className="rounded-3xl border border-amber-200 bg-amber-50 px-5 py-4">
                <p className="text-xs uppercase tracking-[0.2em] text-amber-700">
                  Busy
                </p>
                <p className="mt-3 text-3xl font-semibold text-amber-950">
                  {countByStatus(technicians, 'busy')}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-[28px] border border-slate-200/70 bg-white/90 p-5 shadow-sm backdrop-blur-sm sm:p-6">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="flex-1">
              <label
                htmlFor="technician-search"
                className="mb-2 block text-sm font-medium text-slate-700"
              >
                Search technicians
              </label>
              <input
                id="technician-search"
                type="text"
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                placeholder="Search by name, code, email, phone, department, or specialization"
                className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:bg-white"
              />
            </div>

            <div className="w-full lg:max-w-xs">
              <label
                htmlFor="status-filter"
                className="mb-2 block text-sm font-medium text-slate-700"
              >
                Filter by status
              </label>
              <select
                id="status-filter"
                value={selectedStatus}
                onChange={(event) => setSelectedStatus(event.target.value)}
                className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:bg-white"
              >
                <option value="All">All</option>
                <option value="Available">Available</option>
                <option value="Busy">Busy</option>
                <option value="Assigned">Assigned</option>
                <option value="Inactive">Inactive</option>
              </select>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="rounded-[28px] border border-slate-200/70 bg-white px-6 py-16 text-center text-sm text-slate-500 shadow-sm">
            Loading technicians...
          </div>
        ) : error ? (
          <div className="rounded-[28px] border border-rose-200 bg-white px-6 py-16 text-center shadow-sm">
            <p className="text-sm font-medium text-rose-600">{error}</p>
          </div>
        ) : filteredTechnicians.length === 0 ? (
          <div className="rounded-[28px] border border-slate-200/70 bg-white px-6 py-16 text-center text-sm text-slate-500 shadow-sm">
            No technicians found for the current filters.
          </div>
        ) : (
          <>
            <div className="grid gap-5 xl:grid-cols-3">
              {filteredTechnicians.map((technician) => (
                <article
                  key={technician.id}
                  className="group relative cursor-pointer overflow-hidden rounded-[28px] border border-slate-200/70 bg-white p-5 shadow-sm transition duration-200 hover:-translate-y-1 hover:shadow-[0_22px_60px_-30px_rgba(8,47,73,0.55)]"
                  onClick={() =>
                    navigate(`/admin/technicians/${technician.id}`)
                  }
                >
                  <div className="absolute inset-x-0 top-0 h-1 bg-linear-to-r from-cyan-500 via-sky-500 to-emerald-400" />

                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-center gap-4">
                      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-950 text-lg font-semibold text-white shadow-lg shadow-slate-950/15">
                        {getInitials(technician.full_name)}
                      </div>
                      <div>
                        <h2 className="text-lg font-semibold text-slate-950">
                          {technician.full_name || 'Unnamed technician'}
                        </h2>
                        <p className="text-sm text-slate-500">
                          {technician.email || 'No email available'}
                        </p>
                      </div>
                    </div>

                    <span
                      className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${getStatusTone(technician.status)}`}
                    >
                      {technician.status || 'Unknown'}
                    </span>
                  </div>

                  <div className="mt-5 grid gap-3 sm:grid-cols-2">
                    <div className="rounded-2xl bg-slate-50 p-3">
                      <p className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
                        Tech Code
                      </p>
                      <p className="mt-2 text-sm font-semibold text-slate-900">
                        {technician.technician_code || '-'}
                      </p>
                    </div>
                    <div className="rounded-2xl bg-slate-50 p-3">
                      <p className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
                        Department
                      </p>
                      <p className="mt-2 text-sm font-semibold text-slate-900">
                        {technician.department || '-'}
                      </p>
                    </div>
                    <div className="rounded-2xl bg-slate-50 p-3">
                      <p className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
                        Phone
                      </p>
                      <p className="mt-2 text-sm font-semibold text-slate-900">
                        {technician.phone || '-'}
                      </p>
                    </div>
                    <div className="rounded-2xl bg-slate-50 p-3">
                      <p className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
                        Username
                      </p>
                      <p className="mt-2 text-sm font-semibold text-slate-900">
                        {technician.username || '-'}
                      </p>
                    </div>
                  </div>

                  <div className="mt-5 rounded-3xl border border-slate-200 bg-[linear-gradient(135deg,rgba(6,182,212,0.08),rgba(14,165,233,0.02))] p-4">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <p className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
                          Specialization
                        </p>
                        <p className="mt-2 text-sm font-medium leading-6 text-slate-900">
                          {technician.specialization || 'Not specified'}
                        </p>
                      </div>
                      <div
                        className={`h-3 w-3 rounded-full ${technician.active ? 'bg-emerald-500 shadow-[0_0_0_6px_rgba(16,185,129,0.15)]' : 'bg-slate-300'}`}
                        aria-hidden="true"
                      />
                    </div>
                  </div>

                  <p className="mt-4 text-xs font-medium uppercase tracking-[0.24em] text-cyan-700">
                    Click to view technician details
                  </p>
                </article>
              ))}
            </div>

            <div className="overflow-hidden rounded-[28px] border border-slate-200/70 bg-white shadow-sm">
              <div className="border-b border-slate-200 px-5 py-4 sm:px-6">
                <h2 className="text-lg font-semibold text-slate-900">
                  Technician Directory
                </h2>
                <p className="text-sm text-slate-500">
                  {filteredTechnicians.length} of {technicians.length}{' '}
                  technicians shown
                </p>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-200">
                  <thead className="bg-slate-50">
                    <tr>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Technician
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Code
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Specialization
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Department
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Phone
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 bg-white">
                    {filteredTechnicians.map((technician) => (
                      <tr
                        key={`table-${technician.id}`}
                        className="hover:bg-slate-50"
                      >
                        <td className="px-6 py-4">
                          <div>
                            <p className="font-medium text-slate-900">
                              {technician.full_name || 'Unnamed technician'}
                            </p>
                            <p className="text-sm text-slate-500">
                              {technician.email || '-'}
                            </p>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-700">
                          {technician.technician_code || '-'}
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-700">
                          {technician.specialization || '-'}
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-700">
                          {technician.department || '-'}
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-700">
                          {technician.phone || '-'}
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${getStatusTone(technician.status)}`}
                          >
                            {technician.status || 'Unknown'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
};

export default Technicians;
