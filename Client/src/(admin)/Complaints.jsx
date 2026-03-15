import React, { useMemo, useState } from 'react';

const complaints = [
  {
    id: 1,
    title: 'Air Conditioner Not Cooling',
    description:
      'The air conditioner in the living room is not cooling properly.',
    status: 'Open',
    createdAt: '2024-06-15T10:30:00Z',
  },
  {
    id: 2,
    title: 'Internet Connectivity Issue',
    description:
      'The internet connection is frequently dropping in the office.',
    status: 'In Progress',
    createdAt: '2024-06-14T15:45:00Z',
  },
  {
    id: 3,
    title: 'Leaking Faucet',
    description: 'The kitchen faucet is leaking and causing water wastage.',
    status: 'Resolved',
    createdAt: '2024-06-13T12:20:00Z',
  },
  {
    id: 4,
    title: 'Broken Window',
    description: 'A window in the bedroom is broken and needs to be repaired.',
    status: 'Open',
    createdAt: '2024-06-12T09:00:00Z',
  },
  {
    id: 5,
    title: 'Malfunctioning Heater',
    description:
      'The heater in the bathroom is not working during the cold season.',
    status: 'In Progress',
    createdAt: '2024-06-11T08:15:00Z',
  },
  {
    id: 6,
    title: 'Clogged Drain',
    description:
      'The drain in the kitchen sink is clogged and causing water backup.',
    status: 'Resolved',
    createdAt: '2024-06-10T14:00:00Z',
  },
  {
    id: 7,
    title: 'Faulty Light Switch',
    description:
      'The light switch in the hallway is faulty and needs to be replaced.',
    status: 'Open',
    createdAt: '2024-06-09T11:30:00Z',
  },
  {
    id: 8,
    title: 'Noisy Washing Machine',
    description: 'The washing machine is making loud noises during operation.',
    status: 'In Progress',
    createdAt: '2024-06-08T16:45:00Z',
  },
];

const statusStyles = {
  Open: 'bg-rose-100 text-rose-800',
  'In Progress': 'bg-amber-100 text-amber-800',
  Resolved: 'bg-emerald-100 text-emerald-800',
};

const formatDate = (isoDate) =>
  new Date(isoDate).toLocaleString('en-IN', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

const countByStatus = (items, status) =>
  items.filter((item) => item.status === status).length;

const Complaints = () => {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');
  const [sortOrder, setSortOrder] = useState('latest');

  const filteredComplaints = useMemo(() => {
    const searchValue = query.trim().toLowerCase();

    const matched = complaints.filter((complaint) => {
      const matchesSearch =
        searchValue === '' ||
        complaint.title.toLowerCase().includes(searchValue) ||
        complaint.description.toLowerCase().includes(searchValue);

      const matchesStatus =
        statusFilter === 'All' || complaint.status === statusFilter;

      return matchesSearch && matchesStatus;
    });

    return [...matched].sort((a, b) => {
      const aTime = new Date(a.createdAt).getTime();
      const bTime = new Date(b.createdAt).getTime();

      return sortOrder === 'latest' ? bTime - aTime : aTime - bTime;
    });
  }, [query, statusFilter, sortOrder]);

  return (
    <section className="min-h-screen bg-slate-100 px-4 py-6 sm:px-6 lg:px-10">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <div className="overflow-hidden rounded-3xl bg-linear-to-r from-slate-900 via-slate-800 to-cyan-800 px-6 py-8 text-white shadow-lg sm:px-8">
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-200">
            Admin Operations
          </p>
          <div className="mt-4 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <h1 className="text-3xl font-semibold sm:text-4xl">Complaints</h1>
              <p className="mt-2 max-w-2xl text-sm text-slate-200 sm:text-base">
                Monitor complaint pipeline, track status distribution, and
                identify critical issues that need immediate follow-up.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="rounded-2xl bg-white/10 p-4 backdrop-blur-sm">
                <p className="text-xs text-slate-200">Total</p>
                <p className="mt-2 text-2xl font-semibold">
                  {complaints.length}
                </p>
              </div>
              <div className="rounded-2xl bg-white/10 p-4 backdrop-blur-sm">
                <p className="text-xs text-slate-200">Open</p>
                <p className="mt-2 text-2xl font-semibold">
                  {countByStatus(complaints, 'Open')}
                </p>
              </div>
              <div className="rounded-2xl bg-white/10 p-4 backdrop-blur-sm">
                <p className="text-xs text-slate-200">In Progress</p>
                <p className="mt-2 text-2xl font-semibold">
                  {countByStatus(complaints, 'In Progress')}
                </p>
              </div>
              <div className="rounded-2xl bg-white/10 p-4 backdrop-blur-sm">
                <p className="text-xs text-slate-200">Resolved</p>
                <p className="mt-2 text-2xl font-semibold">
                  {countByStatus(complaints, 'Resolved')}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-3xl bg-white p-5 shadow-sm ring-1 ring-slate-200 sm:p-6">
          <div className="grid gap-4 lg:grid-cols-[1fr_220px_220px]">
            <div>
              <label
                htmlFor="complaint-search"
                className="mb-2 block text-sm font-medium text-slate-700"
              >
                Search complaints
              </label>
              <input
                id="complaint-search"
                type="text"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search by title or description"
                className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:bg-white"
              />
            </div>

            <div>
              <label
                htmlFor="status-filter"
                className="mb-2 block text-sm font-medium text-slate-700"
              >
                Filter status
              </label>
              <select
                id="status-filter"
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
                className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:bg-white"
              >
                <option value="All">All</option>
                <option value="Open">Open</option>
                <option value="In Progress">In Progress</option>
                <option value="Resolved">Resolved</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="sort-order"
                className="mb-2 block text-sm font-medium text-slate-700"
              >
                Sort by
              </label>
              <select
                id="sort-order"
                value={sortOrder}
                onChange={(event) => setSortOrder(event.target.value)}
                className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:bg-white"
              >
                <option value="latest">Latest first</option>
                <option value="oldest">Oldest first</option>
              </select>
            </div>
          </div>
        </div>

        {filteredComplaints.length === 0 ? (
          <div className="rounded-3xl bg-white px-6 py-16 text-center text-sm text-slate-500 shadow-sm ring-1 ring-slate-200">
            No complaints found for the current search/filter.
          </div>
        ) : (
          <>
            <div className="grid gap-5 lg:grid-cols-2">
              {filteredComplaints.map((complaint) => (
                <article
                  key={complaint.id}
                  className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
                >
                  <div className="flex items-start justify-between gap-4">
                    <h2 className="text-lg font-semibold text-slate-900">
                      {complaint.title}
                    </h2>
                    <span
                      className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${statusStyles[complaint.status]}`}
                    >
                      {complaint.status}
                    </span>
                  </div>

                  <p className="mt-3 text-sm leading-6 text-slate-600">
                    {complaint.description}
                  </p>

                  <p className="mt-4 text-xs font-medium uppercase tracking-[0.2em] text-slate-500">
                    Created: {formatDate(complaint.createdAt)}
                  </p>
                </article>
              ))}
            </div>

            <div className="overflow-hidden rounded-3xl bg-white shadow-sm ring-1 ring-slate-200">
              <div className="border-b border-slate-200 px-5 py-4 sm:px-6">
                <h2 className="text-lg font-semibold text-slate-900">
                  Complaint Registry
                </h2>
                <p className="text-sm text-slate-500">
                  {filteredComplaints.length} complaints listed
                </p>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-200">
                  <thead className="bg-slate-50">
                    <tr>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        ID
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Title
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Status
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Created
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 bg-white">
                    {filteredComplaints.map((complaint) => (
                      <tr
                        key={`table-${complaint.id}`}
                        className="hover:bg-slate-50"
                      >
                        <td className="px-6 py-4 text-sm font-medium text-slate-900">
                          {complaint.id}
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-700">
                          {complaint.title}
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${statusStyles[complaint.status]}`}
                          >
                            {complaint.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-700">
                          {formatDate(complaint.createdAt)}
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

export default Complaints;
