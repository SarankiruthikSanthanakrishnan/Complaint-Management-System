import React, { useMemo, useState } from 'react';

const reports = [
  {
    id: 1,
    title: 'Monthly Complaint Summary',
    description:
      'A comprehensive summary of complaints received in the last month, categorized by type and status.',
    timestamp: '2024-06-15T10:30:00Z',
  },
  {
    id: 2,
    title: 'Technician Performance Report',
    description:
      'An analysis of technician performance based on complaint resolution times and customer feedback.',
    timestamp: '2024-06-14T15:45:00Z',
  },
  {
    id: 3,
    title: 'User Activity Report',
    description:
      'A report detailing user activity on the platform, including login frequency and complaint submissions.',
    timestamp: '2024-06-13T12:20:00Z',
  },
  {
    id: 4,
    title: 'System Performance Report',
    description:
      'An overview of system performance metrics, including uptime and response times.',
    timestamp: '2024-06-12T09:00:00Z',
  },
  {
    id: 5,
    title: 'Customer Satisfaction Report',
    description:
      'A report summarizing customer satisfaction ratings and feedback for resolved complaints.',
    timestamp: '2024-06-11T08:15:00Z',
  },
  {
    id: 6,
    title: 'Complaint Resolution Trends',
    description:
      'An analysis of trends in complaint resolution, highlighting common issues and resolution times.',
    timestamp: '2024-06-10T14:00:00Z',
  },
  {
    id: 7,
    title: 'Escalated Complaints Report',
    description:
      'A report on complaints that have been escalated to higher support levels, including reasons for escalation.',
    timestamp: '2024-06-09T11:30:00Z',
  },
  {
    id: 8,
    title: 'User Feedback Analysis',
    description:
      'An analysis of user feedback received through the platform, categorized by sentiment and topic.',
    timestamp: '2024-06-08T16:45:00Z',
  },
];

const formatDate = (isoDate) =>
  new Date(isoDate).toLocaleString('en-IN', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

const Reports = () => {
  const [query, setQuery] = useState('');
  const [sortOrder, setSortOrder] = useState('latest');

  const filteredReports = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    const matched = reports.filter((report) => {
      if (!normalizedQuery) {
        return true;
      }

      return (
        report.title.toLowerCase().includes(normalizedQuery) ||
        report.description.toLowerCase().includes(normalizedQuery)
      );
    });

    return [...matched].sort((a, b) => {
      const aTime = new Date(a.timestamp).getTime();
      const bTime = new Date(b.timestamp).getTime();

      return sortOrder === 'latest' ? bTime - aTime : aTime - bTime;
    });
  }, [query, sortOrder]);

  return (
    <section className="min-h-screen bg-slate-100 px-4 py-6 sm:px-6 lg:px-10">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <div className="overflow-hidden rounded-3xl bg-linear-to-r from-slate-900 via-slate-800 to-cyan-800 px-6 py-8 text-white shadow-lg sm:px-8">
          <p className="text-sm uppercase tracking-[0.28em] text-cyan-200">
            Admin Insights
          </p>
          <div className="mt-4 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <h1 className="text-3xl font-semibold sm:text-4xl">Reports</h1>
              <p className="mt-2 max-w-2xl text-sm text-slate-200 sm:text-base">
                Review complaint operations, technician productivity, and user
                platform behavior through curated administrative reports.
              </p>
            </div>
            <div className="rounded-2xl bg-white/10 px-5 py-4 backdrop-blur-sm">
              <p className="text-xs text-slate-200">Total Reports</p>
              <p className="mt-2 text-3xl font-semibold">{reports.length}</p>
            </div>
          </div>
        </div>

        <div className="rounded-3xl bg-white p-5 shadow-sm ring-1 ring-slate-200 sm:p-6">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="flex-1">
              <label
                htmlFor="report-search"
                className="mb-2 block text-sm font-medium text-slate-700"
              >
                Search reports
              </label>
              <input
                id="report-search"
                type="text"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search by report title or description"
                className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:bg-white"
              />
            </div>

            <div className="w-full lg:max-w-xs">
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

        {filteredReports.length === 0 ? (
          <div className="rounded-3xl bg-white px-6 py-16 text-center text-sm text-slate-500 shadow-sm ring-1 ring-slate-200">
            No reports found for your search.
          </div>
        ) : (
          <>
            <div className="grid gap-5 lg:grid-cols-2">
              {filteredReports.map((report) => (
                <article
                  key={report.id}
                  className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
                >
                  <div className="flex items-start justify-between gap-4">
                    <h2 className="text-lg font-semibold text-slate-900">
                      {report.title}
                    </h2>
                    <span className="inline-flex rounded-full bg-cyan-100 px-3 py-1 text-xs font-semibold text-cyan-800">
                      Report #{report.id}
                    </span>
                  </div>

                  <p className="mt-3 text-sm leading-6 text-slate-600">
                    {report.description}
                  </p>

                  <p className="mt-4 text-xs font-medium uppercase tracking-[0.2em] text-slate-500">
                    Generated: {formatDate(report.timestamp)}
                  </p>
                </article>
              ))}
            </div>

            <div className="overflow-hidden rounded-3xl bg-white shadow-sm ring-1 ring-slate-200">
              <div className="border-b border-slate-200 px-5 py-4 sm:px-6">
                <h2 className="text-lg font-semibold text-slate-900">
                  Reports Directory
                </h2>
                <p className="text-sm text-slate-500">
                  {filteredReports.length} reports listed
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
                        Timestamp
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 bg-white">
                    {filteredReports.map((report) => (
                      <tr
                        key={`table-${report.id}`}
                        className="hover:bg-slate-50"
                      >
                        <td className="px-6 py-4 text-sm font-medium text-slate-900">
                          {report.id}
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-700">
                          {report.title}
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-700">
                          {formatDate(report.timestamp)}
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

export default Reports;
