import React from 'react';
import {
  BarChart3,
  GraduationCap,
  IdCard,
  Users,
  UserCog,
  FileText,
} from 'lucide-react';

const stats = [
  {
    id: 1,
    title: 'Total Users',
    value: 9,
    icon: Users,
    iconBox: 'bg-sky-100 text-sky-600',
  },
  {
    id: 2,
    title: 'Students',
    value: 7,
    icon: GraduationCap,
    iconBox: 'bg-violet-100 text-violet-600',
  },
  {
    id: 3,
    title: 'Faculty',
    value: 0,
    icon: IdCard,
    iconBox: 'bg-emerald-100 text-emerald-600',
  },
  {
    id: 4,
    title: 'Reports',
    value: 2,
    icon: BarChart3,
    iconBox: 'bg-amber-100 text-amber-600',
  },
];

const quickCards = [
  {
    id: 1,
    title: 'Technicians',
    subtitle: 'Active on duty',
    value: 4,
    icon: UserCog,
    tone: 'bg-cyan-50 text-cyan-700 border-cyan-100',
  },
  {
    id: 2,
    title: 'Complaints',
    subtitle: 'Pending actions',
    value: 3,
    icon: FileText,
    tone: 'bg-rose-50 text-rose-700 border-rose-100',
  },
];

const Dashboard = () => {
  return (
    <section className="w-full">
      <div className="rounded-3xl bg-[radial-gradient(circle_at_top_left,rgba(14,165,233,0.14),transparent_33%),linear-gradient(180deg,#f8fafc_0%,#f1f5f9_100%)] p-5 sm:p-7">
        <div className="mb-6 rounded-2xl border border-slate-200 bg-white/80 p-5 shadow-sm backdrop-blur-sm sm:p-6">
          <h1 className="text-3xl font-bold tracking-tight text-slate-950 sm:text-4xl">
            Admin Dashboard
          </h1>
          <p className="mt-2 text-base font-medium text-slate-600 sm:text-lg">
            Manage users, students and faculty
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {stats.map((item) => (
            <article
              key={item.id}
              className="rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_-20px_rgba(15,23,42,0.35)] transition duration-200 hover:-translate-y-0.5 hover:shadow-[0_16px_40px_-22px_rgba(15,23,42,0.4)] sm:p-6"
            >
              <div
                className={`mb-5 flex h-20 w-20 items-center justify-center rounded-3xl ${item.iconBox}`}
              >
                <item.icon size={38} strokeWidth={2.2} />
              </div>
              <p className="text-5xl font-bold text-slate-950">{item.value}</p>
              <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-600">
                {item.title}
              </p>
            </article>
          ))}
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
          {quickCards.map((item) => (
            <article
              key={item.id}
              className={`rounded-3xl border p-5 sm:p-6 ${item.tone}`}
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-semibold uppercase tracking-[0.2em]">
                    {item.title}
                  </p>
                  <p className="mt-2 text-sm opacity-80">{item.subtitle}</p>
                </div>
                <item.icon size={24} />
              </div>
              <p className="mt-6 text-3xl font-bold">{item.value}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Dashboard;
