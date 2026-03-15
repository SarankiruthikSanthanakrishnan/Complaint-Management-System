import React from 'react';

const profile = {
  fullName: 'Sarankiruthik S S',
  email: 'sknexus.erp@gmail.com',
};

const Profile = () => {
  return (
    <section className="min-h-screen bg-slate-200 px-4 py-10 sm:px-6 lg:px-10">
      <div className="mx-auto flex w-full max-w-4xl flex-col items-center">
        <div className="mt-28 text-center sm:mt-24">
          <h1 className="text-4xl font-bold tracking-tight text-slate-950 sm:text-5xl">
            {profile.fullName}
          </h1>
          <p className="mt-2 text-lg font-semibold text-slate-600 sm:text-2xl">
            {profile.email}
          </p>
        </div>

        <div className="mt-12 w-full rounded-3xl border border-slate-300/70 bg-white/80 p-7 shadow-[0_12px_28px_-16px_rgba(15,23,42,0.55)] sm:p-9">
          <div className="space-y-9">
            <div>
              <p className="text-sm font-bold uppercase tracking-[0.08em] text-slate-400 sm:text-3xl">
                Full Name
              </p>
              <p className="mt-2 text-2xl font-medium text-slate-900 sm:text-5xl">
                {profile.fullName}
              </p>
            </div>

            <div>
              <p className="text-sm font-bold uppercase tracking-[0.08em] text-slate-400 sm:text-3xl">
                Email
              </p>
              <p className="mt-2 break-all text-2xl font-medium text-slate-900 sm:text-5xl">
                {profile.email}
              </p>
            </div>
          </div>
        </div>

        <div className="mt-10 flex w-full max-w-xl flex-col gap-4 sm:flex-row sm:justify-center">
          <button
            type="button"
            className="w-full rounded-2xl bg-blue-600 px-8 py-4 text-xl font-semibold text-white transition hover:bg-blue-700 sm:w-auto sm:min-w-56 sm:text-3xl"
          >
            Edit Profile
          </button>
          <button
            type="button"
            className="w-full rounded-2xl bg-red-500 px-8 py-4 text-xl font-semibold text-white transition hover:bg-red-600 sm:w-auto sm:min-w-56 sm:text-3xl"
          >
            Logout
          </button>
        </div>
      </div>
    </section>
  );
};

export default Profile;
