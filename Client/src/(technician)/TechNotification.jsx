import React from 'react';
import {
  Bell,
  CheckCircle2,
  AlertCircle,
  Info,
  UserPlus,
  Clock,
  ChevronRight,
} from 'lucide-react';

const NotificationPage = () => {
  const messages = [
    {
      id: 1,
      title: 'New Complaint Assigned',
      description:
        'A new complaint has been assigned to you. Please check your dashboard for details.',
      timestamp: '2024-06-15T10:30:00Z',
    },
    {
      id: 2,
      title: 'Complaint Resolved',
      description:
        'The complaint regarding the air conditioner has been marked as resolved. Please review the resolution details.',
      timestamp: '2024-06-14T15:45:00Z',
    },
    {
      id: 3,
      title: 'New User Registered',
      description:
        'A new user has registered on the platform. Please check the user management section for more information.',
      timestamp: '2024-06-13T12:20:00Z',
    },
    {
      id: 4,
      title: 'System Maintenance Scheduled',
      description:
        'The system will undergo maintenance on June 20th from 2:00 AM to 4:00 AM. Please save your work accordingly.',
      timestamp: '2024-06-12T09:00:00Z',
    },
    {
      id: 5,
      title: 'Password Change Required',
      description:
        'For security reasons, please change your password within the next 7 days.',
      timestamp: '2024-06-11T08:15:00Z',
    },
    {
      id: 6,
      title: 'New Report Available',
      description:
        'A new report on system performance is available. Please review it at your earliest convenience.',
      timestamp: '2024-06-10T14:00:00Z',
    },
    {
      id: 7,
      title: 'Complaint Escalated',
      description:
        'The complaint regarding the internet connectivity issue has been escalated to the technical team. Please check the complaint details for more information.',
      timestamp: '2024-06-09T11:30:00Z',
    },
    {
      id: 8,
      title: 'User Feedback Received',
      description:
        'A new feedback has been received from a user regarding the mobile app. Please review the feedback and take necessary actions.',
      timestamp: '2024-06-08T16:45:00Z',
    },
    {
      id: 9,
      title: 'New Technician Assigned',
      description:
        'A new technician has been assigned to the complaint regarding the heating system. Please check the technician details for more information.',
      timestamp: '2024-06-07T10:00:00Z',
    },
  ];

  // Title-ah poruthu icon mathura logic
  const getIcon = (title) => {
    if (title.includes('Resolved'))
      return <CheckCircle2 className="text-green-500" size={20} />;
    if (title.includes('Maintenance') || title.includes('Required'))
      return <AlertCircle className="text-red-500" size={20} />;
    if (title.includes('User'))
      return <UserPlus className="text-blue-500" size={20} />;
    return <Info className="text-blue-500" size={20} />;
  };

  return (
    <div className="min-h-screen bg-[#f8f9fa] pb-10">
      {/* Header Section */}
      <div className="bg-white border-b border-gray-100 py-8 px-6 mb-6">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-black text-gray-900 flex items-center gap-3">
              Notifications
              <span className="bg-blue-600 text-white text-xs px-2.5 py-1 rounded-full">
                {messages.length}
              </span>
            </h1>
            <p className="text-gray-500 font-medium mt-1">
              Stay updated with your system activities
            </p>
          </div>
          <button className="text-sm font-bold text-blue-600 hover:bg-blue-50 px-4 py-2 rounded-xl transition-colors">
            Mark all as read
          </button>
        </div>
      </div>

      {/* Notifications List */}
      <div className="max-w-4xl mx-auto px-6 space-y-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className="bg-white p-5 rounded-[2rem] shadow-sm border border-gray-100 flex items-start gap-5 hover:shadow-md transition-all cursor-pointer group"
          >
            {/* Icon Container */}
            <div className="bg-gray-50 p-4 rounded-2xl group-hover:bg-white transition-colors border border-transparent group-hover:border-gray-100">
              {getIcon(msg.title)}
            </div>

            {/* Content */}
            <div className="flex-grow">
              <div className="flex items-center justify-between mb-1">
                <h3 className="font-black text-gray-800 text-lg leading-tight">
                  {msg.title}
                </h3>
                <span className="flex items-center gap-1 text-[11px] font-bold text-gray-400 uppercase tracking-wider">
                  <Clock size={12} />
                  {new Date(msg.timestamp).toLocaleDateString()}
                </span>
              </div>
              <p className="text-gray-500 font-medium text-sm leading-relaxed max-w-2xl">
                {msg.description}
              </p>
            </div>

            {/* Right Arrow */}
            <div className="self-center text-gray-300 group-hover:text-blue-500 transition-colors">
              <ChevronRight size={20} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default NotificationPage;
