export interface User {
  id: Number;
  username: string;
  full_name: string;
  email: string;
  password: string;
  role: 'Admin' | 'MasterAdmin' | 'Faculty' | 'Student' | 'Technician';
  profile_image: string;
  contact: string;
}

export interface Student {
  reg_no: string;
  student_name: string;
  department: string;
  contact_mail: string;
  contact_number: string;
  active: Boolean;
}

export interface Notification {
  id: Number;
  title: string;
  description: string;
  timestamp: string;
}

export interface Complaint {
  id: Number;
  complaint_code: string;
  subject: string;
  description: string;
  status: 'Submitted' | 'Assigned' | 'In Progress' | 'Completed' | 'InComplete';
  created_at: string;
  updated_at: string;
  started_at: string;
  evidence_before: string;
  evidence_after: string;
}
