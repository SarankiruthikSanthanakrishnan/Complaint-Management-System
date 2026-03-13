import { Tabs } from 'expo-router';
import { Home, User, FileText, Bell, Settings } from 'lucide-react-native';

export default function AdminTabLayout() {
  return (
    <Tabs
      screenOptions={{
        headerShown: false,
        tabBarStyle: {
          backgroundColor: 'white',
          borderTopWidth: 0,
          elevation: 5,
        },
      }}
    >
      <Tabs.Screen
        name="Dashboard"
        options={{
          title: 'Dashboard',
          tabBarIcon: ({ color }) => <Home size={20} color={color} />,
        }}
      />
      <Tabs.Screen
        name="Users"
        options={{
          title: 'Users',
          tabBarIcon: ({ color }) => <User size={20} color={color} />,
        }}
      />
      <Tabs.Screen
        name="Technicians"
        options={{
          title: 'Technicians',
          tabBarIcon: ({ color }) => <User size={20} color={color} />,
        }}
      />
      <Tabs.Screen
        name="Complaints"
        options={{
          title: 'Complaints',
          tabBarIcon: ({ color }) => <FileText size={20} color={color} />,
        }}
      />
      <Tabs.Screen
        name="Reports"
        options={{
          title: 'Reports',
          tabBarIcon: ({ color }) => <Bell size={20} color={color} />,
        }}
      />
      <Tabs.Screen
        name="Settings"
        options={{
          title: 'Settings',
          tabBarIcon: ({ color }) => <Settings size={20} color={color} />,
        }}
      />
      <Tabs.Screen
        name="Notifications"
        options={{
          title: 'Notifications',
          tabBarIcon: ({ color }) => <Bell size={20} color={color} />,
        }}
      />
      <Tabs.Screen
        name="Profile"
        options={{
          title: 'Profile',
          tabBarIcon: ({ color }) => <User size={20} color={color} />,
        }}
      />
      <Tabs.Screen
        name="users/[id]"
        options={{
          href: null,
          title: 'User Details',
        }}
      />
      <Tabs.Screen
        name="technicians/[id]"
        options={{
          href: null,
          title: 'Technician Details',
        }}
      />
    </Tabs>
  );
}
