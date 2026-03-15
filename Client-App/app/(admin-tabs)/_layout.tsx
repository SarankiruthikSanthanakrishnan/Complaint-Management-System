import { Tabs } from 'expo-router';
import { Home, User, FileText, Bell, Settings } from 'lucide-react-native';

export default function AdminTabLayout() {
  const TabsLayout = [
    { name: 'Dashboard', title: 'Dashboard', icon: Home },
    { name: 'Users', title: 'Users', icon: User },
    { name: 'Technicians', title: 'Technicians', icon: User },
    { name: 'Complaints', title: 'Complaints', icon: FileText },
    { name: 'Reports', title: 'Reports', icon: Bell },
    { name: 'Settings', title: 'Settings', icon: Settings },
    { name: 'Notifications', title: 'Notifications', icon: Bell },
    { name: 'Profile', title: 'Profile', icon: User },
    { name: 'users/[id]', title: 'User Details', icon: null, href: null },
    {
      name: 'technicians/[id]',
      title: 'Technician Details',
      icon: null,
      href: null,
    },
    {
      name: 'users/AddUser',
      title: 'Add User',
      icon: null,
      href: null,
    },
  ];

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
      {TabsLayout.map((tab) => (
        <Tabs.Screen
          key={tab.name}
          name={tab.name}
          options={{
            title: tab.title,
            href: tab.href,
            tabBarIcon: tab.icon
              ? ({ color }) => <tab.icon size={20} color={color} />
              : undefined,
          }}
        />
      ))}
    </Tabs>
  );
}
