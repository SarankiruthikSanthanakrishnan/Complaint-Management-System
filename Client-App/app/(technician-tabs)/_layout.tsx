import { Tabs } from "expo-router";
import { Home, FileText, PlusCircle, Bell, User } from "lucide-react-native";

export default function TechnicianTabLayout() {
  return (
    <Tabs
      screenOptions={{
        headerShown: false,
        tabBarStyle: {
          backgroundColor: "white",
          borderTopWidth: 0,
          elevation: 5
        }
      }}
    >
      <Tabs.Screen
        name="Dashboard"
        options={{
          title: "Dashboard",
          tabBarIcon: ({ color }) => <Home size={20} color={color} />
        }}
      />
      <Tabs.Screen
        name="AssignedTasks"
        options={{
          title: "Assigned Tasks",
          tabBarIcon: ({ color }) => <FileText size={20} color={color} />
        }}
      />
      <Tabs.Screen
        name="UpdateStatus"
        options={{
          title: "Update Status",
          tabBarIcon: ({ color }) => <PlusCircle size={20} color={color} />
        }}
      />
      <Tabs.Screen
        name="Notifications"
        options={{
          title: "Notifications",
          tabBarIcon: ({ color }) => <Bell size={20} color={color} />
        }}
      />
      <Tabs.Screen
        name="Profile"
        options={{
          title: "Profile",
          tabBarIcon: ({ color }) => <User size={20} color={color} />
        }}
      />
    </Tabs>
  );
}
