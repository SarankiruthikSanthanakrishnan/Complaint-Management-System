import { Tabs } from "expo-router";
import { Home, PlusCircle, FileText, Bell, User } from "lucide-react-native";

export default function TabLayout() {
  return (
    <Tabs screenOptions={{ headerShown: false,tabBarStyle:{backgroundColor:'white'}}}>

      <Tabs.Screen
        name="Home"
        options={{
          title: "Home",
          tabBarIcon: ({ color }) => <Home size={20} color={color} />,
        }}
      />

      <Tabs.Screen
        name="RaiseComplaint"
        options={{
          title: "Raise Complaint",
          tabBarIcon: ({ color }) => <PlusCircle size={20} color={color} />,
        }}
      />

      <Tabs.Screen
        name="MyComplaint"
        options={{
          title: "My Complaint",
          tabBarIcon: ({ color }) => <FileText size={20} color={color} />,
        }}
      />

      <Tabs.Screen
        name="Notifications"
        options={{
          title: "Notifications",
          tabBarIcon: ({ color }) => <Bell size={20} color={color} />,
        }}
      />

      <Tabs.Screen
        name="Profile"
        options={{
          title: "Profile",
          tabBarIcon: ({ color }) => <User size={20} color={color} />,
        }}
      />
    </Tabs>
  );
}
