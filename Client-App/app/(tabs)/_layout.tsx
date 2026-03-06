import { Tabs } from "expo-router";


export default function TabLayout() {
    return (
        <Tabs>
            <Tabs.Screen name="index"/>
            <Tabs.Screen name="complaints" />
            <Tabs.Screen name="profile"/>
            <Tabs.Screen name="settings"/>
            <Tabs.Screen name="help"/>
        </Tabs>
    );
}
