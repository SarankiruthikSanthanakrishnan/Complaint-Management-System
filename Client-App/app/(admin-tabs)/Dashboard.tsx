import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Pressable,
  ActivityIndicator,
} from 'react-native';
import React, { useEffect, useState } from 'react';
import { Users, GraduationCap, BookUser, BarChart3 } from 'lucide-react-native';
import { GetAllUsers } from '@/services/AdminServices';

const AdminDashboard = () => {
  const [totalUsers, setTotalUsers] = useState(0);
  const [students, setStudents] = useState(0);
  const [faculty, setFaculty] = useState(0);
  const [reports, setReports] = useState(0);
  const [loading, setLoading] = useState(true);

  const fetchUsers = async () => {
    try {
      setLoading(true);

      const response = await GetAllUsers();
      const users = response?.data?.users || [];

      setTotalUsers(users.length);

      const studentCount = users.filter(
        (u: any) => u.role === 'Student'
      ).length;
      const facultyCount = users.filter(
        (u: any) => u.role === 'Faculty'
      ).length;

      setStudents(studentCount);
      setFaculty(facultyCount);

      // Example reports count (replace with real logic later)
      setReports(users.length - (studentCount + facultyCount));
    } catch (error) {
      console.log('Dashboard error:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const cards = [
    {
      title: 'Total Users',
      value: totalUsers,
      icon: Users,
      color: '#007AFF',
    },
    {
      title: 'Students',
      value: students,
      icon: GraduationCap,
      color: '#5856D6',
    },
    {
      title: 'Faculty',
      value: faculty,
      icon: BookUser,
      color: '#34C759',
    },
    {
      title: 'Reports',
      value: reports,
      icon: BarChart3,
      color: '#ff9500',
    },
  ];

  if (loading) {
    return (
      <View style={styles.loader}>
        <ActivityIndicator size="large" color="#007AFF" />
      </View>
    );
  }

  return (
    <ScrollView style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>Admin Dashboard</Text>
        <Text style={styles.subtitle}>Manage users, students and faculty</Text>
      </View>

      {/* Cards */}
      <View style={styles.cardContainer}>
        {cards.map((item, index) => {
          const Icon = item.icon;

          return (
            <Pressable key={index} style={styles.card}>
              <View
                style={[styles.iconBox, { backgroundColor: item.color + '20' }]}
              >
                <Icon size={28} color={item.color} />
              </View>

              <Text style={styles.cardValue}>{item.value}</Text>

              <Text style={styles.cardTitle}>{item.title}</Text>
            </Pressable>
          );
        })}
      </View>
    </ScrollView>
  );
};

export default AdminDashboard;

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
    padding: 20,
    marginTop: 30,
  },

  loader: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },

  header: {
    marginBottom: 25,
  },

  title: {
    fontSize: 26,
    fontWeight: 'bold',
  },

  subtitle: {
    color: '#666',
    marginTop: 4,
  },

  cardContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },

  card: {
    width: '48%',
    backgroundColor: 'white',
    borderRadius: 14,
    padding: 18,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOpacity: 0.1,
    shadowRadius: 6,
    elevation: 4,
  },

  iconBox: {
    width: 45,
    height: 45,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 10,
  },

  cardValue: {
    fontSize: 22,
    fontWeight: 'bold',
  },

  cardTitle: {
    color: '#666',
    marginTop: 4,
  },
});
