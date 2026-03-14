import React from 'react';
import {
  View,
  Text,
  FlatList,
  StyleSheet,
  TouchableOpacity,
} from 'react-native';
import { Notification } from '@/types/types';

const Notifications = () => {
  const message: Notification[] = [
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

  const renderItem = ({ item }: { item: Notification }) => (
    <TouchableOpacity activeOpacity={0.7} style={styles.notificationCard}>
      <View style={styles.accentBar} />

      <View style={styles.textContainer}>
        <Text style={styles.title}>{item.title}</Text>
        <Text style={styles.description} numberOfLines={2}>
          {item.description}
        </Text>
        <Text style={styles.time}>
          {new Date(item.timestamp).toLocaleDateString([], {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
          })}
        </Text>
      </View>
    </TouchableOpacity>
  );

  return (
    <View style={styles.container}>
      <Text style={styles.headerTitle}>Notifications</Text>

      <FlatList
        data={message}
        keyExtractor={(item) => item.id.toString()}
        renderItem={renderItem}
        contentContainerStyle={styles.listPadding}
        showsVerticalScrollIndicator={false}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FBFBFF', // Slightly off-white for better contrast
    paddingTop: 60,
  },
  headerTitle: {
    fontSize: 28,
    fontWeight: '800',
    color: '#1A1A1A',
    paddingHorizontal: 20,
    marginBottom: 20,
  },
  listPadding: {
    paddingHorizontal: 20,
    paddingBottom: 40,
  },
  notificationCard: {
    backgroundColor: '#FFFFFF',
    borderRadius: 12,
    flexDirection: 'row',
    marginBottom: 12,
    // Shadow
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 10,
    elevation: 2,
    overflow: 'hidden',
  },
  accentBar: {
    width: 5,
    backgroundColor: '#3b82f6', // Primary Blue
  },
  textContainer: {
    padding: 15,
    flex: 1,
  },
  title: {
    fontSize: 16,
    fontWeight: '700',
    color: '#334155',
    marginBottom: 4,
  },
  description: {
    fontSize: 14,
    color: '#64748b',
    lineHeight: 20,
  },
  time: {
    fontSize: 11,
    color: '#94a3b8',
    marginTop: 8,
    fontWeight: '500',
  },
});

export default Notifications;
