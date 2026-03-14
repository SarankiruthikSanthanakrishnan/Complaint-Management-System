import { View, Text, FlatList, StyleSheet } from 'react-native';
import React from 'react';

const Complaints = () => {
  const complaints = [
    {
      id: 1,
      title: 'Air Conditioner Not Cooling',
      description:
        'The air conditioner in the living room is not cooling properly.',
      status: 'Open',
      createdAt: '2024-06-15T10:30:00Z',
    },
    {
      id: 2,
      title: 'Internet Connectivity Issue',
      description:
        'The internet connection is frequently dropping in the office.',
      status: 'In Progress',
      createdAt: '2024-06-14T15:45:00Z',
    },
    {
      id: 3,
      title: 'Leaking Faucet',
      description: 'The kitchen faucet is leaking and causing water wastage.',
      status: 'Resolved',
      createdAt: '2024-06-13T12:20:00Z',
    },
    {
      id: 4,
      title: 'Broken Window',
      description:
        'A window in the bedroom is broken and needs to be repaired.',
      status: 'Open',
      createdAt: '2024-06-12T09:00:00Z',
    },
    {
      id: 5,
      title: 'Malfunctioning Heater',
      description:
        'The heater in the bathroom is not working during the cold season.',
      status: 'In Progress',
      createdAt: '2024-06-11T08:15:00Z',
    },
    {
      id: 6,
      title: 'Clogged Drain',
      description:
        'The drain in the kitchen sink is clogged and causing water backup.',
      status: 'Resolved',
      createdAt: '2024-06-10T14:00:00Z',
    },
    {
      id: 7,
      title: 'Faulty Light Switch',
      description:
        'The light switch in the hallway is faulty and needs to be replaced.',
      status: 'Open',
      createdAt: '2024-06-09T11:30:00Z',
    },
    {
      id: 8,
      title: 'Noisy Washing Machine',
      description:
        'The washing machine is making loud noises during operation.',
      status: 'In Progress',
      createdAt: '2024-06-08T16:45:00Z',
    },
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Open':
        return '#ef4444'; // Red
      case 'In Progress':
        return '#f59e0b'; // Amber
      case 'Resolved':
        return '#10b981'; // Green
      default:
        return '#6b7280'; // Gray
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.header}>Complaints</Text>

      <FlatList
        data={complaints}
        keyExtractor={(item) => item.id.toString()}
        contentContainerStyle={styles.listContent}
        showsVerticalScrollIndicator={false}
        renderItem={({ item }) => (
          <View style={styles.card}>
            <View style={styles.cardHeader}>
              <Text style={styles.title}>{item.title}</Text>
              <View
                style={[
                  styles.badge,
                  { backgroundColor: getStatusColor(item.status) },
                ]}
              >
                <Text style={styles.badgeText}>{item.status}</Text>
              </View>
            </View>

            <Text style={styles.description}>{item.description}</Text>

            <Text style={styles.footer}>
              Created: {new Date(item.createdAt).toLocaleDateString()}
            </Text>
          </View>
        )}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8fafc', // Light slate background
    paddingTop: 50,
  },
  header: {
    fontSize: 26,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 20,
    color: '#1e293b',
  },
  listContent: {
    paddingHorizontal: 20,
    paddingBottom: 40,
  },
  card: {
    backgroundColor: 'white',
    padding: 16,
    borderRadius: 12,
    marginBottom: 12,
    // Shadow for iOS
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    // Elevation for Android
    elevation: 3,
  },
  cardHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 8,
  },
  title: {
    fontSize: 17,
    fontWeight: '700',
    color: '#334155',
    flex: 1,
    marginRight: 10,
  },
  description: {
    fontSize: 14,
    color: '#64748b',
    lineHeight: 20,
    marginBottom: 12,
  },
  badge: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
  },
  badgeText: {
    color: 'white',
    fontSize: 10,
    fontWeight: 'bold',
    textTransform: 'uppercase',
  },
  footer: {
    fontSize: 12,
    color: '#94a3b8',
    borderTopWidth: 1,
    borderTopColor: '#f1f5f9',
    paddingTop: 8,
  },
});

export default Complaints;
