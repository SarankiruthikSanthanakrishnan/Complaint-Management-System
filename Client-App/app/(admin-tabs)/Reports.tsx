import { View, Text, FlatList } from 'react-native';
import React from 'react';

const Reports = () => {
  const reports = [
    {
      id: 1,
      title: 'Monthly Complaint Summary',
      description:
        'A comprehensive summary of complaints received in the last month, categorized by type and status.',
      timestamp: '2024-06-15T10:30:00Z',
    },
    {
      id: 2,
      title: 'Technician Performance Report',
      description:
        'An analysis of technician performance based on complaint resolution times and customer feedback.',
      timestamp: '2024-06-14T15:45:00Z',
    },
    {
      id: 3,
      title: 'User Activity Report',
      description:
        'A report detailing user activity on the platform, including login frequency and complaint submissions.',
      timestamp: '2024-06-13T12:20:00Z',
    },
    {
      id: 4,
      title: 'System Performance Report',
      description:
        'An overview of system performance metrics, including uptime and response times.',
      timestamp: '2024-06-12T09:00:00Z',
    },
    {
      id: 5,
      title: 'Customer Satisfaction Report',
      description:
        'A report summarizing customer satisfaction ratings and feedback for resolved complaints.',
      timestamp: '2024-06-11T08:15:00Z',
    },
    {
      id: 6,
      title: 'Complaint Resolution Trends',
      description:
        'An analysis of trends in complaint resolution, highlighting common issues and resolution times.',
      timestamp: '2024-06-10T14:00:00Z',
    },
    {
      id: 7,
      title: 'Escalated Complaints Report',
      description:
        'A report on complaints that have been escalated to higher support levels, including reasons for escalation.',
      timestamp: '2024-06-09T11:30:00Z',
    },
    {
      id: 8,
      title: 'User Feedback Analysis',
      description:
        'An analysis of user feedback received through the platform, categorized by sentiment and topic.',
      timestamp: '2024-06-08T16:45:00Z',
    },
  ];
  return (
    <View
      style={{
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 25,
      }}
    >
      <Text style={{ fontSize: 24, fontWeight: 'bold' }}>Reports</Text>
      <FlatList
        data={reports}
        renderItem={({ item }) => (
          <View
            style={{
              padding: 10,
              borderBottomWidth: 1,
              borderBottomColor: 'lightgray',
            }}
          >
            <Text style={{ fontSize: 18, fontWeight: 'bold' }}>
              {item.title}
            </Text>
            <Text style={{ fontSize: 14, color: 'gray' }}>
              {item.description}
            </Text>
            <Text style={{ fontSize: 12, color: 'darkgray' }}>
              {new Date(item.timestamp).toLocaleString()}
            </Text>
          </View>
        )}
        keyExtractor={(item) => item.id.toString()}
      />
    </View>
  );
};

export default Reports;
