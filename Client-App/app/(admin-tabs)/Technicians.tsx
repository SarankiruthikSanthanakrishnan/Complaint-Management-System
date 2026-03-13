import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity,
} from 'react-native';
import React from 'react';
import { useRouter } from 'expo-router';

const technicians = [
  { id: '1', name: 'Kumar', department: 'Electrical' },
  { id: '2', name: 'Ravi', department: 'Plumbing' },
  { id: '3', name: 'Suresh', department: 'Maintenance' },
];

const Technicians = () => {
  const router = useRouter();
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Technicians</Text>

      <FlatList
        data={technicians}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <TouchableOpacity
            onPress={() =>
              router.push(`/(admin-tabs)/technicians/${item.id}.tsx`)
            }
          >
            <View style={styles.card}>
              <Text style={styles.name}>{item.name}</Text>
              <Text style={styles.department}>{item.department}</Text>
            </View>
          </TouchableOpacity>
        )}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F5F5F7',
    paddingHorizontal: 16,
    paddingTop: 40,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 16,
    color: '#333',
    textAlign: 'center',
  },
  card: {
    backgroundColor: '#fff',
    padding: 15,
    borderRadius: 10,
    marginBottom: 10,
    elevation: 2,
  },
  name: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  department: {
    fontSize: 14,
    color: 'gray',
  },
});

export default Technicians;
