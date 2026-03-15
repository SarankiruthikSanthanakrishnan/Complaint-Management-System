import {
  View,
  Text,
  FlatList,
  StyleSheet,
  ActivityIndicator,
  TouchableOpacity,
  Pressable,
} from 'react-native';
import React, { useEffect, useState } from 'react';
import { GetAllUsers } from '@/services/AdminServices';
import { User } from '@/types/types';
import { useRouter } from 'expo-router';
import { Plus } from 'lucide-react-native';

const Users = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    fetchUsers();
  }, []);

  const AddNewUser = async () => {
    router.push(`/(admin-tabs)/users/AddUser`);
  };
  const fetchUsers = async () => {
    try {
      setLoading(true);
      const response = await GetAllUsers();
      if (response.data && response.data.users) {
        setUsers(response.data.users);
      } else {
        setUsers(response.data || []);
      }
    } catch (err: any) {
      setError(err?.response?.data?.message || 'Failed to fetch users');
      console.log('Error fetching users:', err);
    } finally {
      setLoading(false);
    }
  };

  const renderUserCard = ({ item }: { item: User }) => (
    <TouchableOpacity
      style={styles.card}
      onPress={() => router.push(`/(admin-tabs)/users/${item.id}`)}
      activeOpacity={0.7}
    >
      <View style={styles.cardHeader}>
        <Text style={styles.name}>{item.full_name || item.username}</Text>
        <Text style={styles.roleBadge}>{item.role}</Text>
      </View>
      <View style={styles.cardBody}>
        <Text style={styles.infoText}>
          ID: {item.id ? item.id.toString() : 'N/A'}
        </Text>
        <Text style={styles.infoText}>Username: {item.username || 'N/A'}</Text>
        <Text style={styles.infoText}>Email: {item.email || 'N/A'}</Text>
      </View>
    </TouchableOpacity>
  );

  if (loading) {
    return (
      <View style={styles.centerContainer}>
        <ActivityIndicator size="large" color="#0000ff" />
      </View>
    );
  }

  if (error) {
    return (
      <View style={styles.centerContainer}>
        <Text style={styles.errorText}>{error}</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>All Users</Text>
      <Pressable onPress={AddNewUser} style={styles.addUserButton}>
        <View style={styles.addUserContent}>
          <Plus size={20} color="#fff" />
          <Text style={styles.addUserText}>Add User</Text>
        </View>
      </Pressable>
      <FlatList
        data={users}
        keyExtractor={(item, index) =>
          item.id ? item.id.toString() : index.toString()
        }
        renderItem={renderUserCard}
        contentContainerStyle={styles.listContainer}
        showsVerticalScrollIndicator={false}
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
    position: 'relative',
  },
  centerContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5F5F7',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 16,
    color: '#333',
    textAlign: 'center',
  },
  listContainer: {
    paddingBottom: 20,
  },
  card: {
    backgroundColor: '#FFF',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
    elevation: 3,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
  },
  cardHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#F0F0F0',
    paddingBottom: 8,
  },
  name: {
    fontSize: 18,
    fontWeight: '600',
    color: '#1a1a1a',
  },
  roleBadge: {
    backgroundColor: '#E6F0FF',
    color: '#0066CC',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 12,
    fontSize: 12,
    fontWeight: 'bold',
    textTransform: 'capitalize',
    overflow: 'hidden',
  },
  cardBody: {
    gap: 6,
  },
  infoText: {
    fontSize: 14,
    color: '#555',
  },
  errorText: {
    color: '#D8000C',
    fontSize: 16,
  },
  addUserButton: {
    position: 'absolute',
    bottom: 20,
    right: 20,
    backgroundColor: '#0066CC',
    paddingVertical: 12,
    paddingHorizontal: 20,
    borderRadius: 30,
    elevation: 5,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.2,
    shadowRadius: 4,
    zIndex: 1,
  },

  addUserContent: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },

  addUserText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
});

export default Users;
