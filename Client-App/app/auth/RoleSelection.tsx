import { View, Text, Pressable, StyleSheet, SafeAreaView } from 'react-native'
import React, { useEffect } from 'react'
import { useRouter } from 'expo-router'
import { User, ShieldCheck } from 'lucide-react-native'
import AsyncStorage from '@react-native-async-storage/async-storage'

const RoleSelection = () => {
  const router = useRouter()

  useEffect(() => {
    AsyncStorage.setItem('hasSeenRoleSelection', 'true');
  }, [])

  return (
    <View style={styles.container}>
      <View style={styles.content}>
        <View style={styles.header}>
          <Text style={styles.title}>Welcome!</Text>
          <Text style={styles.subtitle}>Please select your role to continue</Text>
        </View>

        <View style={styles.cardsContainer}>
          {/* Student / Faculty Card */}
          <Pressable
            style={({ pressed }) => [
              styles.card,
              pressed && styles.cardPressed
            ]}
            onPress={() => router.push(`/auth/VerifyRegno` as any)}
          >
            <View style={[styles.iconContainer, { backgroundColor: '#e0f2fe' }]}>
              <User size={32} color="#0284c7" />
            </View>
            <Text style={styles.cardTitle}>Student </Text>
            <Text style={styles.cardDesc}>Register to raise complaints and track statuses</Text>
          </Pressable>

          {/* Admin / Technician Card */}
          <Pressable
            style={({ pressed }) => [
              styles.card,
              pressed && styles.cardPressed
            ]}
            onPress={() => router.push(`/auth/Login` as any)}
          >
            <View style={[styles.iconContainer, { backgroundColor: '#f3e8ff' }]}>
              <ShieldCheck size={32} color="#9333ea" />
            </View>
            <Text style={styles.cardTitle}>Admin / Technician / Faculty</Text>
            <Text style={styles.cardDesc}>Login to manage or resolve complaints</Text>
          </Pressable>
        </View>
      </View>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8fafc',
  },
  content: {
    flex: 1,
    padding: 24,
    justifyContent: 'center',
  },
  header: {
    marginBottom: 40,
    alignItems: 'center',
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#0f172a',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    color: '#64748b',
    textAlign: 'center',
  },
  cardsContainer: {
    gap: 20,
  },
  card: {
    backgroundColor: 'white',
    padding: 24,
    borderRadius: 16,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#e2e8f0',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 2,
  },
  cardPressed: {
    transform: [{ scale: 0.98 }],
    backgroundColor: '#f8fafc',
  },
  iconContainer: {
    width: 64,
    height: 64,
    borderRadius: 32,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 16,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#1e293b',
    marginBottom: 8,
  },
  cardDesc: {
    fontSize: 14,
    color: '#64748b',
    textAlign: 'center',
    lineHeight: 20,
  }
})

export default RoleSelection
