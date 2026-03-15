import {
  View,
  Text,
  TextInput,
  Pressable,
  StyleSheet,
  Alert,
} from 'react-native';
import React, { useState } from 'react';
import Toast from 'react-native-toast-message';
import { ChangeUserPassword, UserLogout } from '@/services/AuthService';
import useAuth from '@/context/AuthContext';
import { useRouter } from 'expo-router';

const ChangePassword = () => {
  const { logout } = useAuth();
  const router = useRouter();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const handleChangePassword = async () => {
    try {
      if (!newPassword || !confirmPassword) {
        Toast.show({
          type: 'error',
          text1: 'Error',
          text2: 'Both password fields are required',
        });
        return;
      }

      if (newPassword.length < 6) {
        Toast.show({
          type: 'error',
          text1: 'Weak Password',
          text2: 'Password must be at least 6 characters',
        });
        return;
      }

      if (newPassword !== confirmPassword) {
        Toast.show({
          type: 'error',
          text1: 'Error',
          text2: 'Passwords do not match',
        });
        return;
      }

      const response = await ChangeUserPassword(newPassword, confirmPassword);

      if (response?.data?.success) {
        Toast.show({
          type: 'success',
          text1: 'Success',
          text2: 'Password changed successfully! Please login now.',
        });
        setConfirmPassword('');
        setNewPassword('');
        await logout();
        setTimeout(() => {
          router.replace('/auth/Login');
        }, 2000);
      }
    } catch (error: any) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: error?.response?.data?.message || 'Failed to change password',
      });
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Change Password</Text>

      <Text style={styles.label}>New Password</Text>
      <TextInput
        secureTextEntry
        placeholder="Enter the New Password"
        style={styles.input}
        value={newPassword}
        onChangeText={setNewPassword}
      />

      <Text style={styles.label}>Confirm Password</Text>
      <TextInput
        secureTextEntry
        placeholder="Enter the Confirm Password"
        style={styles.input}
        value={confirmPassword}
        onChangeText={setConfirmPassword}
      />

      <Pressable style={styles.button} onPress={handleChangePassword}>
        <Text style={styles.buttonText}>Update Password</Text>
      </Pressable>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#F5F5F7',
  },

  title: {
    fontSize: 22,
    fontWeight: 'bold',
    marginBottom: 20,
  },

  label: {
    fontSize: 16,
    marginBottom: 6,
    fontWeight: '500',
  },

  input: {
    backgroundColor: '#fff',
    padding: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#ddd',
    marginBottom: 16,
  },

  button: {
    backgroundColor: '#0066CC',
    padding: 14,
    borderRadius: 8,
    alignItems: 'center',
  },

  buttonText: {
    color: '#fff',
    fontWeight: 'bold',
    fontSize: 16,
  },
});

export default ChangePassword;
