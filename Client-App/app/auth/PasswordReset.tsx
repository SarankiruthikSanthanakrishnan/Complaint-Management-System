import {
  View,
  Text,
  TextInput,
  Pressable,
  KeyboardAvoidingView,
  Platform,
  ActivityIndicator,
} from 'react-native';

import React, { useState } from 'react';
import Toast from 'react-native-toast-message';
import { useRouter, useLocalSearchParams } from 'expo-router';
import { ResetPassword } from '@/services/AuthService';

const PasswordReset = () => {
  const router = useRouter();

  const { token } = useLocalSearchParams();

  const [password, setPassword] = useState('');
  const [confirmpassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleResetPassword = async () => {
    if (!password || !confirmpassword) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: 'All fields are required',
      });

      return;
    }

    if (password !== confirmpassword) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: 'Passwords do not match',
      });

      return;
    }

    try {
      setLoading(true);

      const response = await ResetPassword(
        token as string,
        password,
        confirmpassword
      );

      if (response?.data?.success) {
        Toast.show({
          type: 'success',
          text1: 'Password Updated',
          text2: 'You can now login with new password',
        });

        setTimeout(() => {
          router.replace('/auth/Login');
        }, 1500);
      }
    } catch (error: any) {
      console.log(error.response.data.message);
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: error?.response?.data?.message || 'Something went wrong',
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      style={{ flex: 1 }}
    >
      <View style={{ flex: 1, justifyContent: 'center', padding: 20 }}>
        <Text
          style={{
            fontSize: 28,
            fontWeight: 'bold',
            textAlign: 'center',
            marginBottom: 25,
          }}
        >
          Reset Password
        </Text>

        <TextInput
          placeholder="New Password"
          secureTextEntry
          value={password}
          onChangeText={setPassword}
          style={{
            borderWidth: 1,
            borderColor: '#ccc',
            padding: 12,
            borderRadius: 8,
            marginBottom: 10,
          }}
        />

        <TextInput
          placeholder="Confirm Password"
          secureTextEntry
          value={confirmpassword}
          onChangeText={setConfirmPassword}
          style={{
            borderWidth: 1,
            borderColor: '#ccc',
            padding: 12,
            borderRadius: 8,
            marginBottom: 20,
          }}
        />

        <Pressable
          onPress={handleResetPassword}
          style={{
            backgroundColor: 'black',
            padding: 14,
            borderRadius: 8,
            alignItems: 'center',
          }}
        >
          {loading ? (
            <ActivityIndicator color="white" />
          ) : (
            <Text style={{ color: 'white' }}>Update Password</Text>
          )}
        </Pressable>
      </View>

      <Toast />
    </KeyboardAvoidingView>
  );
};

export default PasswordReset;
