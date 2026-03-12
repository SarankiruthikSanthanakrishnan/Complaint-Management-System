import {
  View,
  Text,
  KeyboardAvoidingView,
  Platform,
  TextInput,
  Pressable,
  ActivityIndicator,
} from 'react-native';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'expo-router';
import Toast from 'react-native-toast-message';
import useAuth from '@/context/AuthContext';
import { ForgotPassword } from '@/services/AuthService';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { jwtDecode } from 'jwt-decode';

const Login = () => {
  const { login, isAuthenticated, user, error, loading } = useAuth();

  const router = useRouter();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isForgot, setIsForgot] = useState(false);
  const [sending, setSending] = useState(false);

  // Show login error
  useEffect(() => {
    if (error) {
      Toast.show({
        type: 'error',
        text1: 'Login Failed',
        text2: error,
      });
    }
  }, [error]);

  // Redirect based on role
  useEffect(() => {
    const checkRedirection = async () => {
      if (isAuthenticated && user) {
        Toast.show({
          type: 'success',
          text1: 'Login Successful',
        });

        try {
          const accessToken = await AsyncStorage.getItem('accessToken');
          if (accessToken) {
            const decoded: any = jwtDecode(accessToken);
            if (decoded?.must_change_password) {
              router.replace('/auth/ChangePassword');
              return;
            }
          }
        } catch (error) {
          console.error('Error decoding token:', error);
        }

        if (user.role === 'Student' || user.role === 'Faculty') {
          router.replace('/(user-tabs)/Home');
        } else if (user.role === 'Technician') {
          router.replace('/(technician-tabs)/Dashboard');
        } else if (user.role === 'Admin' || user.role === 'MasterAdmin') {
          router.replace('/(admin-tabs)/Dashboard');
        }
      }
    };

    checkRedirection();
  }, [isAuthenticated, user]);

  const handleLogin = async () => {
    if (!email || !password) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: 'All fields are required',
      });
      return;
    }

    await login(email, password);
  };

  const handleResetPassword = async () => {
    if (!email) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: 'Email is required',
      });
      return;
    }

    try {
      setSending(true);

      const response = await ForgotPassword(email);

      if (response?.data?.success) {
        Toast.show({
          type: 'success',
          text1: 'Reset Link Sent',
          text2: 'Check your email to reset password',
        });
        setIsForgot(false);
        setEmail('');
      }
    } catch (error: any) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: error?.response?.data?.message || 'Something went wrong',
      });
    } finally {
      setSending(false);
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
            marginBottom: 20,
          }}
        >
          {isForgot ? 'Reset Password' : 'Login'}
        </Text>

        <TextInput
          placeholder="Email"
          value={email}
          onChangeText={setEmail}
          style={{
            borderWidth: 1,
            borderColor: '#ccc',
            padding: 12,
            borderRadius: 8,
            marginBottom: 10,
          }}
        />

        {!isForgot && (
          <TextInput
            placeholder="Password"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            style={{
              borderWidth: 1,
              borderColor: '#ccc',
              padding: 12,
              borderRadius: 8,
              marginBottom: 20,
            }}
          />
        )}

        <Pressable
          onPress={() => setIsForgot(!isForgot)}
          style={{ marginBottom: 20 }}
        >
          <Text
            style={{
              color: '#0284c7',
              textAlign: 'right',
              textDecorationLine: 'underline',
            }}
          >
            {isForgot ? 'Back to Login' : 'Forgot Password ?'}
          </Text>
        </Pressable>

        <Pressable
          onPress={isForgot ? handleResetPassword : handleLogin}
          style={{
            backgroundColor: 'black',
            padding: 14,
            borderRadius: 8,
            alignItems: 'center',
          }}
        >
          {isForgot ? (
            sending ? (
              <ActivityIndicator color="white" />
            ) : (
              <Text style={{ color: 'white' }}>Send Reset Link</Text>
            )
          ) : loading ? (
            <ActivityIndicator color="white" />
          ) : (
            <Text style={{ color: 'white' }}>Sign In</Text>
          )}
        </Pressable>

        {!isForgot && (
          <View
            style={{
              flexDirection: 'row',
              justifyContent: 'center',
              marginTop: 25,
            }}
          >
            <Text style={{ color: '#64748b' }}>Don't have an account?</Text>

            <Pressable onPress={() => router.push('/auth/RoleSelection')}>
              <Text
                style={{
                  color: '#0284c7',
                  fontWeight: 'bold',
                }}
              >
                {' '}
                Register
              </Text>
            </Pressable>
          </View>
        )}
      </View>

      <Toast />
    </KeyboardAvoidingView>
  );
};

export default Login;
