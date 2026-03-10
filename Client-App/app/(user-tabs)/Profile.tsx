import {
  View,
  Text,
  Pressable,
  Image,
  ActivityIndicator,
  ScrollView,
  TextInput,
} from 'react-native';
import { Shield, User, GraduationCap, BookUser } from 'lucide-react-native';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'expo-router';
import useAuth from '@/context/AuthContext';

import axios from 'axios';
import pickImage from '@/utils/Picker';
import Toast from 'react-native-toast-message';
import { UpdateUser } from '@/services/AuthService';
import { ipAddress } from '@/utils/IpAddress';

const Profile = () => {
  const { user, logout, loading } = useAuth();
  const router = useRouter();

  const [isEdit, setIsEdit] = useState(false);
  const [fullname, setFullName] = useState<string>('');
  const [email, setEmail] = useState<string>('');
  const [contact, setContact] = useState<string>('');
  const [image, setImage] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (user) {
      setFullName(user.full_name || '');
      setEmail(user.email || '');
      setContact(user.contact || '');
      setImage(user.profile_image || null);
    }
  }, [user]);

  const roleConfig: any = {
    admin: {
      color: '#ff3b30',
      label: 'ADMIN',
      icon: Shield,
    },
    student: {
      color: '#007AFF',
      label: 'STUDENT',
      icon: GraduationCap,
    },
    teacher: {
      color: '#34C759',
      label: 'TEACHER',
      icon: BookUser,
    },
    user: {
      color: '#5856D6',
      label: 'USER',
      icon: User,
    },
  };

  const role = user?.role || 'user';
  const roleStyle = roleConfig[role] || roleConfig.user;
  const RoleIcon = roleStyle.icon;
  // Logout
  const handleLogout = async () => {
    await logout();
    router.replace('/auth/Login');
  };

  // Pick Image
  const handlePickImage = async () => {
    const img = await pickImage();

    if (img) {
      setImage(img);
    }
  };

  // Update Profile
  const handleEdit = async () => {
    try {
      if (!fullname.trim()) {
        Toast.show({
          type: 'error',
          text1: 'Validation Error',
          text2: 'Full name cannot be empty',
        });
        return;
      }

      setSaving(true);

      const formData = new FormData();

      formData.append('full_name', fullname);
      formData.append('contact', contact);

      if (image && image.startsWith('file')) {
        formData.append('file', {
          uri: image,
          name: 'profile.jpg',
          type: 'image/jpeg',
        } as any);
      }

      const res = await UpdateUser(formData);

      if (res?.data?.success) {
        Toast.show({
          type: 'success',
          text1: 'Profile Updated',
          text2: 'Your profile was updated successfully',
        });

        setIsEdit(false);
      }
    } catch (error: any) {
      Toast.show({
        type: 'error',
        text1: 'Update Failed',
        text2: error?.response?.data?.message || 'Something went wrong',
      });
    } finally {
      setSaving(false);
    }
  };

  // Image URL logic
  const profile =
    image && image.startsWith('file')
      ? image
      : image
        ? `http://${ipAddress}:4500${image}`
        : 'https://cdn-icons-png.flaticon.com/512/149/149071.png';

  return (
    <ScrollView
      contentContainerStyle={{
        flexGrow: 1,
        alignItems: 'center',
        paddingTop: 70,
        backgroundColor: '#f5f5f5',
      }}
    >
      {/* Avatar */}
      <Pressable onPress={isEdit ? handlePickImage : undefined}>
        <Image
          source={{ uri: profile }}
          style={{
            width: 120,
            height: 120,
            borderRadius: 60,
            marginBottom: 15,
            borderWidth: 2,
            borderColor: '#ddd',
          }}
        />
      </Pressable>

      {/* Name */}
      <Text
        style={{
          fontSize: 24,
          fontWeight: 'bold',
        }}
      >
        {fullname}
      </Text>

      {/* Email */}
      <Text
        style={{
          fontSize: 15,
          color: '#666',
          marginBottom: 25,
        }}
      >
        {email}
      </Text>

      {/* Card */}
      <View
        style={{
          width: '90%',
          backgroundColor: 'white',
          borderRadius: 14,
          padding: 20,
          shadowColor: '#000',
          shadowOpacity: 0.1,
          shadowRadius: 8,
          elevation: 4,
        }}
      >
        {/* Full Name */}
        <View style={{ marginBottom: 18 }}>
          {isEdit ? (
            <TextInput
              placeholder="Full Name"
              value={fullname}
              onChangeText={setFullName}
              style={{
                borderWidth: 1,
                borderColor: '#ddd',
                borderRadius: 8,
                padding: 10,
                marginTop: 5,
              }}
            />
          ) : (
            <>
              <Text style={{ color: '#888', fontSize: 13 }}>FULL NAME</Text>

              <Text
                style={{
                  fontSize: 17,
                  fontWeight: '600',
                  marginTop: 4,
                }}
              >
                {fullname}
              </Text>
            </>
          )}
        </View>

        {/* Email */}
        <View style={{ marginBottom: 18 }}>
          <Text style={{ color: '#888', fontSize: 13 }}>EMAIL</Text>

          <Text
            style={{
              fontSize: 17,
              fontWeight: '600',
              marginTop: 4,
            }}
          >
            {email}
          </Text>
        </View>
        {/* Contact */}
        <View style={{ marginBottom: 18 }}>
          {isEdit ? (
            <>
              <TextInput
                placeholder="Contact"
                value={user?.contact || ''}
                onChangeText={setContact}
                style={{
                  borderWidth: 1,
                  borderColor: '#ddd',
                  borderRadius: 8,
                  padding: 10,
                  marginTop: 5,
                }}
              />
            </>
          ) : (
            <>
              <Text style={{ color: '#888', fontSize: 13 }}>CONTACT</Text>

              <Text
                style={{
                  fontSize: 17,
                  fontWeight: '600',
                  marginTop: 4,
                }}
              >
                {user?.contact || ''}
              </Text>
            </>
          )}
        </View>
        {/* Username */}
        <View style={{ marginBottom: 18 }}>
          <Text style={{ color: '#888', fontSize: 13 }}>USERNAME</Text>

          <Text
            style={{
              fontSize: 17,
              fontWeight: '600',
              marginTop: 4,
            }}
          >
            {user?.username}
          </Text>
        </View>

        {/* Role */}
        <View style={{ marginBottom: 18 }}>
          <Text style={{ color: '#888', fontSize: 13 }}>ROLE</Text>

          <View
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              marginTop: 6,
              backgroundColor: roleStyle.color + '20',
              paddingHorizontal: 10,
              paddingVertical: 6,
              borderRadius: 8,
              alignSelf: 'flex-start',
            }}
          >
            <RoleIcon size={18} color={roleStyle.color} />

            <Text
              style={{
                marginLeft: 6,
                fontWeight: '600',
                color: roleStyle.color,
              }}
            >
              {roleStyle.label}
            </Text>
          </View>
        </View>
      </View>

      {/* Buttons */}
      <View
        style={{
          flexDirection: 'row',
          marginTop: 35,
          gap: 15,
        }}
      >
        {/* Edit */}
        <Pressable
          style={{
            backgroundColor: '#007AFF',
            paddingVertical: 12,
            paddingHorizontal: 30,
            borderRadius: 10,
          }}
          onPress={() => {
            if (isEdit) {
              handleEdit();
            } else {
              setIsEdit(true);
            }
          }}
        >
          {saving ? (
            <ActivityIndicator color="white" />
          ) : (
            <Text style={{ color: 'white', fontWeight: 'bold' }}>
              {isEdit ? 'Save Profile' : 'Edit Profile'}
            </Text>
          )}
        </Pressable>

        {/* Logout */}
        <Pressable
          onPress={handleLogout}
          disabled={loading}
          style={{
            backgroundColor: '#ff3b30',
            paddingVertical: 12,
            paddingHorizontal: 30,
            borderRadius: 10,
          }}
        >
          {loading ? (
            <ActivityIndicator color="white" />
          ) : (
            <Text style={{ color: 'white', fontWeight: 'bold' }}>Logout</Text>
          )}
        </Pressable>
      </View>

      <Toast />
    </ScrollView>
  );
};

export default Profile;
