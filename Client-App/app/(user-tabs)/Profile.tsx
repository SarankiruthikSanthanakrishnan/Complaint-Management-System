import { View, Text, Pressable, Image, ActivityIndicator, ScrollView } from 'react-native'
import React from 'react'

import { useRouter } from 'expo-router'
import useAuth from '@/context/AuthContext'

const Profile = () => {

  const { user, logout, loading } = useAuth()
  const router = useRouter()

  const handleLogout = async () => {
    await logout()
    router.replace('/auth/Login')
  }

  const avatar = user?.id
    ? `http://10.28.207.123:4500/uploads/${user.id}.jpg`
    : "https://i.pravatar.cc/150"

  return (

    <ScrollView
      contentContainerStyle={{
        flexGrow:1,
        alignItems:'center',
        paddingTop:70,
        backgroundColor:'#f5f5f5'
      }}
    >

      {/* Avatar */}
      <Image
        source={{ uri: avatar }}
        defaultSource={{ uri: "https://i.pravatar.cc/150" }}
        style={{
          width:120,
          height:120,
          borderRadius:60,
          marginBottom:15
        }}
      />

      {/* Name */}
      <Text style={{
        fontSize:24,
        fontWeight:'bold'
      }}>
        {user?.full_name}
      </Text>

      {/* Email */}
      <Text style={{
        fontSize:15,
        color:'#666',
        marginBottom:25
      }}>
        {user?.email}
      </Text>

      {/* Card */}
      <View style={{
        width:'90%',
        backgroundColor:'white',
        borderRadius:14,
        padding:20,
        shadowColor:'#000',
        shadowOpacity:0.1,
        shadowRadius:8,
        elevation:4
      }}>

        {/* Full Name */}
        <View style={{marginBottom:18}}>
          <Text style={{color:'#888',fontSize:13}}>
            FULL NAME
          </Text>

          <Text style={{
            fontSize:17,
            fontWeight:'600',
            marginTop:4
          }}>
            {user?.full_name}
          </Text>
        </View>

        {/* Email */}
        <View style={{marginBottom:18}}>
          <Text style={{color:'#888',fontSize:13}}>
            EMAIL
          </Text>

          <Text style={{
            fontSize:17,
            fontWeight:'600',
            marginTop:4
          }}>
            {user?.email}
          </Text>
        </View>

      </View>

      {/* Buttons */}
      <View style={{
        flexDirection:'row',
        marginTop:35,
        gap:15
      }}>

        {/* Edit */}
        <Pressable
          style={{
            backgroundColor:'#007AFF',
            paddingVertical:12,
            paddingHorizontal:30,
            borderRadius:10
          }}
        >
          <Text style={{color:'white',fontWeight:'bold'}}>
            Edit Profile
          </Text>
        </Pressable>

        {/* Logout */}
        <Pressable
          onPress={handleLogout}
          disabled={loading}
          style={{
            backgroundColor:'#ff3b30',
            paddingVertical:12,
            paddingHorizontal:30,
            borderRadius:10
          }}
        >

          {loading ? (
            <ActivityIndicator color="white" />
          ) : (
            <Text style={{color:'white',fontWeight:'bold'}}>
              Logout
            </Text>
          )}

        </Pressable>

      </View>

    </ScrollView>
  )
}

export default Profile
