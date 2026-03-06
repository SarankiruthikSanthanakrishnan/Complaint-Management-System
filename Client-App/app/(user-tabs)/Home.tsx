import { View, Text, Button } from 'react-native'
import React from 'react'
import { useRouter } from 'expo-router';
import useAuth from '@/context/AuthContext';

const Home = () => {
  const {logout, loading} = useAuth();
  const router = useRouter();
  return (
    <View style={{flex:1,justifyContent:'center',alignItems:'center'}}>
      <View>
          <Button title={loading?"Logging out":"Logout"}onPress={async()=>{
            await logout();
            router.replace('/auth/Login');
          }}/>
      </View>
    </View>
  )
}

export default Home
