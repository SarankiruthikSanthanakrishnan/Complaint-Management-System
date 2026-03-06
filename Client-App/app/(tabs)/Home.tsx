import { View, Text, Button } from 'react-native'
import React from 'react'
import { useAuth } from '../context/AuthContext'
import { useRouter } from 'expo-router';

const Home = () => {
  const {logout} = useAuth();
  const router = useRouter();
  return (
    <View style={{flex:1,justifyContent:'center',alignItems:'center'}}>
      <View>
          <Button title='LOGOUT' onPress={()=>{
            logout();
            router.push('/auth/login');
          }}/>
      </View>
    </View>
  )
}

export default Home
