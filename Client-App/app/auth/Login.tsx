import { View, Text, KeyboardAvoidingView, Platform, TextInput, Pressable, ActivityIndicator } from 'react-native'
import React, { useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import { Redirect, useRouter } from 'expo-router'

const Login = () => {

  const { login,isAuthenticated} = useAuth()
  const router = useRouter();

  const [email,setEmail] = useState("")
  const [password,setPassword] = useState("")
  const [error,setError] = useState("")
  const [loading,setLoading] = useState(false)

  useEffect(()=>{
    if(isAuthenticated){
    router.push('/(tabs)/Home')
    }
  },[isAuthenticated])

  const handleLogin = async () => {



    if(!email || !password){
      setError("Please enter email and password")
      return
    }

    try{

      setLoading(true)
      setError("")

      await login(email,password);




    }catch(err){
      setError("Login failed")
    }
    finally{
      setLoading(false)
    }

  }

  return (

    <KeyboardAvoidingView
      behavior={Platform.OS === "ios" ? "padding" : "height"}
      style={{flex:1}}
    >

      <View style={{flex:1, justifyContent:'center', padding:20}}>

        <Text style={{fontSize:28,fontWeight:"bold",textAlign:'center',marginBottom:20}}>
          Login
        </Text>

        {error ? (
          <Text style={{color:"red",marginBottom:10}}>
            {error}
          </Text>
        ) : null}

        <TextInput
          placeholder="Email"
          value={email}
          onChangeText={setEmail}
          style={{
            borderWidth:1,
            borderColor:"#ccc",
            padding:12,
            borderRadius:8,
            marginBottom:10
          }}
        />

        <TextInput
          placeholder="Password"
          value={password}
          onChangeText={setPassword}
          secureTextEntry
          style={{
            borderWidth:1,
            borderColor:"#ccc",
            padding:12,
            borderRadius:8,
            marginBottom:20
          }}
        />

        <Pressable
          onPress={handleLogin}
          style={{
            backgroundColor:'black',
            padding:14,
            borderRadius:8,
            alignItems:'center'
          }}
        >

          {loading
            ? <ActivityIndicator color="white"/>
            : <Text style={{color:"white"}}>Sign In</Text>
          }

        </Pressable>

      </View>

    </KeyboardAvoidingView>

  )
}

export default Login
