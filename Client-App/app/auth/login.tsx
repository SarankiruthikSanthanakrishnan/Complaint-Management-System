import { View, Text, KeyboardAvoidingView, Platform, TextInput, Pressable } from 'react-native'
import React, { useState } from 'react'


const login = () => {
    const [email,setEmail] = useState("");
    const [password,setPassword] = useState("");
    const [error,setError] = useState("");
    const [loading,setLoading] = useState(false);
  return (
    <>
    <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : 'height'} style={{flex:1}}>
        <View style={{flex:1, justifyContent:'center', alignItems:'center'}}>
            <Text>Login</Text>
            <TextInput placeholder="Email" />
            <TextInput placeholder="Password" />
            <Pressable style={{backgroundColor:'black', padding:10, borderRadius:5}}><Text>{loading ? "Signing In..." : "Sign In"}</Text></Pressable>
        </View>
    </KeyboardAvoidingView>
    </>
  )
}

export default login
