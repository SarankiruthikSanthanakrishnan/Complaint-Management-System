import { View, Text, KeyboardAvoidingView, Platform, TextInput, Pressable, ActivityIndicator } from 'react-native'
import React, { useState } from 'react'
import { useRouter } from 'expo-router'
import Toast from "react-native-toast-message"
import { UserVerify } from '@/services/AuthService'


const VerifyRegno = () => {
  const router = useRouter()

  const [regNo, setRegNo] = useState("")
  const [loading, setLoading] = useState(false)

  const handleVerify = async () => {
    if(!regNo.trim()){
      Toast.show({
        type:"error",
        text1:"Error",
        text2:"Please enter your Registration Number"
      })
      return
    }

    try{
      setLoading(true)

      const response = await UserVerify(regNo);

      if (response?.data?.success || response?.status === 200) {
        Toast.show({
          type:"success",
          text1:"Verified successfully",
          text2:"Proceeding to registration"
        })

        // Passing the reg no to the register page
        router.push(`/auth/Register?regNo=${regNo}` as any)
      }

    } catch (err: any) {
      Toast.show({
        type: "error",
        text1: "Verification Failed",
        text2: err?.response?.data?.message || "Invalid Registration Number"
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === "ios" ? "padding" : "height"}
      style={{flex:1}}
    >
      <View style={{flex:1, justifyContent:'center', padding:20, backgroundColor: '#f8fafc'}}>
        <Text style={{fontSize:28,fontWeight:"bold",textAlign:'center',marginBottom:10, color: '#0f172a'}}>
          Verify Registration
        </Text>
        <Text style={{fontSize:16,textAlign:'center',marginBottom:30, color: '#64748b'}}>
          Please enter your university Registration Number to continue
        </Text>

        <TextInput
          placeholder="e.g. 732419104001"
          value={regNo}
          onChangeText={setRegNo}
          keyboardType='number-pad'
          autoCapitalize="characters"
          style={{
            borderWidth:1,
            borderColor:"#ccc",
            backgroundColor: "white",
            padding:14,
            borderRadius:8,
            marginBottom:20,
            fontSize: 16
          }}
        />

        <Pressable
          onPress={handleVerify}
          disabled={loading}
          style={{
            backgroundColor:'#0284c7',
            padding:16,
            borderRadius:8,
            alignItems:'center'
          }}
        >
          {loading
            ? <ActivityIndicator color="white"/>
            : <Text style={{color:"white", fontSize: 16, fontWeight: 'bold'}}>Verify & Continue</Text>
          }
        </Pressable>

        <Pressable
          onPress={() => router.back()}
          style={{
            padding:16,
            marginTop: 10,
            alignItems:'center'
          }}
        >
          <Text style={{color:"#64748b", fontSize: 16}}>Go Back</Text>
        </Pressable>
      </View>
    </KeyboardAvoidingView>
  )
}

export default VerifyRegno
