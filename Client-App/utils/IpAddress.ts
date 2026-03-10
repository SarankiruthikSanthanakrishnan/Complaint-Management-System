import Constants from 'expo-constants';
import { Platform } from 'react-native';

let ipAddress: string;

if (Platform.OS === 'web') {
  ipAddress =
    typeof window !== 'undefined' ? window.location.hostname : 'localhost';
} else {
  const debuggerHost = Constants.expoConfig?.hostUri;
  ipAddress = debuggerHost?.split(':')[0] || 'localhost';
}

export { ipAddress };
