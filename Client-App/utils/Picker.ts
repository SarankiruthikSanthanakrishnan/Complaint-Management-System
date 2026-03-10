import * as ImagePicker from 'expo-image-picker';
const pickImage = async () => {
  const permission = await ImagePicker.requestMediaLibraryPermissionsAsync();

  if (!permission.granted) {
    alert('Permission required to access gallery');
    return;
  }

  const result = await ImagePicker.launchImageLibraryAsync({
    mediaTypes: ImagePicker.MediaTypeOptions.Images,
    allowsEditing: true,
    aspect: [1, 1],
    quality: 1,
  });

  if (!result.canceled) {
    return result.assets[0].uri;
  }
};

export default pickImage;
