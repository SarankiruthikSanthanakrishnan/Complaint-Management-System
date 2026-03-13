import * as DocumentPicker from 'expo-document-picker';

const pickFile = async () => {
  try {
    const file = await DocumentPicker.getDocumentAsync({
      type: '*/*',
    });
    return file;
  } catch (error) {
    console.error('Error picking file:', error);
  }
};

export default pickFile;
