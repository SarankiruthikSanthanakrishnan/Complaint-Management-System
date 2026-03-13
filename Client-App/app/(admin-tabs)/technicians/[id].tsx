import { View, Text } from 'react-native';
import React from 'react';

const TechnicianDetails = ({ route }: { route: any }) => {
  const { id } = route.params;

  return (
    <View>
      <Text>{id}</Text>
    </View>
  );
};

export default TechnicianDetails;
