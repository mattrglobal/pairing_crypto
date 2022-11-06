import React from 'react';
import { ButtonProps, TouchableOpacity, Text, View, StyleSheet } from 'react-native';

/*
 * Need smaller button for fit all buttons in one screen without scroll
 */
export const Button: React.FC<ButtonProps> = (props) => {
  const { title, ...restProps } = props;
  const { buttonContainer, buttonText } = styles;
  return (
    <View style={buttonContainer}>
      <TouchableOpacity {...restProps}>
        <Text style={buttonText}>{title}</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  buttonContainer: {
    flexDirection: 'row',
    justifyContent: 'center',
  },
  buttonText: {
    fontSize: 16,
    color: '#007AFF',
  },
});
