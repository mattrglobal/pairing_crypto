/*
 * need smaller button for fit all buttons in one screen without scroll
 */
import * as React from 'react';
import {
  ButtonProps,
  TouchableOpacity,
  Text,
  View,
  TextStyle,
  StyleSheet,
  ViewStyle,
} from 'react-native';

export const MyButton: React.FC<ButtonProps> = (props) => {
  const { title, ...restProps } = props;
  const { buttonContainer, buttonText } = createButtonStyle();
  return (
    <View style={buttonContainer}>
      <TouchableOpacity {...restProps}>
        <Text style={buttonText}>{title}</Text>
      </TouchableOpacity>
    </View>
  );
};

type ButtonStyle = {
  readonly buttonContainer: ViewStyle;
  readonly buttonText: TextStyle;
};

const createButtonStyle = (): ButtonStyle => {
  return StyleSheet.create({
    buttonContainer: {
      flexDirection: 'row',
      justifyContent: 'center',
    },
    buttonText: {
      fontSize: 16,
      color: '#007AFF',
    },
  });
};
