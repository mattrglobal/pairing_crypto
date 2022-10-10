import React from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  View,
} from 'react-native';

import { Colors } from 'react-native/Libraries/NewAppScreen';

import { MyButton } from './MyButton';
import { BbsBls12381Sha256GenerateKeyPair } from './pairing-crypto';
import { executeSignatureFixtures } from './fixtureRunner';

export default function App() {
  return (
    <>
      <StatusBar barStyle="dark-content" />
      <SafeAreaView>
        <ScrollView
          contentInsetAdjustmentBehavior="automatic"
          style={styles.scrollView}
        >
          <View testID="mainView" style={styles.body}>
            <View style={styles.sectionContainer}>
              <MyButton
                testID="BbsBls12381Sha256GenerateKeyPair"
                title={'Test generate key pair'}
                onPress={BbsBls12381Sha256GenerateKeyPair}
              />
            </View>
            <View style={styles.sectionContainer}>
              <MyButton
                testID="SignatureTestCases"
                title={'Run signature test cases'}
                onPress={executeSignatureFixtures}
              />
            </View>
          </View>
        </ScrollView>
      </SafeAreaView>
    </>
  );
}

const styles = StyleSheet.create({
  scrollView: {
    backgroundColor: Colors.lighter,
  },
  engine: {
    position: 'absolute',
    right: 0,
  },
  body: {
    backgroundColor: Colors.white,
  },
  sectionContainer: {
    marginTop: 32,
    paddingHorizontal: 24,
  },
  sectionTitle: {
    fontSize: 24,
    fontWeight: '600',
    color: Colors.black,
  },
  sectionDescription: {
    marginTop: 8,
    fontSize: 18,
    fontWeight: '400',
    color: Colors.dark,
  },
  highlight: {
    fontWeight: '700',
  },
  footer: {
    color: Colors.dark,
    fontSize: 12,
    fontWeight: '600',
    padding: 4,
    paddingRight: 12,
    textAlign: 'right',
  },
});
