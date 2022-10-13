import React from 'react';
import { ScrollView, StatusBar, StyleSheet, Text, View } from 'react-native';

import { Colors } from 'react-native/Libraries/NewAppScreen';

import { Button } from './Button';
import { TestReportView } from './TestReport';
import { TestSignature, useTestSignatureControl } from './TestSignature';
import { TestWrapper } from './TestWrapper';
import {
  BbsBls12381Sha256GenerateKeyPair,
  BbsBls12381Shake256GenerateKeyPair,
  BbsBls12381Sha256ProofGen,
  BbsBls12381Shake256ProofGen,
  BbsBls12381Sha256Verify,
  BbsBls12381Shake256Verify,
  BbsBls12381Sha256ProofVerify,
  BbsBls12381Shake256ProofVerify,
} from './pairing-crypto';
import { fixtures } from '../__fixtures__';

export default function App() {
  const signatureTestControl = useTestSignatureControl();
  const proofGenTestControl = useTestSignatureControl();

  return (
    <>
      <StatusBar barStyle="dark-content" />
      <TestReportView>
        <ScrollView testID="mainScrollView" contentInsetAdjustmentBehavior="automatic" style={styles.scrollView}>
          <View testID="mainView" style={styles.body}>
            <View style={styles.sectionContainer}>
              <TestWrapper
                testID="BbsBls12381Sha256GenerateKeyPair"
                title={'Generate bls12381_sha256 key pair'}
                verify={BbsBls12381Sha256GenerateKeyPair}
              />
            </View>
            <View style={styles.sectionContainer}>
              <TestWrapper
                testID="BbsBls12381Shake256GenerateKeyPair"
                title={'Generate bls12381_shake256 key pair'}
                verify={BbsBls12381Shake256GenerateKeyPair}
              />
            </View>

            <View style={styles.sectionContainer}>
              <Button
                testID="SignatureTestCases"
                title={'Run all signature test cases'}
                onPress={signatureTestControl.verifyAll}
              />

              <Text style={styles.sectionSubtitle}>{'BbsBls12381Sha256 Signature Test Cases'}</Text>
              {Object.values(fixtures.bls12381Sha256Signature).map((fixture) => (
                <TestSignature
                  testID={`${fixture.source}-SignatureVerify`}
                  ref={signatureTestControl.register(fixture)}
                  key={fixture.source}
                  fixture={fixture}
                  verify={() => BbsBls12381Sha256Verify(fixture)}
                />
              ))}

              <Text style={styles.sectionSubtitle}>{'BbsBls12381Shake256 Signature Test Cases'}</Text>
              {Object.values(fixtures.bls12381Shake256Signature).map((fixture) => (
                <TestSignature
                  testID={`${fixture.source}-SignatureVerify`}
                  ref={signatureTestControl.register(fixture)}
                  key={fixture.source}
                  fixture={fixture}
                  verify={() => BbsBls12381Shake256Verify(fixture)}
                />
              ))}

              <Text style={styles.sectionSubtitle}>{'BbsBls12381Sha256 Proof Test Cases'}</Text>
              {Object.values(fixtures.bls12381Sha256Proof).map((fixture) => (
                <TestSignature
                  testID={`${fixture.source}-ProofVerify`}
                  ref={signatureTestControl.register(fixture)}
                  key={fixture.source}
                  fixture={fixture}
                  verify={() => BbsBls12381Sha256ProofVerify(fixture)}
                />
              ))}

              <Text style={styles.sectionSubtitle}>{'BbsBls12381Shake256 Proof Test Cases'}</Text>
              {Object.values(fixtures.bls12381Shake256Proof).map((fixture) => (
                <TestSignature
                  testID={`${fixture.source}-ProofVerify`}
                  ref={signatureTestControl.register(fixture)}
                  key={fixture.source}
                  fixture={fixture}
                  verify={() => BbsBls12381Shake256ProofVerify(fixture)}
                />
              ))}
            </View>

            <View style={styles.sectionContainer}>
              <Button
                testID="SignatureTestCases"
                title={'Run all proofGen test cases'}
                onPress={proofGenTestControl.verifyAll}
              />

              <Text style={styles.sectionSubtitle}>{'BbsBls12381Sha256 ProofGen Test Cases'}</Text>
              {Object.values(fixtures.bls12381Sha256ProofValidCases).map((fixture) => (
                <TestSignature
                  testID={`${fixture.source}-ProofGen`}
                  ref={proofGenTestControl.register(fixture)}
                  key={fixture.source}
                  fixture={fixture}
                  verify={() => BbsBls12381Sha256ProofGen(fixture)}
                />
              ))}

              <Text style={styles.sectionSubtitle}>{'BbsBls12381Shake256 ProofGen Test Cases'}</Text>
              {Object.values(fixtures.bls12381Shake256ProofValidCases).map((fixture) => (
                <TestSignature
                  testID={`${fixture.source}-ProofGen`}
                  ref={proofGenTestControl.register(fixture)}
                  key={fixture.source}
                  fixture={fixture}
                  verify={() => BbsBls12381Shake256ProofGen(fixture)}
                />
              ))}
            </View>
          </View>
        </ScrollView>
      </TestReportView>
    </>
  );
}

const styles = StyleSheet.create({
  scrollView: {
    backgroundColor: Colors.white,
    minHeight: '100%',
  },
  body: {
    backgroundColor: Colors.white,
    minHeight: '100%',
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
  sectionSubtitle: {
    fontSize: 16,
    fontWeight: '400',
    textAlign: 'center',
    color: Colors.black,
    marginVertical: 16,
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
