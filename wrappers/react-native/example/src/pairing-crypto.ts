import { Alert, AlertButton } from 'react-native';
import { bbs } from '@mattrglobal/pairing-crypto-rn';

enum AlertType {
  SuccessAlert = 0,
  ErrorAlert = 1,
}

const getAlertTypeMessage = (
  alertType: AlertType
): AlertButton[] | undefined => {
  if (alertType == AlertType.SuccessAlert) {
    return [{ text: 'OK', onPress: (): void => console.log('OK Pressed') }];
  }

  if (alertType == AlertType.ErrorAlert) {
    return [
      { text: 'Close', onPress: (): void => console.log('Close Pressed') },
    ];
  }

  return undefined;
};

const raiseAlert = (
  alertType: AlertType,
  displayString: string,
  result?: unknown
): void => {
  Alert.alert(
    displayString,
    result ? JSON.stringify(result) : undefined,
    getAlertTypeMessage(alertType),

    { cancelable: false }
  );
};

export const BbsBls12381Sha256GenerateKeyPair = async (): Promise<void> => {
  try {
    const keyPair = await bbs.bls12381_sha256.generateKeyPair();
    console.log(JSON.stringify(keyPair, null, 2));
    if (!keyPair) {
      throw 'bbs.bls12381_sha256.generateKeyPair Failed';
    }
    raiseAlert(AlertType.SuccessAlert, 'Generated key pair');
  } catch (err) {
    console.log('Error:', err);
    raiseAlert(AlertType.ErrorAlert, 'Error: ', err);
  }
};
