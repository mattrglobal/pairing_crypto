# React Native Wrapper

The following directory contains a native module implementation of the "pairing crypto" crate for usage in the React Native ecosystem.

## Using

### Installation

With [npm](https://www.npmjs.com/)

```sh
npm install @mattrglobal/pairing-crypto-rn
```

Or [yarn](https://yarnpkg.com/)

```sh
yarn add @mattrglobal/pairing-crypto-rn
```

## API

```js
import { bbs } from '@mattrglobal/pairing-crypto-rn';

const keyPair = await bbs.bls12381_sha256.generateKeyPair();
```

## Contributing

We use [Yarn](https://yarnpkg.com/) as the package manager for this library

To install the required dependencies run

```
yarn install --frozen-lockfile
yarn bootstrap
```

To build the library run

```
yarn build
```

To run the local app on iOS

```
yarn example ios
```

To run the local app on Android

```
yarn example android
```

To run the Detox E2E tests on iOS

```
yarn detox:build:ios
yarn detox:ios
```

To run the Detox E2E tests on Android

```
yarn detox:build:android
yarn detox:android
```

# Project setup

This project was scaffolded using [Bob](https://github.com/react-native-community/bob)
