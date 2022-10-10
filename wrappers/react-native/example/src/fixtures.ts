export const fixtures = {
  keyPair: {
    ikm: '746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579',
    keyInfo:
      '746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e',
    publicKey:
      'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
    secretKey:
      '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
  },
  bls12381Sha256SignatureFixtures: [
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/signature/signature001.json',
      value: {
        caseName: 'single message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
        ],
        signature:
          '88d67d43de012792f014c03e181ecc8997c432f6cd33aef424408c350ddb6e5b31395775784bbdbd8b00cb12d4f33feb0fd0d12df6996055e1435c1042f199b0c29ba0c4535c45d07737e9f1866ed64c382f46493d7386b57ff521782bb68bd5080b6d8e8f91b26e7bdb66c039176c0a',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/signature/signature002.json',
      value: {
        caseName: 'single message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        ],
        signature:
          '88d67d43de012792f014c03e181ecc8997c432f6cd33aef424408c350ddb6e5b31395775784bbdbd8b00cb12d4f33feb0fd0d12df6996055e1435c1042f199b0c29ba0c4535c45d07737e9f1866ed64c382f46493d7386b57ff521782bb68bd5080b6d8e8f91b26e7bdb66c039176c0a',
        result: {
          valid: false,
          reason: 'modified message',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/signature/signature003.json',
      value: {
        caseName: 'single message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
        ],
        signature:
          '88d67d43de012792f014c03e181ecc8997c432f6cd33aef424408c350ddb6e5b31395775784bbdbd8b00cb12d4f33feb0fd0d12df6996055e1435c1042f199b0c29ba0c4535c45d07737e9f1866ed64c382f46493d7386b57ff521782bb68bd5080b6d8e8f91b26e7bdb66c039176c0a',
        result: {
          valid: false,
          reason: 'extra unsigned message',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/signature/signature004.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        ],
        signature:
          '802c45364dd52022e8d02d5ff64f8b338454528e3907ccb7cdfbd74df6a74809043019b52a629613a0430c3d55ce6b7e4244d16e06b4b6b3287cc9ac2009a60d18f4227109184d6a53848c5421e8e852065cb725e9de623c848deb74811e46485e445b838d98b0b3072a644b844e9966',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/signature/signature005.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
        ],
        signature:
          '802c45364dd52022e8d02d5ff64f8b338454528e3907ccb7cdfbd74df6a74809043019b52a629613a0430c3d55ce6b7e4244d16e06b4b6b3287cc9ac2009a60d18f4227109184d6a53848c5421e8e852065cb725e9de623c848deb74811e46485e445b838d98b0b3072a644b844e9966',
        result: {
          valid: false,
          reason: 'missing messages',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/signature/signature006.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
        ],
        signature:
          '802c45364dd52022e8d02d5ff64f8b338454528e3907ccb7cdfbd74df6a74809043019b52a629613a0430c3d55ce6b7e4244d16e06b4b6b3287cc9ac2009a60d18f4227109184d6a53848c5421e8e852065cb725e9de623c848deb74811e46485e445b838d98b0b3072a644b844e9966',
        result: {
          valid: false,
          reason: 're-ordered messages',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/signature/signature007.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'a91de0aa76950a710fd45ae66c08b221a8b7b6e01d7c6e5284dc013b10f7ac5ee6ccec6b9f18dc4f4e9d62a75906434e084d1261beb1670be46965d4e3f4c3bce9aff1bf9c121a2ba62bdc9fc1420cf0b79948d7b5da19e689a120fc9f0cfabf',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        ],
        signature:
          '802c45364dd52022e8d02d5ff64f8b338454528e3907ccb7cdfbd74df6a74809043019b52a629613a0430c3d55ce6b7e4244d16e06b4b6b3287cc9ac2009a60d18f4227109184d6a53848c5421e8e852065cb725e9de623c848deb74811e46485e445b838d98b0b3072a644b844e9966',
        result: {
          valid: false,
          reason: 'wrong public key',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/signature/signature008.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: 'ffeeddccbbaa00998877665544332211',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        ],
        signature:
          '802c45364dd52022e8d02d5ff64f8b338454528e3907ccb7cdfbd74df6a74809043019b52a629613a0430c3d55ce6b7e4244d16e06b4b6b3287cc9ac2009a60d18f4227109184d6a53848c5421e8e852065cb725e9de623c848deb74811e46485e445b838d98b0b3072a644b844e9966',
        result: {
          valid: false,
          reason: 'different header',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/signature/signature009.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
        ],
        signature:
          '802c45364dd52022e8d02d5ff64f8b338454528e3907ccb7cdfbd74df6a74809043019b52a629613a0430c3d55ce6b7e4244d16e06b4b6b3287cc9ac2009a60d18f4227109184d6a53848c5421e8e852065cb725e9de623c848deb74811e46485e445b838d98b0b3072a644b844e9966',
        result: {
          valid: false,
          reason: 're-ordered(randomly shuffled) messages',
        },
      },
    },
  ],
  bls12381Shake256SignatureFixtures: [
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/signature/signature001.json',
      value: {
        caseName: 'single message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
        ],
        signature:
          '92629222b6bb5de18a273b7d7877292b393f770b0a4f0784963927c2cee962718a333d7b2f32993b717d83588b2141241bd3cda3e5e449e364bde83fe8d3551433de2e5385a93cde0dce16a0debffe3e44eea213eaf758035043a226520694d9f90651b3e4533b68b3fd4481dc4b58af',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/signature/signature002.json',
      value: {
        caseName: 'single message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        ],
        signature:
          '92629222b6bb5de18a273b7d7877292b393f770b0a4f0784963927c2cee962718a333d7b2f32993b717d83588b2141241bd3cda3e5e449e364bde83fe8d3551433de2e5385a93cde0dce16a0debffe3e44eea213eaf758035043a226520694d9f90651b3e4533b68b3fd4481dc4b58af',
        result: {
          valid: false,
          reason: 'modified message',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/signature/signature003.json',
      value: {
        caseName: 'single message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
        ],
        signature:
          '92629222b6bb5de18a273b7d7877292b393f770b0a4f0784963927c2cee962718a333d7b2f32993b717d83588b2141241bd3cda3e5e449e364bde83fe8d3551433de2e5385a93cde0dce16a0debffe3e44eea213eaf758035043a226520694d9f90651b3e4533b68b3fd4481dc4b58af',
        result: {
          valid: false,
          reason: 'extra unsigned message',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/signature/signature004.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        ],
        signature:
          'ae9c7afa3996cc5bb570a3925c0c560014bc374f5352a6f4ce9ad00ad6d7067a42d99d60d17764faecdfa4264a96049e4a32ea6f2fa5f475844ea0fffebda403a52b29a2961fa677da760e3f43b49cb602cf56ab8a5186c43efdbdbb273c34e2e3a00e94812801353143e27baf957693',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/signature/signature005.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
        ],
        signature:
          'ae9c7afa3996cc5bb570a3925c0c560014bc374f5352a6f4ce9ad00ad6d7067a42d99d60d17764faecdfa4264a96049e4a32ea6f2fa5f475844ea0fffebda403a52b29a2961fa677da760e3f43b49cb602cf56ab8a5186c43efdbdbb273c34e2e3a00e94812801353143e27baf957693',
        result: {
          valid: false,
          reason: 'missing messages',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/signature/signature006.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
        ],
        signature:
          'ae9c7afa3996cc5bb570a3925c0c560014bc374f5352a6f4ce9ad00ad6d7067a42d99d60d17764faecdfa4264a96049e4a32ea6f2fa5f475844ea0fffebda403a52b29a2961fa677da760e3f43b49cb602cf56ab8a5186c43efdbdbb273c34e2e3a00e94812801353143e27baf957693',
        result: {
          valid: false,
          reason: 're-ordered messages',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/signature/signature007.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'a91de0aa76950a710fd45ae66c08b221a8b7b6e01d7c6e5284dc013b10f7ac5ee6ccec6b9f18dc4f4e9d62a75906434e084d1261beb1670be46965d4e3f4c3bce9aff1bf9c121a2ba62bdc9fc1420cf0b79948d7b5da19e689a120fc9f0cfabf',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        ],
        signature:
          'ae9c7afa3996cc5bb570a3925c0c560014bc374f5352a6f4ce9ad00ad6d7067a42d99d60d17764faecdfa4264a96049e4a32ea6f2fa5f475844ea0fffebda403a52b29a2961fa677da760e3f43b49cb602cf56ab8a5186c43efdbdbb273c34e2e3a00e94812801353143e27baf957693',
        result: {
          valid: false,
          reason: 'wrong public key',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/signature/signature008.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: 'ffeeddccbbaa00998877665544332211',
        messages: [
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        ],
        signature:
          'ae9c7afa3996cc5bb570a3925c0c560014bc374f5352a6f4ce9ad00ad6d7067a42d99d60d17764faecdfa4264a96049e4a32ea6f2fa5f475844ea0fffebda403a52b29a2961fa677da760e3f43b49cb602cf56ab8a5186c43efdbdbb273c34e2e3a00e94812801353143e27baf957693',
        result: {
          valid: false,
          reason: 'different header',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/signature/signature009.json',
      value: {
        caseName: 'multi-message signature',
        signerKeyPair: {
          secretKey:
            '47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56',
          publicKey:
            'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        },
        header: '11223344556677889900aabbccddeeff',
        messages: [
          'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
          'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
        ],
        signature:
          'ae9c7afa3996cc5bb570a3925c0c560014bc374f5352a6f4ce9ad00ad6d7067a42d99d60d17764faecdfa4264a96049e4a32ea6f2fa5f475844ea0fffebda403a52b29a2961fa677da760e3f43b49cb602cf56ab8a5186c43efdbdbb273c34e2e3a00e94812801353143e27baf957693',
        result: {
          valid: false,
          reason: 're-ordered(randomly shuffled) messages',
        },
      },
    },
  ],
  bls12381Sha256ProofFixtures: [
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof001.json',
      value: {
        caseName: 'single message signature, message revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
        },
        totalMessageCount: 1,
        proof:
          'a9139cc3b4e917398ea070b2f9cda8fef663847d18730ed1ac780b441649ceef05f592afd88d984c9edc152bdbe0f3148bf36b73524bf65d093723558b081d83b7e220403fac5c4d74246f0a2b27c65688e7b1b8fafaf9bcc55bc222b94bdf9ba4826e773434769836dab5ede0b6d52d991e858d5244c04ced92e61a3f2348c31574071523915c860f4df5aba950e7fb280b4346b90ec5c9373ae9c9d87d1fd1a3039bb3a63127b9af28ddabbaff58e607a3d6715b108c3a17d94b56b5cbfd70b5389535598d7767ee568fea4916721f5f061d9feb82cec4704d86fceaef6f28ca92117a2645d47c20dd5dbe400659224c56ba3de9030176c91c272af643578b61ef03b8e0d98e73e7eac33a8cc3bc4c06657a3a0ad1d26da96918edaa6db9164151d56c5450cb409384b0b37d001aca',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof002.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '1': '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '3': 'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '5': '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '7': '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '8': '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          '9': 'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        },
        totalMessageCount: 10,
        proof:
          'b060c2d0bce458e1258869767c6255fb55220cc2a39300671c5ba452b4a2a8bdb46d38766c69be8dceb0bb0ee8c0ed9e86152a78e987b4bb7fcc9e84dfe40187cde6e4b6601c0b3e389df95d56132097ebdde7f7999bee052cd5858e831c219fa34fcb9c56b7cd3e10c1ea65a5a79569ff214144dc2c9f8d0a2251ea4a4e496be64f69ccc95b707b5c63d60529f857f80e3cd064278eb1a20c6b701f36723ff35b9e10ca0ec295fea9cc00c5053deb6339f0e36a737520e64817f7c800c949f8c93bcfac8226277dbe45d1da7296ecfd2a38ccbb5d915e572cfd099b1c8659be0c7f7b860b054c0b61517c82e58ac472069f98aff85d306498fc7f76dd91324c84751cf485b893bc8a5daf97b088a93831527168890f57643acda65f04b1ef17e8998dccd21a2345934f7137ba825477',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof003.json',
      value: {
        caseName: 'multi-message signature, multiple messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          '93bdb4a1e535be7f8a6355e7c510d585e95439f976d09f4fdec297a6907d6082f3a299c1a8616fcea59d71ed634c6d018fb53e55bc3befd835f87ca0f603eae3796b63c613b74c39877bbbf673310bc9c17c2669892c9c8a3a8c1a4dd221206488dbdfe3e9d24999ee4bb77e9907559007b614fc3c2fa20aaf5aec66ba29859803796a820bdf802c6099888769e0aa3d2ce5b0f50fca8d87878b036e2184552620f6c038a262908e66ea589f3f8c0a84540329ebb1920d1296a0837e2740eb81e7252d48392da1b1ff26a58fa2d3c15b0c3d44b21278c43c3a71596f3ee805cfa9ab3e0d2c40cd5eb3246d125ef030a524c30b478a196cb85a6422cee5f278871fbc35d6d7d98f6bb96dbd70ec4490f32f155f122816f61397ec1c366a5b1f68269c6416a9fc2107879d325c675bfe78001988de8368a15506467fb60553fdcf4c0478ae06f08481bdf77da6c193557d203c2dad8bf2e5ed248a735fa7e7bd7f87f391282788e5236a6c04b2296ad5011f8f06f3069fc7cafb30a3a995aaf1e0315009874facc7d1f0d123307d5e0b602f491dcd335bfbd90c1a4a681a4c8faf231619f8fd15a1354fedc1ce29cb627a151cc3b8a015c8d1b62fee1331067ddfa01013779a1b697ff126d2e8a1e825645c9b3f1052b0b8abaed5880d00b27dcf64896cacef701774d48ca105d0fb58f7',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof004.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          '011594ba7f95b3b470ea4102dd5899de3a042e5104d3ea01d15e6780d831d2be',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 'different presentation header',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof005.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'a91de0aa76950a710fd45ae66c08b221a8b7b6e01d7c6e5284dc013b10f7ac5ee6ccec6b9f18dc4f4e9d62a75906434e084d1261beb1670be46965d4e3f4c3bce9aff1bf9c121a2ba62bdc9fc1420cf0b79948d7b5da19e689a120fc9f0cfabf',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 'wrong public key',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof006.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '7fb7129b7177837d5e373b9b8b685d91d819d64f9c4a21323644798d40daea4ef5533584380377e992b5f08a8efeb4914b2da286e94223fd50c635fed44ee1b58ab4efdc91ee546348d1225e4c73ab15eb6a1e7aefc3c657a07edcab666a19d1be5bd0b9',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 'modified messages',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof007.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '9': 'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        },
        totalMessageCount: 10,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 'extra message un-revealed in proof',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof008.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '9': '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
        },
        totalMessageCount: 10,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 'extra message invalid message un-revealed in proof',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof009.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 'missing message revealed in proof',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof010.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
        },
        totalMessageCount: 10,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 're-ordered messages',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof011.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '9': 'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        },
        totalMessageCount: 11,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 'extra valid message, modified total message count',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof012.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 9,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 'modified total message count less than actual',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_sha_256/proof/proof013.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: 'ffeeddccbbaa00998877665544332211',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          'b8aaea8ee50007e6ef0f81024154306dcd00e3360a01aaad0c6ed25f59ea365dc153dac1736462316669567a4c304cceb06284a6ed10c8823464d9478cf17e2fa0ae164d7ffed8cdf2d9b673f3fe5d96991ccc19e05505751d15d10a4832eb7a89adc3d62e1ec8817acc5881ad5f3afb2c2a8d08f195c049d25fb70884e17a598f67c0a36cc0e52f60c0d69ab75845dd185b0d7ac3ef9d52cbd4b84023934e022379902d9f1d430f3d55660a4e3ddaa329fdc46e8f1df49a3731f614e03c7886f821e852668cbb7ee5f9214487c990f3144e2a19be680b8d7133c547b0ca04e3f69549892c95f75a1a1406fe6e0d03ee5d580b2ebdb1d94d8afb18cdd9992a931251c10d16f40db9373882bf897ed9a34892c8ba16afb86d26c64feb26dfda89c1c1716690acc2c87c2c4c48a6df8da55e31ba6f22018561235dc4d475b0bedbbf1854a1d7d19a82eb354af42172126a43c6c8f67b4046933f63aa370fd7219998413e4d7b6030ead96380d40d05303c6ed0eae708a73fc82ea31115b78a66ae32508448f743024422af87e592c4c6d5097666528b1ffc16bb627551a391d74f4d380256a9bc23b683ee926b303689ad2a3e1cb84b90668d9422aac8ea30c537784ea1cbd31f80f90d5718badf89b8b161ce313378f1354a36c50650f7db821d7be1a2353f5515966b318de0aa82f6da',
        result: {
          valid: false,
          reason: 'different header',
        },
      },
    },
  ],
  bls12381Shake256ProofFixtures: [
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof001.json',
      value: {
        caseName: 'single message signature, message revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
        },
        totalMessageCount: 1,
        proof:
          '869c402ce5f88da72561381971cda4993d7b69ff5d3ea7d8bb6250be1b2158441bf14fb93b01d1eb18b361a57330a6a58bee712bf517a5a4380701b92b56645d811c7190e6ff8b28c8bde5187404b7bafb3473d9466329e670bb8418ee1c858a8bd75defab2f3204fb5c258e506dc4de663668b9b33b6af949cd6dde446fa39ec41a07f91010ba98f6a3b35a0655d2e52f81f9b24c9ca3952bee147e0d3513759f6274df8f9cf211ea4e83a43fc847586c0260f351875f99863532fc9f246308f3c0d560d3dc24ba45039d4a962b3d3f5d0121bbd6c70304f8b15d8e1ff6df1b60e8b64003d2d828e9f6efbc1bbba4164f0e720cd79ca890f4c6c49f747e5daa8b2fba4fcf04c758eb2db0c84efd980671333602e6528b389cba66e37d97bacdcdf6d29777bfdcfa04373e1e49abbaed',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof002.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '1': '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '3': 'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '5': '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '7': '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
          '8': '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
          '9': 'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        },
        totalMessageCount: 10,
        proof:
          '8b8a51ba76d3b5453d6749989e40fbce8fcd908a70f937b7251b2cdf20ea94d521f28746cf1112dbd3945ffc6ec8b5658e03e0ff4d89383aab81272b130e72ff7febe1b997554b785fc6717e2bb6d39e58dcc6fbd255bb8e54e1a8b08b8f01cfb16943c24dca18789318cf9449daf8cbf2db0a4841bbd698719d4019f91d3432ed1728377bc6fc9917ca95712408179a44bedc143cd9ea6cd4c52a71a3f9ef1c29b2dda1fab4ff78abd644d2e7fa12355d226abd5cc9f843e45a8a34af3228375cf0e58690f79b396b6e446f5ff2377150af414c8c3b6141c928b1129cd23fe4fb987031fa7d3617a404325618e6f3d12c9f156ffc62c8a901544c2f713c3bc9550cad582bb25224111327d0f824aef722903ba0fd5d448d8447e1ce2eda95fefd7065e3f174757ef2f22d7884bb14bf',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof003.json',
      value: {
        caseName: 'multi-message signature, multiple messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          'ac1f220973f6fc59a04b4b2bfe5505635124004734d1fb44cf84ce607a1ed282686ecd7b7bd17c48fc84322abde55401b12c7aa1ba0caa3531e55118fd5d2f2f7404a420de1be876e34f9a4a885934857e3f6c282d87c1963ba7040b3e2106c9b22277d3a2dcf6b058d8d6182aa4063e5c95d4e6c61121df903e344a64579084ebdcfad7cee46b42e58b5c334b8f6f1d0379bee1ed46b338e5369f178765be4d0ee4d730562f4a31d9677d36de28f4cc44494e2657fa655e3a74f44773d6feb4fd7f4f4b6e909fc6b6d0b4481d4dda85096cb8309dd3f8f4df675a18d1b68f41bd42e87af2ed48e119c394fa76434d7e6f2996f63bebe6d7e2d9ea922f3687ad1e026b8f3343ffbc995295c89a5ff43d0598a93c6664bc919001e3fb416a1f72a999088ce0bdf3c1d4b2f3b9e477a54b6d443a3ec1a5321d9f8bb0a2bb540f1232efbf1cf2f4e2e28322374ebfe9a01e3f090e3692ab3a1b5add0b69c1e1f8dd1b6117dd003d7f620d6f922fc318ae1a0813208b1e92ae2ae6f7db0c43902f85b330c6f6bb98095a06aeed47ee45b05d39c8f328c50bb691a74e2ef4dc5c648b7eb93b8ada84865572086e33597925974abc78780918172a9613536a8ef15284f71dd73f3435dc28d6467d757b8e32a44fc984c64c48a5cc35454c3db4f1dfe43e051427ffb19ec3569103da65671a91',
        result: {
          valid: true,
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof004.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          '011594ba7f95b3b470ea4102dd5899de3a042e5104d3ea01d15e6780d831d2be',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 'different presentation header',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof005.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'a91de0aa76950a710fd45ae66c08b221a8b7b6e01d7c6e5284dc013b10f7ac5ee6ccec6b9f18dc4f4e9d62a75906434e084d1261beb1670be46965d4e3f4c3bce9aff1bf9c121a2ba62bdc9fc1420cf0b79948d7b5da19e689a120fc9f0cfabf',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 'wrong public key',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof006.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '4abbdef3ed883be29964a1475925246dad63b8938030ed00f1be0085638ca8ab7083f22981736d2c22f84f1a7f29483cbb0508b04332a188f05f818f388d7170da79a4ae1e5bfb1c3600e806270d0b3c26b9a269139ed508c67bbf111bceacbabaae53a1',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 'modified messages',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof007.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '9': 'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        },
        totalMessageCount: 10,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 'extra message un-revealed in proof',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof008.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '9': '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
        },
        totalMessageCount: 10,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 'extra message invalid message un-revealed in proof',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof009.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 'missing message revealed in proof',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof010.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
        },
        totalMessageCount: 10,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 're-ordered messages',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof011.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
          '9': 'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
        },
        totalMessageCount: 11,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 'extra valid message, modified total message count',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof012.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: '11223344556677889900aabbccddeeff',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 9,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 'modified total message count less than actual',
        },
      },
    },
    {
      name: '/Users/tobiaslooker/Documents/Repositories/mattr/oss/pairing_crypto/wrappers/react-native/example/__fixtures__/../../../../tests/fixtures/bbs/bls12_381_shake_256/proof/proof013.json',
      value: {
        caseName: 'multi-message signature, all messages revealed proof',
        signerPublicKey:
          'b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7',
        header: 'ffeeddccbbaa00998877665544332211',
        presentationHeader:
          'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
        revealedMessages: {
          '0': '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
          '2': '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
          '4': 'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
          '6': '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
        },
        totalMessageCount: 10,
        proof:
          '925d87a2ccba0122db4ccb0e07c1e2ae6f2c60797fd0b1b02f62f13d7d2d5f928de333efeb27cf7a85536bfc480edfcd98ca9e44401023e1c22d85734b4ac8cc56a72f2d8931d67f36a34df4b4508a5bd695558bf827c30421d8509a86783f168023dda3245bbde2c3cb8982f6c336d04917506d089b01be223d8f3ebc22c4a09fe89e1151b67936101ee55250ce67102c3bede1a689123968502c0a35a994ff21a6a8df2e5d2e5e658c785f2a24219d598d4dd7747f769df250b943fe445aeba6d057fffa51894e236ae786679d13410c6a07521f1badffb394d3a73eed80d7747054ee7f3dee42edd8739bf9a116d7381ca55d9c5717c7d383746c7fc16edd53677559a7421aed8df8d3ddaab9dd837361bbe676bbbd51cf0b1e7b5521faab7b24fbc0db04c6e5f8907f3ca78890c1212290cf268e60f2e9f23299f240ec8ad0d5b9d0416b6e7e63ca3fbaea774e4c2ef33192f3db3c30696a1c27a4fb3d4fa8175b109618708b42ed79594bb4bc58249ab3d0f09d180d2c1cc1884393c4e2dafd8b07ee9bb1a76a655ea7df5bf64d129c63fbfad5e1cd01c679ebf827293d54c0218d9a0283029c35587802f63f7a1dd118e1a5875efcb7a0a07a3b8df360f957b9d1e904f775d56de8ad4498ae4373e44afb5927b0ce90799e3c5170fc76ab800946c49779aa00147ed2e08df37d',
        result: {
          valid: false,
          reason: 'different header',
        },
      },
    },
  ],
} as any;
