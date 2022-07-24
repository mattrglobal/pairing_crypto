import { randomBytes } from "@stablelib/random";
import { generateMessages } from "../bench/helper";

import { bbs, KeyPair, utilities } from "../lib";

import fs from "fs";

const MESSAGE_SIZE_BYTES = 32;

interface GenerateFixtureRequest {
  numberOfMessages?: number;
  messages?: Uint8Array[];
  signerKeyPair?: KeyPair;
  verifyFixtures: boolean;
  messagesToReveal: number[];
  signerKeyIkm?: Uint8Array;
  signerKeyInfo?: Uint8Array;
  header?: Uint8Array;
  presentationMessage?: Uint8Array;
}

interface GenerateFixtureResponse {
  signerKeyPair: KeyPair;
  header: Uint8Array;
  presentationMessage: Uint8Array;
  messagesToReveal: number[];
  totalMessageCount: number;
  revealedMessages: { [key: number]: Uint8Array };
  signature: Uint8Array;
  messages: Uint8Array[];
  proof: Uint8Array;
}

const outputDirectory = "__fixtures__";

const header = new Uint8Array(
  Buffer.from(
    "11223344556677889900aabbccddeeff",
    "hex"
  )
);

const presentationMessage = new Uint8Array(
  Buffer.from(
    "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501",
    "hex"
  )
);

// TODO make these configurable
const messages = [
  new Uint8Array(
    Buffer.from(
      "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
      "hex"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6",
      "hex"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90",
      "hex"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943",
      "hex"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151",
      "hex"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc",
      "hex"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2",
      "hex"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91",
      "hex"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416",
      "hex"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
      "hex"
    )
  ),
];

const signerKeyIkm = new Uint8Array(
  Buffer.from(
    "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579",
    "hex"
  )
);

const signerKeyInfo = new Uint8Array(
  Buffer.from(
    "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e",
    "hex"
  )
);

const spareSignerKeyPair = {
  publicKey: new Uint8Array(
    Buffer.from(
      "a91de0aa76950a710fd45ae66c08b221a8b7b6e01d7c6e5284dc013b10f7ac5ee6ccec6b9f18dc4f4e9d62a75906434e084d1261beb1670be46965d4e3f4c3bce9aff1bf9c121a2ba62bdc9fc1420cf0b79948d7b5da19e689a120fc9f0cfabf",
      "hex"
    )
  ),
  secretKey: new Uint8Array(
    Buffer.from(
      "593ba71072476149dead00db79a0e3058839a337d48b43490b3d2d8d5207133c",
      "hex"
    )
  ),
};

const generateFixture = async (
  request: GenerateFixtureRequest
): Promise<GenerateFixtureResponse> => {
  let ikm = request.signerKeyIkm ?? randomBytes(32);
  let keyInfo = request.signerKeyInfo ?? randomBytes(32);
  let signerKeyPair =
    request.signerKeyPair ?? (await bbs.bls12381.generateKeyPair(ikm, keyInfo));
  const messages = request.numberOfMessages
    ? generateMessages(request.numberOfMessages, MESSAGE_SIZE_BYTES)
    : (request.messages as Uint8Array[]);

  let header = request.header ?? randomBytes(32);


  const signature = await bbs.bls12381.sign({
    secretKey: signerKeyPair.secretKey,
    publicKey: signerKeyPair.publicKey,
    header,
    messages

  });

  if (request.verifyFixtures) {
    if (
      !(await bbs.bls12381.verify({
        publicKey: signerKeyPair.publicKey,
        header,
        messages,
        signature,
      }))
    ) {
      throw new Error("Failed to verify generated signature");
    }
  }

  let presentationMessage = request.presentationMessage ?? randomBytes(32);

  let revealMessages = utilities.convertToRevealMessageArray(
    messages,
    request.messagesToReveal
  );

  const proof = await bbs.bls12381.deriveProof({
    messages: revealMessages,
    publicKey: signerKeyPair.publicKey,
    header,
    presentationMessage,
    signature,
  });

  const revealedMessages: {
    [key: number]: Uint8Array;
  } = utilities.convertRevealMessageArrayToRevealMap(revealMessages);

  return {
    signature,
    signerKeyPair,
    header,
    presentationMessage,
    totalMessageCount: messages.length,
    messagesToReveal: request.messagesToReveal,
    revealedMessages,
    messages,
    proof,
  };
};

const generateSignatureTestVectors = async () => {
  let fixture = await generateFixture({
    signerKeyIkm,
    signerKeyInfo,
    presentationMessage,
    messages: messages.slice(0, 1),
    header,
    verifyFixtures: true,
    messagesToReveal: [0],
  });

  // Key pair fixture
  await writeKeyPairTestVectorToFile(`${outputDirectory}/keyPair.json`, {
    ikm: signerKeyIkm,
    keyInfo: signerKeyInfo,
    keyPair: fixture.signerKeyPair,
  });

  // Valid single message signature
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature001.json`,
    {
      ...fixture,
      caseName: "single message signature",
      result: { valid: true },
    }
  );

  // Invalid single message signature, message modified
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature002.json`,
    {
      ...fixture,
      messages: [messages[messages.length - 1]],
      caseName: "single message signature",
      result: { valid: false, reason: "modified message" },
    }
  );

  // Invalid single message signature, extra unsigned message
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature003.json`,
    {
      ...fixture,
      messages: [...fixture.messages, messages[messages.length - 1]],
      caseName: "single message signature",
      result: { valid: false, reason: "extra unsigned message" },
    }
  );

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof001.json`,
    {
      ...fixture,
      revealedMessages: fixture.revealedMessages,
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "single message signature, message revealed proof",
      result: { valid: true },
    }
  );

  fixture = await generateFixture({
    signerKeyIkm,
    signerKeyInfo,
    header,
    presentationMessage,
    messages: messages.slice(0, 10),
    verifyFixtures: true,
    messagesToReveal: [...Array(10).keys()],
  });

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof002.json`,
    {
      ...fixture,
      revealedMessages: fixture.revealedMessages,
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, all messages revealed proof",
      result: { valid: true },
    }
  );

  fixture = await generateFixture({
    signerKeyIkm,
    signerKeyInfo,
    header,
    presentationMessage,
    messages: messages.slice(0, 10),
    verifyFixtures: true,
    messagesToReveal: [0, 2, 4, 6],
  });

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof003.json`,
    {
      ...fixture,
      revealedMessages: fixture.revealedMessages,
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: { valid: true },
    }
  );

  fixture.presentationMessage.reverse();

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof004.json`,
    {
      ...fixture,
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: { valid: false, reason: "different presentation message" },
    }
  );

  fixture.presentationMessage.reverse();

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof005.json`,
    {
      ...fixture,
      signerPublicKey: spareSignerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: { valid: false, reason: "wrong public key" },
    }
  );

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof006.json`,
    {
      ...fixture,
      revealedMessages: Object.entries(fixture.revealedMessages).reduce(
        (map, val, _) => {
          const key = parseInt(val[0]);
          let message = new Uint8Array(val[1]);
          message = message.reverse();

          map = {
            ...map,
            [key]: message,
          };

          return map;
        },
        {}
      ),
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: { valid: false, reason: "modified messages" },
    }
  );

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof007.json`,
    {
      ...fixture,
      revealedMessages: { ...fixture.revealedMessages, 9: messages[9] },
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: { valid: false, reason: "extra message un-revealed in proof" },
    }
  );

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof008.json`,
    {
      ...fixture,
      revealedMessages: { ...fixture.revealedMessages, 9: messages[8] },
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: {
        valid: false,
        reason: "extra message invalid message un-revealed in proof",
      },
    }
  );

  let missingMessages = { ...fixture.revealedMessages };
  delete missingMessages[2];
  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof009.json`,
    {
      ...fixture,
      revealedMessages: missingMessages,
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: { valid: false, reason: "missing message revealed in proof" },
    }
  );

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof010.json`,
    {
      ...fixture,
      revealedMessages: {
        ...fixture.revealedMessages,
        // Swap the valid messages in their association to the right reveal index
        [2]: fixture.revealedMessages[6],
        [6]: fixture.revealedMessages[2],
      },
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: { valid: false, reason: "re-ordered messages" },
    }
  );

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof011.json`,
    {
      ...fixture,
      revealedMessages: { ...fixture.revealedMessages, 9: messages[9] },
      totalMessageCount: fixture.totalMessageCount + 1,
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: {
        valid: false,
        reason: "extra valid message, modified total message count",
      },
    }
  );

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof012.json`,
    {
      ...fixture,
      revealedMessages: { ...fixture.revealedMessages },
      totalMessageCount: fixture.totalMessageCount - 1,
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: {
        valid: false,
        reason: "modified total message count less than actual",
      },
    }
  );

  // TODO need to try the case where some revealed messages are dropped from the proof structure

  fixture = await generateFixture({
    signerKeyIkm,
    signerKeyInfo,
    header,
    presentationMessage,
    messages,
    verifyFixtures: true,
    messagesToReveal: [0],
  });

  // Valid multi-message signature
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature004.json`,
    {
      ...fixture,
      caseName: "multi-message signature",
      result: { valid: true },
    }
  );

  // Invalid multi-message signature, missing messages
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature005.json`,
    {
      ...fixture,
      messages: fixture.messages.slice(0, 2),
      caseName: "multi-message signature",
      result: { valid: false, reason: "missing messages" },
    }
  );

  // Invalid multi-message signature, re-ordered messages
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature006.json`,
    {
      ...fixture,
      messages: fixture.messages.reverse(),
      caseName: "multi-message signature",
      result: { valid: false, reason: "re-ordered messages" },
    }
  );
  // Restore the order
  fixture.messages.reverse();

  // Invalid multi-message signature, wrong public key
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature007.json`,
    {
      ...fixture,
      signerKeyPair: spareSignerKeyPair,
      caseName: "multi-message signature",
      result: { valid: false, reason: "wrong public key" },
    }
  );
};

const bytesToString = (byteArray: Uint8Array) => {
  return Buffer.from(byteArray).toString("hex");
};

const writeKeyPairTestVectorToFile = async (
  fileName: string,
  fixture: {
    ikm: Uint8Array;
    keyInfo: Uint8Array;
    keyPair: KeyPair;
  }
) => {
  const result = {
    ikm: bytesToString(fixture.ikm),
    keyInfo: bytesToString(fixture.keyInfo),
    publicKey: bytesToString(fixture.keyPair.publicKey),
    secretKey: bytesToString(fixture.keyPair.secretKey),
  };

  await fs.promises.writeFile(
    fileName,
    Buffer.from(JSON.stringify(result, null, 2)),
    "utf8"
  );
};

const writeSignatureTestVectorToFile = async (
  fileName: string,
  fixture: {
    caseName: string;
    result: { valid: false; reason: string } | { valid: true };
    signature: Uint8Array;
    messages: Uint8Array[];
    signerKeyPair: KeyPair;
    header: Uint8Array;
  }
) => {
  const result = {
    caseName: fixture.caseName,
    signature: bytesToString(fixture.signature),
    messages: fixture.messages.map((item) => bytesToString(item)),
    result: fixture.result,
    signerKeyPair: {
      publicKey: bytesToString(fixture.signerKeyPair.publicKey),
      secretKey: bytesToString(fixture.signerKeyPair.secretKey),
    },
    header: bytesToString(fixture.header),
  };

  await fs.promises.writeFile(
    fileName,
    Buffer.from(JSON.stringify(result, null, 2)),
    "utf8"
  );
};

const writeSignatureProofTestVectorFile = async (
  fileName: string,
  fixture: {
    caseName: string;
    result: { valid: false; reason: string } | { valid: true };
    proof: Uint8Array;
    header: Uint8Array;
    presentationMessage: Uint8Array;
    totalMessageCount: number;
    revealedMessages: { [key: number]: Uint8Array };
    signerPublicKey: Uint8Array;
  }
) => {
  const revealedMessages = Object.entries(fixture.revealedMessages).reduce(
    (map, val, _) => {
      const key = parseInt(val[0]);
      const message = Buffer.from(val[1]).toString("hex");

      map = {
        ...map,
        [key]: message,
      };

      return map;
    },
    {}
  );

  const result = {
    caseName: fixture.caseName,
    proof: bytesToString(fixture.proof),
    header: bytesToString(fixture.header),
    presentationMessage: bytesToString(fixture.presentationMessage),
    revealedMessages,
    totalMessageCount: fixture.totalMessageCount,
    result: fixture.result,
    signerPublicKey: bytesToString(fixture.signerPublicKey),
  };

  await fs.promises.writeFile(
    fileName,
    Buffer.from(JSON.stringify(result, null, 2)),
    "utf8"
  );
};

generateSignatureTestVectors();
