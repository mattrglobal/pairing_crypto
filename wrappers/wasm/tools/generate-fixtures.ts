import { randomBytes } from "@stablelib/random";
import { generateMessages } from "../bench/helper";

import { bls12381, KeyPair, utilities } from "../lib";

import fs from "fs";

const MESSAGE_SIZE_BYTES = 32;

interface GenerateFixtureRequest {
  numberOfMessages?: number;
  messages?: Uint8Array[];
  signerKeyPair?: KeyPair;
  verifyFixtures: boolean;
  messagesToReveal: number[];
  signerKeySeed?: Uint8Array;
  presentationMessage?: Uint8Array;
}

interface GenerateFixtureResponse {
  signerKeyPair: KeyPair;
  presentationMessage: Uint8Array;
  messagesToReveal: number[];
  totalMessageCount: number;
  revealedMessages: { [key: number]: Uint8Array };
  signature: Uint8Array;
  messages: Uint8Array[];
  proof: Uint8Array;
}

const outputDirectory = "__fixtures__";

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
      "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416"
    )
  ),
  new Uint8Array(
    Buffer.from(
      "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
    )
  ),
];

const signerKeySeed = new Uint8Array(
  Buffer.from(
    "0cf3cc44220fdb2f8ca701f8686ed7e9a32db440edc15a9b62222905d8c7bba3",
    "hex"
  )
);

const spareSignerKeyPair = {
  publicKey: new Uint8Array(
    Buffer.from(
      "94d5fcad678c27602a345d332e9d64a077e8a13e9d7556ae4b223f9f4fc296a4ef14e2ccfc51f528478c7895befa0f5617495561f49f63d27712e940eb3c44c3c1f301a363b02da53289558b1a476630251becda0c658d9bdac4924506f62c8a",
      "hex"
    )
  ),
  secretKey: new Uint8Array(
    Buffer.from(
      "24a038e171d441723ed5d441132af7b0f7aeced8e0c6d9402a95b6a6bbdfae64",
      "hex"
    )
  ),
};

const generateFixture = async (
  request: GenerateFixtureRequest
): Promise<GenerateFixtureResponse> => {
  let seed = request.signerKeySeed ?? randomBytes(32);
  let signerKeyPair =
    request.signerKeyPair ?? (await bls12381.generateG2KeyPair(seed));
  const messages = request.numberOfMessages
    ? generateMessages(request.numberOfMessages, MESSAGE_SIZE_BYTES)
    : (request.messages as Uint8Array[]);

  const signature = await bls12381.bbs.sign({
    messages,
    secretKey: signerKeyPair.secretKey,
  });

  if (request.verifyFixtures) {
    if (
      !(await bls12381.bbs.verify({
        publicKey: signerKeyPair.publicKey,
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

  const proof = await bls12381.bbs.deriveProof({
    messages: revealMessages,
    publicKey: signerKeyPair.publicKey,
    presentationMessage,
    signature,
  });

  const revealedMessages: {
    [key: number]: Uint8Array;
  } = utilities.convertRevealMessageArrayToRevealMap(revealMessages);

  return {
    signature,
    signerKeyPair,
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
    signerKeySeed,
    presentationMessage,
    messages: messages.slice(0, 1),
    verifyFixtures: true,
    messagesToReveal: [0],
  });

  // Key pair fixture
  await writeKeyPairTestVectorToFile(`${outputDirectory}/keyPair.json`, {
    seed: signerKeySeed,
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
    signerKeySeed,
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
    signerKeySeed,
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
    signerKeySeed,
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
    seed: Uint8Array;
    keyPair: KeyPair;
  }
) => {
  const result = {
    seed: bytesToString(fixture.seed),
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
