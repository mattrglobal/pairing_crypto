import { randomBytes } from "@stablelib/random";
import { generateMessages } from "../bench/helper";

import { bls12381, KeyPair } from "../lib";

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
  revealedMessages: { [key: number]: Uint8Array };
  signature: Uint8Array;
  messages: Uint8Array[];
  proof: Uint8Array;
}

const outputDirectory = "__fixtures__";

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

const signerKeyPair = {
  publicKey: new Uint8Array(
    Buffer.from(
      "855356ed5ea276ecca4fa7d7844a367a708a0c70d3f111cfbac351cc124da1b496b5426747f36bb4a1c9070aa839d1eb1433db1339fb5ee4417000548de4a122e1d21f6c3df4add6b4169398c69d4c7f6f47ff5f28960781b18517b7fa6daef1",
      "hex"
    )
  ),
  secretKey: new Uint8Array(
    Buffer.from(
      "6ee252c19d60b5fd3d1ec1246c4a41398962a5c8ac62868a2e095ae2250852e7",
      "hex"
    )
  ),
};

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

  let presentationMessage = randomBytes(32);

  let revealMessages: { value: Uint8Array; reveal: boolean }[] = [];
  let i = 0;
  messages.forEach((element) => {
    if (request.messagesToReveal.includes(i)) {
      revealMessages.push({ value: element, reveal: true });
    } else {
      revealMessages.push({ value: element, reveal: false });
    }
    i++;
  });

  const proof = await bls12381.bbs.deriveProof({
    messages: messages.map((item) => {
      return { value: item, reveal: true };
    }),
    publicKey: signerKeyPair.publicKey,
    presentationMessage,
    signature,
  });

  const revealedMessages: { [key: number]: Uint8Array } = revealMessages.reduce(
    (map, item, index) => {
      map = {
        ...map,
        [index]: item.value,
      };
      return map;
    },
    {}
  );

  // TODO verify proof

  return {
    signature,
    signerKeyPair,
    presentationMessage,
    messagesToReveal: request.messagesToReveal,
    revealedMessages,
    messages,
    proof,
  };
};

const generateSignatureTestVectors = async () => {
  let fixture = await generateFixture({
    signerKeyPair,
    messages: messages.slice(0, 1),
    verifyFixtures: true,
    messagesToReveal: [0],
  });

  // Valid single message signature
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature-001.json`,
    {
      ...fixture,
      caseName: "single message signature",
      result: { valid: true },
    }
  );

  // Invalid single message signature, message modified
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature-002.json`,
    {
      ...fixture,
      messages: [messages[messages.length - 1]],
      caseName: "single message signature",
      result: { valid: false, reason: "modified message" },
    }
  );

  // Invalid single message signature, extra unsigned message
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature-003.json`,
    {
      ...fixture,
      messages: [...fixture.messages, messages[messages.length - 1]],
      caseName: "single message signature",
      result: { valid: false, reason: "extra unsigned message" },
    }
  );

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof-001.json`,
    {
      ...fixture,
      revealedMessages: fixture.revealedMessages,
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "single message signature, message revealed proof",
      result: { valid: true },
    }
  );

  fixture = await generateFixture({
    signerKeyPair,
    messages: messages.slice(0, 10),
    verifyFixtures: true,
    messagesToReveal: [0, 2, 4, 6],
  });

  await writeSignatureProofTestVectorFile(
    `${outputDirectory}/proof/proof-002.json`,
    {
      ...fixture,
      revealedMessages: fixture.revealedMessages,
      signerPublicKey: fixture.signerKeyPair.publicKey,
      caseName: "multi-message signature, multiple messages revealed proof",
      result: { valid: true },
    }
  );

  fixture = await generateFixture({
    signerKeyPair,
    messages,
    verifyFixtures: true,
    messagesToReveal: [0],
  });

  // Valid multi-message signature
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature-004.json`,
    {
      ...fixture,
      caseName: "multi-message signature",
      result: { valid: true },
    }
  );

  // Invalid multi-message signature, missing messages
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature-005.json`,
    {
      ...fixture,
      messages: fixture.messages.slice(0, 2),
      caseName: "multi-message signature",
      result: { valid: false, reason: "missing messages" },
    }
  );

  // Invalid multi-message signature, missing messages
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature-006.json`,
    {
      ...fixture,
      messages: fixture.messages.reverse(),
      caseName: "multi-message signature",
      result: { valid: false, reason: "re-ordered messages" },
    }
  );

  // Invalid multi-message signature, wrong public key
  await writeSignatureTestVectorToFile(
    `${outputDirectory}/signature/signature-007.json`,
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
    revealedMessages: { [key: number]: Uint8Array };
    signerPublicKey: Uint8Array;
  }
) => {
  const revealedMessages = Object.entries(fixture.revealedMessages).reduce(
    (map, val, index) => {
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
    revealedMessages,
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
