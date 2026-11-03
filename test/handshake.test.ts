import { describe, expect, test } from "bun:test";
import { bytesToHex as hex, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { generateKeypair, Handshake, type HandshakeOptions, type Keypair } from "../src/index.ts";
import type { Transport } from "../src/transport.ts";

const SUITE = "_25519_ChaChaPoly_BLAKE2s";
const ONE_WAY = ["N", "K", "X"];
const FUNDAMENTAL = ["NN", "NK", "NX", "XN", "XK", "XX", "KN", "KK", "KX", "IN", "IK", "IX"];
const DEFERRED = [
  "NK1",
  "NX1",
  "X1N",
  "X1K",
  "XK1",
  "X1K1",
  "X1X",
  "XX1",
  "X1X1",
  "K1N",
  "K1K",
  "KK1",
  "K1K1",
  "K1X",
  "KX1",
  "K1X1",
  "I1N",
  "I1K",
  "IK1",
  "I1K1",
  "I1X",
  "IX1",
  "I1X1",
];
const prologue = utf8ToBytes("prologue");

type Options = Omit<HandshakeOptions, "protocol">;
type Pair = { initiator: Options; responder: Options };

/** Derives key options from the pattern name: N has no static key, K pre-shares it, X and I transmit it. */
function keysFor(base: string, initiator: Keypair, responder: Keypair): Pair & { learns: [boolean, boolean] } {
  const [first, second] = base.length === 1 ? [base, "K"] : [base[0]!, base.replace(/^[NKXI]1?/, "")[0]!];
  return {
    initiator: {
      staticPrivateKey: first === "N" ? undefined : initiator.privateKey,
      remoteStaticPublicKey: second === "K" ? responder.publicKey : undefined,
    },
    responder: {
      staticPrivateKey: second === "N" ? undefined : responder.privateKey,
      remoteStaticPublicKey: first === "K" ? initiator.publicKey : undefined,
    },
    learns: [second !== "N", first !== "N"],
  };
}

function handshake(protocol: HandshakeOptions["protocol"], { initiator, responder }: Pair) {
  const parties = [
    Handshake.initiator({ protocol, prologue, ...initiator }),
    Handshake.responder({ protocol, prologue, ...responder }),
  ] as const;
  let count = 0;
  while (!parties[0].isFinished) {
    const [writer, reader] = parties[0].isMyTurn ? parties : [parties[1], parties[0]];
    expect(reader.isMyTurn).toBe(false);
    const payload = utf8ToBytes(`handshake message ${count++}`);
    expect(reader.readMessage(writer.writeMessage(payload))).toEqual(payload);
  }
  expect(parties[1].isFinished).toBe(true);
  return { count, sessions: [parties[0].intoTransport(), parties[1].intoTransport()] as const };
}

function exchange(sender: Transport, receiver: Transport, count = 3) {
  for (let i = 0; i < count; i++) {
    const payload = randomBytes(i * 50);
    expect(receiver.readMessage(sender.writeMessage(payload))).toEqual(payload);
  }
}

const withPsks = (keys: Pair, initiatorPsks: Options["psks"], responderPsks = initiatorPsks): Pair => ({
  initiator: { ...keys.initiator, psks: initiatorPsks },
  responder: { ...keys.responder, psks: responderPsks },
});

describe.each([...ONE_WAY, ...FUNDAMENTAL, ...DEFERRED])("Noise_%s", (base) => {
  const [initiatorKeys, responderKeys] = [generateKeypair(), generateKeypair()];
  const keys = keysFor(base, initiatorKeys, responderKeys);
  const { count } = handshake(`Noise_${base}${SUITE}`, keys);
  const positions = Array.from({ length: count + 1 }, (_, i) => i);
  const modifierSets = [[], ...positions.map((p) => [p]), positions];

  test.each(modifierSets.map((set) => [set.map((p) => `psk${p}`).join("+"), set] as const))(
    "round trip with modifiers '%s'",
    (modifiers, set) => {
      const psks = Object.fromEntries(set.map((p) => [p, randomBytes(32)]));
      const { sessions } = handshake(`Noise_${base}${modifiers}${SUITE}`, withPsks(keys, psks));
      const [initiator, responder] = sessions;
      expect(hex(responder.handshakeHash)).toBe(hex(initiator.handshakeHash));
      expect(initiator.remoteStaticPublicKey).toEqual(keys.learns[0] ? responderKeys.publicKey : undefined);
      expect(responder.remoteStaticPublicKey).toEqual(keys.learns[1] ? initiatorKeys.publicKey : undefined);
      exchange(initiator, responder);
      if (base.length === 1) {
        expect(() => initiator.readMessage(new Uint8Array(16))).toThrow("one-way");
        expect(() => responder.writeMessage()).toThrow("one-way");
      } else {
        exchange(responder, initiator);
        exchange(initiator, responder);
      }
    },
  );

  test("fails on a mismatched prologue, PSK, or pre-shared static key", () => {
    const protocol = `Noise_${base}${SUITE}` as const;
    expect(() =>
      handshake(protocol, { ...keys, initiator: { ...keys.initiator, prologue: utf8ToBytes("other") } }),
    ).toThrow();
    for (const p of positions) {
      const wrong = withPsks(keys, { [p]: randomBytes(32) }, { [p]: randomBytes(32) });
      expect(() => handshake(`Noise_${base}psk${p}${SUITE}`, wrong)).toThrow();
    }
    if (keys.responder.remoteStaticPublicKey) {
      const other = { ...keys, responder: { ...keys.responder, remoteStaticPublicKey: generateKeypair().publicKey } };
      expect(() => handshake(protocol, other)).toThrow();
    }
    if (keys.initiator.remoteStaticPublicKey) {
      const other = { ...keys, initiator: { ...keys.initiator, remoteStaticPublicKey: generateKeypair().publicKey } };
      expect(() => handshake(protocol, other)).toThrow();
    }
  });

  test(`rejects psk${count + 1}, past the last message`, () => {
    const psks = { [count + 1]: randomBytes(32) };
    expect(() =>
      Handshake.initiator({ protocol: `Noise_${base}psk${count + 1}${SUITE}`, ...keys.initiator, psks }),
    ).toThrow("unsupported Noise modifiers");
  });
});

test("rejects unsupported suites, patterns, fallback, hybrid and malformed modifiers", () => {
  const names = [
    "Noise_XX_25519_AESGCM_SHA256",
    "Noise_XX_448_ChaChaPoly_BLAKE2s",
    "Noise_XX_25519_ChaChaPoly_BLAKE2b",
    "Noise_XX_25519_ChaChaPoly_BLAKE2s ",
    "noise_XX_25519_ChaChaPoly_BLAKE2s",
    "Noise_XY_25519_ChaChaPoly_BLAKE2s",
    "Noise_NN1_25519_ChaChaPoly_BLAKE2s",
    "Noise_xx_25519_ChaChaPoly_BLAKE2s",
    "Noise_XXfallback_25519_ChaChaPoly_BLAKE2s",
    "Noise_XXpsk0+fallback_25519_ChaChaPoly_BLAKE2s",
    "Noise_XXhfs_25519+Kyber1024_ChaChaPoly_BLAKE2s",
    "Noise_XXhfs_25519_ChaChaPoly_BLAKE2s",
    "Noise_XXfoo_25519_ChaChaPoly_BLAKE2s",
    "Noise_NNpsk_25519_ChaChaPoly_BLAKE2s",
    "Noise_NNpsk01_25519_ChaChaPoly_BLAKE2s",
    "Noise_NNpsk0+psk0_25519_ChaChaPoly_BLAKE2s",
    "Noise_NNpsk2+psk0_25519_ChaChaPoly_BLAKE2s",
    "Noise_NNpsk0+_25519_ChaChaPoly_BLAKE2s",
    "Noise_NNpsk3_25519_ChaChaPoly_BLAKE2s",
    "Noise_Npsk2_25519_ChaChaPoly_BLAKE2s",
    "Noise_NNpsk99999999999999999999_25519_ChaChaPoly_BLAKE2s",
  ];
  for (const protocol of [...names, undefined]) {
    expect(() => Handshake.initiator({ protocol } as HandshakeOptions)).toThrow(/^unsupported Noise/);
  }
});

describe("options", () => {
  const key = generateKeypair();
  const psk = randomBytes(32);
  const cases: [string, HandshakeOptions, RegExp][] = [
    ["missing local static", { protocol: `Noise_XX${SUITE}` }, /requires staticPrivateKey/],
    ["missing remote static", { protocol: `Noise_NK${SUITE}` }, /requires remoteStaticPublicKey/],
    ["unused local static", { protocol: `Noise_NN${SUITE}`, staticPrivateKey: key.privateKey }, /does not use/],
    [
      "unused remote static, which XX would not check",
      { protocol: `Noise_XX${SUITE}`, staticPrivateKey: key.privateKey, remoteStaticPublicKey: key.publicKey },
      /does not use remoteStaticPublicKey/,
    ],
    ["short local static", { protocol: `Noise_XX${SUITE}`, staticPrivateKey: key.privateKey.subarray(1) }, /length 32/],
    ["short remote static", { protocol: `Noise_NK${SUITE}`, remoteStaticPublicKey: new Uint8Array(33) }, /length 32/],
    ["non-byte key", { protocol: `Noise_XX${SUITE}`, staticPrivateKey: [...key.privateKey] as never }, /Uint8Array/],
    ["missing PSK", { protocol: `Noise_NNpsk0${SUITE}` }, /PSKs exactly at positions \[0\]/],
    ["PSK at the wrong position", { protocol: `Noise_NNpsk0${SUITE}`, psks: { 1: psk } }, /psk0/],
    ["extra PSK", { protocol: `Noise_NNpsk0${SUITE}`, psks: { 0: psk, 2: psk } }, /PSKs exactly/],
    ["PSK for a non-PSK pattern", { protocol: `Noise_NN${SUITE}`, psks: { 0: psk } }, /PSKs exactly/],
    ["short PSK", { protocol: `Noise_NNpsk0${SUITE}`, psks: { 0: psk.subarray(1) } }, /length 32/],
    ["non-byte prologue", { protocol: `Noise_NN${SUITE}`, prologue: "v1" as never }, /Uint8Array/],
  ];
  test.each(cases)("rejects %s", (_, options, error) => expect(() => Handshake.initiator(options)).toThrow(error));
});

describe("state machine", () => {
  const protocol = `Noise_NN${SUITE}`;

  test("enforces turns and completion without disturbing the handshake", () => {
    const initiator = Handshake.initiator({ protocol });
    const responder = Handshake.responder({ protocol });
    expect(() => responder.writeMessage()).toThrow("not this party's turn to write");
    expect(() => initiator.readMessage(new Uint8Array(32))).toThrow("not this party's turn to read");
    expect(() => initiator.intoTransport()).toThrow("not finished");
    responder.readMessage(initiator.writeMessage());
    expect(() => initiator.writeMessage()).toThrow("not this party's turn to write");
    expect(() => responder.intoTransport()).toThrow("not finished");
    initiator.readMessage(responder.writeMessage());
    for (const party of [initiator, responder]) {
      expect(party.isMyTurn).toBe(false);
      expect(() => party.writeMessage()).toThrow("already finished");
      expect(() => party.readMessage(new Uint8Array(48))).toThrow("already finished");
    }
    exchange(initiator.intoTransport(), responder.intoTransport());
  });

  test("converts into exactly one transport, then refuses all use", () => {
    const initiator = Handshake.initiator({ protocol });
    const responder = Handshake.responder({ protocol });
    responder.readMessage(initiator.writeMessage());
    initiator.readMessage(responder.writeMessage());
    const alias = initiator;
    const transport = initiator.intoTransport();
    for (const party of [initiator, alias]) {
      expect(() => party.intoTransport()).toThrow("no longer usable");
      expect(() => party.writeMessage()).toThrow("no longer usable");
      expect(() => party.readMessage(new Uint8Array(48))).toThrow("no longer usable");
      expect(party.isFinished).toBe(true);
    }
    exchange(transport, responder.intoTransport());
  });

  // In PSK handshakes, the ephemeral in the first NN message already keys the payload (Noise spec section 9.2).
  test.each([`Noise_NK${SUITE}`, `Noise_NNpsk2${SUITE}`])(
    "%s bounds handshake messages to 65535 bytes and fails on a bad length",
    (protocol) => {
      const pair = keysFor(protocol.slice(6, 8), generateKeypair(), generateKeypair());
      const psks = protocol.includes("psk") ? { 2: randomBytes(32) } : {};
      const start = () =>
        [
          Handshake.initiator({ protocol, ...pair.initiator, psks }),
          Handshake.responder({ protocol, ...pair.responder, psks }),
        ] as const;
      const [initiator, responder] = start();
      const largest = randomBytes(65535 - 32 - 16);
      const message = initiator.writeMessage(largest);
      expect(message.length).toBe(65535);
      expect(responder.readMessage(message)).toEqual(largest);
      initiator.readMessage(responder.writeMessage());
      exchange(initiator.intoTransport(), responder.intoTransport());
      const [oversized, truncated, overlong] = [start()[0], start()[1], start()[1]];
      expect(() => oversized.writeMessage(new Uint8Array(largest.length + 1))).toThrow("too long");
      expect(() => truncated.readMessage(message.subarray(0, 31))).toThrow("too short");
      expect(() => overlong.readMessage(new Uint8Array(65536))).toThrow("too long");
      for (const party of [oversized, truncated, overlong]) {
        expect(() => party.writeMessage()).toThrow("no longer usable");
      }
    },
  );

  test("permanently invalidates a handshake after a failed read", () => {
    const pair = keysFor("NK", generateKeypair(), generateKeypair());
    const initiator = Handshake.initiator({ protocol: `Noise_NK${SUITE}`, ...pair.initiator });
    const responder = Handshake.responder({ protocol: `Noise_NK${SUITE}`, ...pair.responder });
    const message = initiator.writeMessage(utf8ToBytes("hello"));
    const tampered = message.slice();
    tampered[tampered.length - 1] ^= 1;
    expect(() => responder.readMessage(tampered)).toThrow(expect.objectContaining({ code: "decrypt-failed" }));
    expect(() => responder.readMessage(message)).toThrow("no longer usable");
    expect(() => responder.writeMessage()).toThrow("no longer usable");
  });

  test("preserves Noble's rejection of low-order public keys", () => {
    const lowOrder = new Uint8Array(32);
    const initiator = Handshake.initiator({ protocol: `Noise_NK${SUITE}`, remoteStaticPublicKey: lowOrder });
    expect(() => initiator.writeMessage()).toThrow(expect.objectContaining({ code: "invalid-key" }));
    expect(() => initiator.writeMessage()).toThrow("no longer usable");
    const responder = Handshake.responder({
      protocol: `Noise_NK${SUITE}`,
      staticPrivateKey: generateKeypair().privateKey,
    });
    expect(() => responder.readMessage(new Uint8Array(48))).toThrow(expect.objectContaining({ code: "invalid-key" }));
    expect(() => responder.readMessage(new Uint8Array(48))).toThrow("no longer usable");
  });

  test("generates a fresh ephemeral for every handshake", () => {
    const first = Handshake.initiator({ protocol }).writeMessage();
    const second = Handshake.initiator({ protocol }).writeMessage();
    expect(hex(first)).not.toBe(hex(second));
  });
});

test("keeps private copies of options", () => {
  const protocol = `Noise_IKpsk2${SUITE}`;
  const [client, server] = [generateKeypair(), generateKeypair()];
  const inputs = {
    prologue: prologue.slice(),
    psk: randomBytes(32),
    client: client.privateKey.slice(),
    server: server.publicKey.slice(),
  };
  const initiator = Handshake.initiator({
    protocol,
    prologue: inputs.prologue,
    staticPrivateKey: inputs.client,
    remoteStaticPublicKey: inputs.server,
    psks: { 2: inputs.psk },
  });
  const responder = Handshake.responder({
    protocol,
    prologue,
    staticPrivateKey: server.privateKey,
    psks: { 2: inputs.psk.slice() },
  });
  for (const input of Object.values(inputs)) input.fill(0);
  responder.readMessage(initiator.writeMessage());
  initiator.readMessage(responder.writeMessage());
  exchange(initiator.intoTransport(), responder.intoTransport());
});

test("keeps nothing aliased to messages, payloads, or returned metadata", () => {
  // IX sends the initiator's static key unencrypted, so it is read straight out of the message buffer.
  const protocol = `Noise_IX${SUITE}`;
  const [client, server] = [generateKeypair(), generateKeypair()];
  const initiator = Handshake.initiator({ protocol, staticPrivateKey: client.privateKey });
  const responder = Handshake.responder({ protocol, staticPrivateKey: server.privateKey });
  const first = initiator.writeMessage(utf8ToBytes("first"));
  const payload = responder.readMessage(first);
  first.fill(0);
  new Uint8Array(payload.buffer).fill(0);
  responder.remoteStaticPublicKey!.fill(0);
  expect(responder.remoteStaticPublicKey).toEqual(client.publicKey);
  expect(initiator.readMessage(responder.writeMessage())).toEqual(new Uint8Array());

  const [a, b] = [initiator.intoTransport(), responder.intoTransport()];
  const hash = a.handshakeHash;
  a.handshakeHash.fill(0);
  a.remoteStaticPublicKey!.fill(0);
  b.remoteStaticPublicKey!.fill(0);
  expect(a.handshakeHash).toEqual(hash);
  expect(b.handshakeHash).toEqual(hash);
  expect(a.remoteStaticPublicKey).toEqual(server.publicKey);
  expect(b.remoteStaticPublicKey).toEqual(client.publicKey);
  exchange(a, b);
  exchange(b, a);
});
