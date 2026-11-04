import { describe, expect, test } from "bun:test";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hexToBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Handshake } from "../src/index.ts";
import { CipherState } from "../src/state.ts";

function connect() {
  const protocol = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
  const initiator = Handshake.initiator({ protocol });
  const responder = Handshake.responder({ protocol });
  responder.readMessage(initiator.writeMessage());
  initiator.readMessage(responder.writeMessage());
  return [initiator.intoTransport(), responder.intoTransport()] as const;
}

test("a failed decryption leaves the receiving nonce in place", () => {
  const [sender, receiver] = connect();
  const first = sender.writeMessage(utf8ToBytes("first"));
  const second = sender.writeMessage(utf8ToBytes("second"));
  const tampered = first.slice();
  tampered[0] ^= 1;
  expect(() => receiver.readMessage(tampered)).toThrow();
  expect(() => receiver.readMessage(second)).toThrow();
  expect(receiver.readMessage(first)).toEqual(utf8ToBytes("first"));
  expect(receiver.readMessage(second)).toEqual(utf8ToBytes("second"));
});

test("bounds transport messages to 16..65535 bytes before using a nonce", () => {
  const [sender, receiver] = connect();
  const largest = randomBytes(65535 - 16);
  expect(() => sender.writeMessage(new Uint8Array(largest.length + 1))).toThrow("too long");
  const message = sender.writeMessage(largest);
  expect(message.length).toBe(65535);
  expect(() => receiver.readMessage(message.subarray(0, 15))).toThrow("invalid Noise message length");
  expect(() => receiver.readMessage(new Uint8Array(65536))).toThrow("invalid Noise message length");
  expect(receiver.readMessage(message)).toEqual(largest);
  const empty = receiver.writeMessage();
  expect(empty.length).toBe(16);
  expect(sender.readMessage(empty)).toEqual(new Uint8Array());
});

describe("CipherState", () => {
  const key = randomBytes(32);
  const ad = utf8ToBytes("associated data");
  const plaintext = utf8ToBytes("plaintext");
  const sealed = (nonce: string) => chacha20poly1305(key, hexToBytes(nonce), ad).encrypt(plaintext);

  test.each([
    [0n, ["000000000000000000000000", "000000000100000000000000"]],
    [255n, ["00000000ff00000000000000", "000000000001000000000000"]],
    [2n ** 32n - 1n, ["00000000ffffffff00000000", "000000000000000001000000"]],
    [2n ** 53n - 1n, ["00000000ffffffffffff1f00", "000000000000000000002000", "000000000100000000002000"]],
    [2n ** 64n - 3n, ["00000000fdffffffffffffff", "00000000feffffffffffffff"]],
  ])("counts from %p as four zero bytes and a little-endian uint64", (start, nonces) => {
    const sender = new CipherState("ChaChaPoly", key, start);
    const receiver = new CipherState("ChaChaPoly", key, start);
    for (const nonce of nonces) {
      const ciphertext = sender.encryptWithAd(ad, plaintext);
      expect(ciphertext).toEqual(sealed(nonce));
      expect(receiver.decryptWithAd(ad, ciphertext)).toEqual(plaintext);
    }
  });

  test("refuses the reserved nonce 2^64 - 1 in both directions", () => {
    const sender = new CipherState("ChaChaPoly", key, 2n ** 64n - 2n);
    sender.encryptWithAd(ad, plaintext);
    expect(() => sender.encryptWithAd(ad, plaintext)).toThrow("exhausted");
    const receiver = new CipherState("ChaChaPoly", key, 2n ** 64n - 1n);
    expect(() => receiver.decryptWithAd(ad, sealed("00000000ffffffffffffffff"))).toThrow("exhausted");
  });
});
