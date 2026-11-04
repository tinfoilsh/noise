import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { blake2b, blake2s } from "@noble/hashes/blake2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { concatBytes, copyBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { NoiseError } from "./errors.js";

export const TAG_LENGTH = 16;
export const EMPTY = new Uint8Array();
// HKDF outputs are truncated to 32 bytes when used as cipher keys (Noise spec section 5.2).
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
// Nonces are 4 zero bytes and the counter, little-endian for ChaChaPoly, big-endian for AESGCM (Noise spec 12.3, 12.4).
const COUNTER_OFFSET = 4;
// 2^64-1 is reserved and may not be used as a nonce (Noise spec section 5.1).
const RESERVED_NONCE = 2n ** 64n - 1n;

export const CIPHERS = {
  ChaChaPoly: { aead: chacha20poly1305, littleEndian: true },
  AESGCM: { aead: gcm, littleEndian: false },
};
export const HASHES = { BLAKE2s: blake2s, BLAKE2b: blake2b, SHA256: sha256, SHA512: sha512 };
export type CipherName = keyof typeof CIPHERS;
export type HashName = keyof typeof HASHES;

/** A keyed CipherState (Noise spec section 5.1). */
export class CipherState {
  readonly #cipher: (typeof CIPHERS)[CipherName];
  readonly #key: Uint8Array;
  #n: bigint;

  constructor(cipher: CipherName, key: Uint8Array, n = 0n) {
    this.#cipher = CIPHERS[cipher];
    this.#key = key;
    this.#n = n;
  }

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array<ArrayBuffer> {
    const ciphertext = this.#aead(ad).encrypt(plaintext);
    this.#n++;
    return ciphertext;
  }

  /** Leaves the nonce unchanged when authentication fails. */
  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array<ArrayBuffer> {
    const aead = this.#aead(ad);
    try {
      const plaintext = aead.decrypt(ciphertext);
      this.#n++;
      return plaintext;
    } catch (cause) {
      throw new NoiseError("decrypt-failed", "Noise message failed authentication", { cause });
    }
  }

  #aead(ad: Uint8Array) {
    if (this.#n === RESERVED_NONCE) throw new NoiseError("nonce-exhausted", "Noise nonce exhausted");
    const nonce = new Uint8Array(NONCE_LENGTH);
    new DataView(nonce.buffer).setBigUint64(COUNTER_OFFSET, this.#n, this.#cipher.littleEndian);
    return this.#cipher.aead(this.#key, nonce, ad);
  }
}

/** The SymmetricState (Noise spec section 5.2). An absent CipherState represents the spec's empty key. */
export class SymmetricState {
  readonly #cipherName: CipherName;
  readonly #hash: (typeof HASHES)[HashName];
  #ck: Uint8Array;
  #h: Uint8Array;
  #cipher: CipherState | undefined;

  constructor(protocol: string, cipher: CipherName, hash: HashName) {
    this.#cipherName = cipher;
    this.#hash = HASHES[hash];
    const name = utf8ToBytes(protocol);
    if (name.length <= this.#hash.outputLen) {
      this.#h = new Uint8Array(this.#hash.outputLen);
      this.#h.set(name);
    } else {
      this.#h = this.#hash(name);
    }
    this.#ck = this.#h;
  }

  get hasKey(): boolean {
    return this.#cipher !== undefined;
  }

  get handshakeHash(): Uint8Array {
    return this.#h;
  }

  mixKey(inputKeyMaterial: Uint8Array): void {
    const [ck, k] = this.#hkdf(inputKeyMaterial, 2);
    this.#ck = ck;
    this.#cipher = this.#cipherState(k);
  }

  mixHash(data: Uint8Array): void {
    this.#h = this.#hash(concatBytes(this.#h, data));
  }

  mixKeyAndHash(inputKeyMaterial: Uint8Array): void {
    const [ck, h, k] = this.#hkdf(inputKeyMaterial, 3);
    this.#ck = ck;
    this.mixHash(h);
    this.#cipher = this.#cipherState(k);
  }

  encryptAndHash(plaintext: Uint8Array): Uint8Array<ArrayBuffer> {
    const ciphertext = this.#cipher?.encryptWithAd(this.#h, plaintext) ?? copyBytes(plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }

  decryptAndHash(ciphertext: Uint8Array): Uint8Array<ArrayBuffer> {
    const plaintext = this.#cipher?.decryptWithAd(this.#h, ciphertext) ?? copyBytes(ciphertext);
    this.mixHash(ciphertext);
    return plaintext;
  }

  split(): [CipherState, CipherState] {
    const [k1, k2] = this.#hkdf(new Uint8Array(), 2);
    return [this.#cipherState(k1), this.#cipherState(k2)];
  }

  #hkdf(inputKeyMaterial: Uint8Array, outputs: number): Uint8Array[] {
    const length = this.#hash.outputLen;
    const okm = hkdf(this.#hash, inputKeyMaterial, this.#ck, undefined, outputs * length);
    return Array.from({ length: outputs }, (_, i) => okm.slice(i * length, (i + 1) * length));
  }

  #cipherState(k: Uint8Array): CipherState {
    return new CipherState(this.#cipherName, k.subarray(0, KEY_LENGTH));
  }
}
