import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { blake2s } from "@noble/hashes/blake2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { concatBytes, copyBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { NoiseError } from "./errors.js";

export const TAG_LENGTH = 16;
export const EMPTY = new Uint8Array();
const HASH_LENGTH = 32;
const NONCE_LENGTH = 12;
// ChaChaPoly nonces are 4 zero bytes followed by the little-endian counter (Noise spec section 12.3).
const COUNTER_OFFSET = 4;
// 2^64-1 is reserved and may not be used as a nonce (Noise spec section 5.1).
const RESERVED_NONCE = 2n ** 64n - 1n;

/** A keyed ChaChaPoly CipherState (Noise spec section 5.1). */
export class CipherState {
  readonly #key: Uint8Array;
  #n: bigint;

  constructor(key: Uint8Array, n = 0n) {
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
    new DataView(nonce.buffer).setBigUint64(COUNTER_OFFSET, this.#n, true);
    return chacha20poly1305(this.#key, nonce, ad);
  }
}

/** The BLAKE2s SymmetricState (Noise spec section 5.2). An absent CipherState represents the spec's empty key. */
export class SymmetricState {
  #ck: Uint8Array;
  #h: Uint8Array;
  #cipher: CipherState | undefined;

  constructor(protocol: string) {
    const name = utf8ToBytes(protocol);
    if (name.length <= HASH_LENGTH) {
      this.#h = new Uint8Array(HASH_LENGTH);
      this.#h.set(name);
    } else {
      this.#h = blake2s(name);
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
    this.#cipher = new CipherState(k);
  }

  mixHash(data: Uint8Array): void {
    this.#h = blake2s(concatBytes(this.#h, data));
  }

  mixKeyAndHash(inputKeyMaterial: Uint8Array): void {
    const [ck, h, k] = this.#hkdf(inputKeyMaterial, 3);
    this.#ck = ck;
    this.mixHash(h);
    this.#cipher = new CipherState(k);
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
    return [new CipherState(k1), new CipherState(k2)];
  }

  #hkdf(inputKeyMaterial: Uint8Array, outputs: number): Uint8Array[] {
    const okm = hkdf(blake2s, inputKeyMaterial, this.#ck, undefined, outputs * HASH_LENGTH);
    return Array.from({ length: outputs }, (_, i) => okm.slice(i * HASH_LENGTH, (i + 1) * HASH_LENGTH));
  }
}
