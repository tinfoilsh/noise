import { abytes } from "@noble/hashes/utils.js";
import { NoiseError } from "./errors.js";
import { type CipherState, EMPTY, TAG_LENGTH } from "./state.js";

/** The maximum length in bytes of any Noise message, handshake or transport (Noise spec section 3). */
export const MAX_MESSAGE_LENGTH = 65535;

/**
 * The transport phase of a completed handshake, created by `Handshake.intoTransport()`.
 *
 * Each direction uses an internal nonce, so messages must be read in the order they were written,
 * with none missing. The caller is responsible for framing and delivery.
 */
export class Transport {
  readonly #send: CipherState | undefined;
  readonly #receive: CipherState | undefined;
  readonly #handshakeHash: Uint8Array;
  readonly #remoteStaticPublicKey: Uint8Array | undefined;

  /** @internal */
  constructor(
    send: CipherState | undefined,
    receive: CipherState | undefined,
    handshakeHash: Uint8Array,
    remoteStaticPublicKey: Uint8Array | undefined,
  ) {
    this.#send = send;
    this.#receive = receive;
    this.#handshakeHash = handshakeHash;
    this.#remoteStaticPublicKey = remoteStaticPublicKey;
  }

  /**
   * A copy of the final handshake hash, which uniquely identifies the session and can be used for
   * channel binding.
   *
   * @see https://noiseprotocol.org/noise.html#channel-binding
   */
  get handshakeHash(): Uint8Array<ArrayBuffer> {
    return this.#handshakeHash.slice();
  }

  /**
   * A copy of the peer's static public key, or `undefined` if the pattern does not provide one. The
   * peer has proven it holds the private key only once this party has read a message whose key depends
   * on a DH with that key. In some patterns that is the peer's first transport message (e.g. IX and X1N
   * for the responder, XX1 for the initiator), and one-way initiators never get that proof. The caller
   * decides whether to trust the key.
   */
  get remoteStaticPublicKey(): Uint8Array<ArrayBuffer> | undefined {
    return this.#remoteStaticPublicKey?.slice();
  }

  /**
   * Encrypts `payload` into the next transport message, with empty associated data. Throws if this
   * party is the responder of a one-way pattern or the message would exceed 65535 bytes.
   */
  writeMessage(payload: Uint8Array = EMPTY): Uint8Array<ArrayBuffer> {
    abytes(payload, undefined, "payload");
    if (!this.#send) throw new NoiseError("invalid-state", "the responder of a one-way Noise pattern cannot send");
    if (payload.length + TAG_LENGTH > MAX_MESSAGE_LENGTH) {
      throw new NoiseError("invalid-length", "Noise message too long");
    }
    return this.#send.encryptWithAd(EMPTY, payload);
  }

  /**
   * Decrypts the next transport message and returns its payload. Throws if this party is the initiator
   * of a one-way pattern, the message length is invalid, or authentication fails. A failed
   * authentication leaves the nonce unchanged.
   */
  readMessage(message: Uint8Array): Uint8Array<ArrayBuffer> {
    abytes(message, undefined, "message");
    if (!this.#receive) {
      throw new NoiseError("invalid-state", "the initiator of a one-way Noise pattern cannot receive");
    }
    if (message.length < TAG_LENGTH || message.length > MAX_MESSAGE_LENGTH) {
      throw new NoiseError("invalid-length", "invalid Noise message length");
    }
    return this.#receive.decryptWithAd(EMPTY, message);
  }
}
