import { x25519 } from "@noble/curves/ed25519.js";
import { abytes, concatBytes, copyBytes } from "@noble/hashes/utils.js";
import { NoiseError } from "./errors.js";
import { type DhToken, parsePattern, type PskToken, type Token } from "./patterns.js";
import { EMPTY, SymmetricState, TAG_LENGTH } from "./state.js";
import { MAX_MESSAGE_LENGTH, Transport } from "./transport.js";

const DH_LENGTH = 32;
const PSK_LENGTH = 32;

export interface HandshakeOptions {
  /** The exact protocol name, e.g. `Noise_XX_25519_ChaChaPoly_BLAKE2s` or `Noise_NNpsk0+psk2_25519_ChaChaPoly_BLAKE2s`. */
  readonly protocol: `Noise_${string}_25519_ChaChaPoly_BLAKE2s`;
  /** Data mixed into the handshake hash. Both parties must use the same prologue. Defaults to empty. */
  readonly prologue?: Uint8Array | undefined;
  /** This party's X25519 static private key. Required if and only if the pattern uses one for this role. */
  readonly staticPrivateKey?: Uint8Array | undefined;
  /** The peer's X25519 static public key. Required if and only if the pattern pre-shares it with this role. */
  readonly remoteStaticPublicKey?: Uint8Array | undefined;
  /** 32-byte PSKs keyed by modifier position, e.g. `{ 0: a, 2: b }` for `psk0+psk2`. */
  readonly psks?: Readonly<Record<number, Uint8Array>> | undefined;
}

/** An X25519 keypair, as returned by {@link generateKeypair}. */
export interface Keypair {
  readonly privateKey: Uint8Array<ArrayBuffer>;
  readonly publicKey: Uint8Array<ArrayBuffer>;
}

/** Generates an X25519 static key pair from a secure random source. */
export function generateKeypair(): Keypair {
  const { secretKey, publicKey } = x25519.keygen();
  return { privateKey: secretKey, publicKey };
}

interface Secrets {
  readonly symmetric: SymmetricState;
  readonly s: Keypair | undefined;
  readonly psks: Readonly<Record<number, Uint8Array>>;
  rs: Uint8Array | undefined;
  e?: Keypair;
  re?: Uint8Array;
}

/**
 * A state machine for one party's side of a `Noise_<pattern>_25519_ChaChaPoly_BLAKE2s` handshake.
 *
 * Messages must be written and read in the order the pattern defines; once `isFinished` is true,
 * `intoTransport()` returns the session's `Transport`. Calling out of turn or after the handshake
 * finished throws without changing state. Any other failure, such as an invalid message length, a
 * tampered message, or an invalid peer key, permanently invalidates the handshake.
 *
 * @see https://noiseprotocol.org/noise.html#the-handshakestate-object
 */
export class Handshake {
  readonly #initiator: boolean;
  readonly #messages: readonly (readonly Token[])[];
  readonly #pskMode: boolean;
  #position = 0;
  #secrets: Secrets | undefined;

  /**
   * Starts a handshake as the initiator, which sends the first message.
   * Throws if the protocol is unsupported or the options do not match its pattern.
   */
  static initiator(options: HandshakeOptions): Handshake {
    return new Handshake(true, options);
  }

  /**
   * Starts a handshake as the responder, which receives the first message.
   * Throws if the protocol is unsupported or the options do not match its pattern.
   */
  static responder(options: HandshakeOptions): Handshake {
    return new Handshake(false, options);
  }

  private constructor(initiator: boolean, options: HandshakeOptions) {
    const pattern = parsePattern(options.protocol);
    const [localPreMessage, remotePreMessage] = initiator
      ? [pattern.initiatorPreMessage, pattern.responderPreMessage]
      : [pattern.responderPreMessage, pattern.initiatorPreMessage];
    const sendsStatic = pattern.messages.some((tokens, i) => i % 2 === (initiator ? 0 : 1) && tokens.includes("s"));
    const key = (name: string, value: Uint8Array | undefined, required: boolean) => {
      if (required !== (value !== undefined)) {
        const role = initiator ? "initiator" : "responder";
        const message = `${pattern.protocol} ${required ? "requires" : "does not use"} ${name} for the ${role}`;
        throw new NoiseError("invalid-options", message);
      }
      return value && copyBytes(abytes(value, DH_LENGTH, name));
    };
    const staticPrivateKey = key("staticPrivateKey", options.staticPrivateKey, localPreMessage || sendsStatic);
    const rs = key("remoteStaticPublicKey", options.remoteStaticPublicKey, remotePreMessage);
    const psks = options.psks ?? {};
    if (Object.keys(psks).length !== pattern.pskPositions.length) {
      const message = `${pattern.protocol} requires PSKs exactly at positions [${pattern.pskPositions}]`;
      throw new NoiseError("invalid-options", message);
    }
    const s = staticPrivateKey && { privateKey: staticPrivateKey, publicKey: x25519.getPublicKey(staticPrivateKey) };
    const symmetric = new SymmetricState(pattern.protocol);
    symmetric.mixHash(abytes(options.prologue ?? EMPTY, undefined, "prologue"));
    const preMessages = [localPreMessage ? s?.publicKey : undefined, rs];
    for (const preMessage of initiator ? preMessages : preMessages.reverse()) {
      if (preMessage) symmetric.mixHash(preMessage);
    }
    this.#initiator = initiator;
    this.#messages = pattern.messages;
    this.#pskMode = pattern.pskPositions.length > 0;
    this.#secrets = {
      symmetric,
      s,
      rs,
      psks: Object.fromEntries(pattern.pskPositions.map((p) => [p, copyBytes(abytes(psks[p], PSK_LENGTH, `psk${p}`))])),
    };
  }

  /** Whether the next handshake call is `writeMessage()`; false once the handshake is no longer usable. */
  get isMyTurn(): boolean {
    return this.#secrets !== undefined && !this.isFinished && this.#position % 2 === (this.#initiator ? 0 : 1);
  }

  /** Whether every handshake message has been exchanged, so `intoTransport()` may be called. */
  get isFinished(): boolean {
    return this.#position === this.#messages.length;
  }

  /**
   * A copy of the peer's static public key, or `undefined` if the pattern provides none, it has not
   * been received yet, or the handshake is no longer usable. The caller is responsible for deciding
   * whether to trust it.
   */
  get remoteStaticPublicKey(): Uint8Array<ArrayBuffer> | undefined {
    return this.#secrets?.rs?.slice();
  }

  /**
   * Writes the next handshake message with `payload`, which is sent in the clear if the pattern has not
   * yet derived a key. Throws if it is not this party's turn or the message would exceed 65535 bytes.
   */
  writeMessage(payload: Uint8Array = EMPTY): Uint8Array<ArrayBuffer> {
    abytes(payload, undefined, "payload");
    const secrets = this.#next(true);
    return this.#step(() => {
      const parts: Uint8Array[] = [];
      for (const token of this.#messages[this.#position]) {
        if (token === "e") {
          secrets.e = generateKeypair();
          this.#mixEphemeral(secrets, secrets.e.publicKey);
          parts.push(secrets.e.publicKey);
        } else if (token === "s") {
          parts.push(secrets.symmetric.encryptAndHash(secrets.s!.publicKey));
        } else {
          this.#mixSecret(secrets, token);
        }
      }
      const message = concatBytes(...parts, secrets.symmetric.encryptAndHash(payload));
      if (message.length > MAX_MESSAGE_LENGTH) throw new NoiseError("invalid-length", "Noise message too long");
      return message;
    });
  }

  /**
   * Reads the next handshake message and returns its payload.
   * Throws if it is not this party's turn or the message length is invalid for this step.
   */
  readMessage(message: Uint8Array): Uint8Array<ArrayBuffer> {
    abytes(message, undefined, "message");
    const secrets = this.#next(false);
    return this.#step(() => {
      if (message.length > MAX_MESSAGE_LENGTH) throw new NoiseError("invalid-length", "Noise message too long");
      const { symmetric } = secrets;
      let offset = 0;
      const take = (length: number) => {
        if (offset + length > message.length) throw new NoiseError("invalid-length", "Noise message too short");
        return message.subarray(offset, (offset += length));
      };
      for (const token of this.#messages[this.#position]) {
        if (token === "e") {
          secrets.re = copyBytes(take(DH_LENGTH));
          this.#mixEphemeral(secrets, secrets.re);
        } else if (token === "s") {
          secrets.rs = symmetric.decryptAndHash(take(DH_LENGTH + (symmetric.hasKey ? TAG_LENGTH : 0)));
        } else {
          this.#mixSecret(secrets, token);
        }
      }
      return symmetric.decryptAndHash(message.subarray(offset));
    });
  }

  /**
   * Converts the finished handshake into its `Transport`. Throws if the handshake is not finished;
   * after a successful call, the handshake is unusable.
   */
  intoTransport(): Transport {
    const { symmetric, rs } = this.#live();
    if (!this.isFinished) throw new NoiseError("invalid-state", "Noise handshake not finished");
    this.#secrets = undefined;
    const [initiatorToResponder, responderToInitiator] = symmetric.split();
    // One-way patterns discard the second CipherState (Noise spec section 7.4).
    const reply = this.#messages.length > 1 ? responderToInitiator : undefined;
    return this.#initiator
      ? new Transport(initiatorToResponder, reply, symmetric.handshakeHash, rs)
      : new Transport(reply, initiatorToResponder, symmetric.handshakeHash, rs);
  }

  #live(): Secrets {
    if (!this.#secrets) throw new NoiseError("invalid-state", "Noise handshake is no longer usable");
    return this.#secrets;
  }

  #next(writing: boolean): Secrets {
    const secrets = this.#live();
    if (this.isFinished) throw new NoiseError("invalid-state", "Noise handshake already finished");
    if (this.isMyTurn !== writing) {
      throw new NoiseError("invalid-state", `not this party's turn to ${writing ? "write" : "read"}`);
    }
    return secrets;
  }

  #step<T>(run: () => T): T {
    try {
      const result = run();
      this.#position++;
      return result;
    } catch (error) {
      this.#secrets = undefined;
      throw error;
    }
  }

  // PSK handshakes also mix every ephemeral into the key (Noise spec section 9.2).
  #mixEphemeral({ symmetric }: Secrets, publicKey: Uint8Array): void {
    symmetric.mixHash(publicKey);
    if (this.#pskMode) symmetric.mixKey(publicKey);
  }

  #mixSecret(secrets: Secrets, token: DhToken | PskToken): void {
    if (typeof token === "object") secrets.symmetric.mixKeyAndHash(secrets.psks[token.psk]);
    else secrets.symmetric.mixKey(this.#dh(secrets, token));
  }

  #dh({ e, s, re, rs }: Secrets, token: DhToken): Uint8Array {
    const pairs: Record<DhToken, [Keypair | undefined, Uint8Array | undefined]> = {
      ee: [e, re],
      ss: [s, rs],
      es: this.#initiator ? [e, rs] : [s, re],
      se: this.#initiator ? [s, re] : [e, rs],
    };
    const [local, remote] = pairs[token];
    try {
      return x25519.getSharedSecret(local!.privateKey, remote!);
    } catch (cause) {
      throw new NoiseError("invalid-key", "Noise DH rejected an invalid public key", { cause });
    }
  }
}
