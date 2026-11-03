export type NoiseErrorCode =
  | "unsupported"
  | "invalid-options"
  | "invalid-state"
  | "invalid-length"
  | "invalid-key"
  | "decrypt-failed"
  | "nonce-exhausted";

/**
 * Raised for every Noise failure, with a `code` callers can branch on:
 * - `unsupported`: the protocol name or its modifiers are not supported
 * - `invalid-options`: the options do not match the pattern
 * - `invalid-state`: the call is out of turn, premature, or on a finished or failed object
 * - `invalid-length`: a message or payload is outside the Noise length limits
 * - `invalid-key`: DH rejected a public key, such as a low-order point
 * - `decrypt-failed`: a message failed authentication
 * - `nonce-exhausted`: the cipher state has used every nonce
 *
 * Arguments of the wrong type or length throw `TypeError` or `RangeError` instead.
 */
export class NoiseError extends Error {
  readonly code: NoiseErrorCode;

  constructor(code: NoiseErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "NoiseError";
    this.code = code;
  }
}
