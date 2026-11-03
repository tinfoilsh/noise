/**
 * Noise Protocol Framework handshakes and transports for `Noise_*_25519_ChaChaPoly_BLAKE2s`.
 *
 * @see https://noiseprotocol.org/noise.html
 * @packageDocumentation
 */
export { NoiseError, type NoiseErrorCode } from "./errors.js";
export { generateKeypair, Handshake, type HandshakeOptions, type Keypair } from "./handshake.js";
export type { Transport } from "./transport.js";
