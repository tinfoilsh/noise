/**
 * Noise Protocol Framework handshakes and transports for `Noise_*_25519_<ChaChaPoly|AESGCM>_<BLAKE2s|BLAKE2b|SHA256|SHA512>`.
 *
 * @see https://noiseprotocol.org/noise.html
 * @packageDocumentation
 */
export { NoiseError, type NoiseErrorCode } from "./errors.js";
export { generateKeypair, Handshake, type HandshakeOptions, type Keypair } from "./handshake.js";
export type { Transport } from "./transport.js";
