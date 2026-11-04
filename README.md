# @tinfoilsh/noise

> NOTE: This library has not been audited.

A Noise Protocol (revision 34) implementation built on top of @noble/ciphers, @noble/curves, and @noble/hashes.

The goal is to provide a general-purpose browser-compatible implementation of Noise with
minimal papercuts, using only well-audited JavaScript crypto.

In particular, this is inspired by snow's representation of the Noise state machine.

- Handshakes are first *constructed*, keys are *exchanged* and then handles are *consumed* to be turned into a transport.
- Failed handshakes fail closed.

Component matrix:
- DH: Curve25519 (X25519). Unsupported: Curve448
- AEAD: ChaCha20-Poly1305. Unsupported: AES-256-GCM
- Hashes: BLAKE2s. Unsupported: SHA-256, SHA-512, BLAKE2b
- Patterns: All 3 one-way (N, K, X), all 12 fundamental interactive, all 23 deferred patterns. Unsupported: custom patterns
- Modifiers: pskN, alone or combined (e.g. NNpsk0, XXpsk3, NNpsk0+psk2, XXpsk0+psk1+psk2+psk3). Unsupported: fallback, hfs
- Additional features (unsupported for now): rekeying, out-of-order transport.

## Example usage

``` typescript
import { generateKeypair, Handshake } from "@tinfoilsh/noise";

const server = generateKeypair();
const initiator = Handshake.initiator({ protocol: "Noise_NK_25519_ChaChaPoly_BLAKE2s", remoteStaticPublicKe: server.publicKey })
const responder = Handshake.initiator({ protocol: "Noise_NK_25519_ChaChaPoly_BLAKE2s", remoteStaticPublicKe: server. privateKey })

responder.readMessage(initiator.writeMessage()) // -> e, es
initiator.readMessage(responder.writeMessage()) // <- e, ee

const client = initiator.intoTransport();
const session = responder.intoTransport();
session.readMessage(client.writeMessage(new TextEncoder().encode("hello")))
```

Tested (and passed) against every `Noise_*_25519_ChaChaPoly_BLAKE2s` test vector in snow's snow.txt, cacophony.txt, and noise-c-basic.txt, plus 270 initiator-side Noise_NK vectors from cacophony, snow, dissononce, and flynn/noise.
