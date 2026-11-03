# alias

A Noise Protocol implementation built on top of @noble/ciphers, @noble/curves, and @noble/hashes.

The goal is to provide a general-purpose browser-compatible implementation of Noise with
minimal papercuts, using only well-audited JavaScript components.

In particular, this is inspired by snow's representation of the Noise state machine.

- Handshakes are first *constructed*, keys are *exchanged* and then handles are *consumed* to be turned into a transport.
- Failed handshakes fail closed.
- Only `Noise_*_25519_ChaChaPoly_BLAKE2s` support, for now.

