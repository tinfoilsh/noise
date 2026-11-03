// Runs an XX handshake between two in-process parties: `bun examples/xx.ts`.
// A real application sends each message over a framed channel.
import { equalBytes } from "@noble/ciphers/utils.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { generateKeypair, Handshake } from "../src/index.ts";

const protocol = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const prologue = utf8ToBytes("example-app v1");
const [client, server] = [generateKeypair(), generateKeypair()];
const trustedServerKey = server.publicKey;

const initiator = Handshake.initiator({ protocol, prologue, staticPrivateKey: client.privateKey });
const responder = Handshake.responder({ protocol, prologue, staticPrivateKey: server.privateKey });

// -> e
responder.readMessage(initiator.writeMessage());
// <- e, ee, s, es
initiator.readMessage(responder.writeMessage());
// XX authenticates the server key but does not establish trust in it; verify it before sending the client key.
if (!equalBytes(initiator.remoteStaticPublicKey!, trustedServerKey)) throw new Error("untrusted server key");
// -> s, se
responder.readMessage(initiator.writeMessage());

const [clientSession, serverSession] = [initiator.intoTransport(), responder.intoTransport()];
const reply = clientSession.readMessage(serverSession.writeMessage(utf8ToBytes("hello, client")));
console.log(new TextDecoder().decode(reply));
console.log("channel binding:", equalBytes(clientSession.handshakeHash, serverSession.handshakeHash));
