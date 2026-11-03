import { afterAll, describe, expect, spyOn, test } from "bun:test";
import { readFileSync } from "node:fs";
import { x25519 } from "@noble/curves/ed25519.js";
import { bytesToHex as hex, hexToBytes as bytes } from "@noble/hashes/utils.js";
import { Handshake, type HandshakeOptions } from "../src/handshake.ts";

const random = spyOn(crypto, "getRandomValues");
afterAll(() => random.mockRestore());
// A party's ephemeral is the first random draw of its first message; noble's later blinding draws stay real.
const fixEphemeral = (privateKey: string) =>
  random.mockImplementationOnce((array) => (new Uint8Array(array!.buffer).set(bytes(privateKey)), array));

type Role = "init" | "resp";
type Vector = {
  protocol_name: HandshakeOptions["protocol"];
  handshake_hash?: string;
  messages: { payload: string; ciphertext: string }[];
} & {
  [K in `${Role}_${"prologue" | "static" | "ephemeral" | "remote_static"}`]?: string;
} & { [K in `${Role}_psks`]?: string[] };

const load = (file: string): Vector[] =>
  JSON.parse(readFileSync(new URL(`vectors/${file}`, import.meta.url), "utf8")).vectors;
const optional = (value: string | undefined) => (value === undefined ? undefined : bytes(value));

function party(v: Vector, role: Role): Handshake {
  const positions = [...v.protocol_name.matchAll(/psk(\d+)/g)].map((m) => Number(m[1]));
  const options = {
    protocol: v.protocol_name,
    prologue: bytes(v[`${role}_prologue`]!),
    staticPrivateKey: optional(v[`${role}_static`]),
    remoteStaticPublicKey: optional(v[`${role}_remote_static`]),
    psks: Object.fromEntries(positions.map((position, i) => [position, bytes(v[`${role}_psks`]![i]!)])),
  };
  return role === "init" ? Handshake.initiator(options) : Handshake.responder(options);
}

const publicKey = (privateKey: string | undefined) => privateKey && hex(x25519.getPublicKey(bytes(privateKey)));

function replay(v: Vector) {
  const initiator = party(v, "init");
  const responder = party(v, "resp");
  const oneWay = /^Noise_[NKX](psk|_)/.test(v.protocol_name);
  let i = 0;
  for (; !initiator.isFinished; i++) {
    const [writer, reader] = i % 2 === 0 ? [initiator, responder] : [responder, initiator];
    const ephemeral = v[`${i % 2 === 0 ? "init" : "resp"}_ephemeral`];
    if (i < 2 && ephemeral) fixEphemeral(ephemeral);
    const { payload, ciphertext } = v.messages[i]!;
    expect(hex(writer.writeMessage(bytes(payload)))).toBe(ciphertext);
    expect(hex(reader.readMessage(bytes(ciphertext)))).toBe(payload);
  }
  expect(responder.isFinished).toBe(true);
  const sessions = [initiator.intoTransport(), responder.intoTransport()] as const;
  expect(hex(sessions[1].handshakeHash)).toBe(hex(sessions[0].handshakeHash));
  if (v.handshake_hash) expect(hex(sessions[0].handshakeHash)).toBe(v.handshake_hash);
  expect(sessions[0].remoteStaticPublicKey && hex(sessions[0].remoteStaticPublicKey)).toBe(publicKey(v.resp_static));
  expect(sessions[1].remoteStaticPublicKey && hex(sessions[1].remoteStaticPublicKey)).toBe(publicKey(v.init_static));
  for (; i < v.messages.length; i++) {
    const [writer, reader] = oneWay || i % 2 === 0 ? sessions : [sessions[1], sessions[0]];
    const { payload, ciphertext } = v.messages[i]!;
    expect(hex(writer.writeMessage(bytes(payload)))).toBe(ciphertext);
    expect(hex(reader.readMessage(bytes(ciphertext)))).toBe(payload);
  }
}

describe.each([
  ["snow.json", 51],
  ["cacophony.json", 59],
] as const)("%s, both roles", (file, count) => {
  const vectors = load(file);
  test("has every vector", () => expect(vectors.length).toBe(count));
  for (const v of vectors) test(v.protocol_name, () => replay(v));
});

describe("monitor NK vectors, initiator only", () => {
  const vectors = [...load("noise-nk-published.json"), ...load("noise-nk-flynn.json")];
  test("has every vector", () => expect(vectors.length).toBe(270));
  vectors.forEach((v, n) =>
    test(`${n}: ${v.messages.length} messages`, () => {
      const handshake = Handshake.initiator({
        protocol: v.protocol_name,
        prologue: bytes(v.init_prologue!),
        remoteStaticPublicKey: bytes(v.init_remote_static!),
      });
      fixEphemeral(v.init_ephemeral!);
      const [first, reply, ...rest] = v.messages;
      expect(hex(handshake.writeMessage(bytes(first!.payload)))).toBe(first!.ciphertext);
      expect(hex(handshake.readMessage(bytes(reply!.ciphertext)))).toBe(reply!.payload);
      const transport = handshake.intoTransport();
      if (v.handshake_hash) expect(hex(transport.handshakeHash)).toBe(v.handshake_hash);
      rest.forEach(({ payload, ciphertext }, i) => {
        if (i % 2 === 0) expect(hex(transport.writeMessage(bytes(payload)))).toBe(ciphertext);
        else expect(hex(transport.readMessage(bytes(ciphertext)))).toBe(payload);
      });
    }),
  );
});
