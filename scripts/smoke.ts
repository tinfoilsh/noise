// Packs the build, installs the tarball into a scratch project, then imports it from Node and type-checks a consumer.
import { mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const dir = mkdtempSync(join(tmpdir(), "noise-smoke-"));
const run = (cwd: string, ...cmd: string[]) => {
  if (!Bun.spawnSync(cmd, { cwd, stdout: "inherit", stderr: "inherit" }).success) throw new Error(cmd.join(" "));
};

run(root, "bun", "pm", "pack", "--quiet", "--destination", dir);
const tarball = readdirSync(dir).find((file) => file.endsWith(".tgz"))!;
const files: Record<string, string> = {
  "package.json": JSON.stringify({ type: "module", dependencies: { "@tinfoilsh/noise": `file:./${tarball}` } }),
  "tsconfig.json": JSON.stringify({
    compilerOptions: { strict: true, module: "nodenext", target: "es2022", lib: ["es2022"], types: [], noEmit: true },
    files: ["consumer.ts"],
  }),
  "consumer.mjs": `
    import assert from "node:assert/strict";
    import * as noise from "@tinfoilsh/noise";
    assert.deepEqual(Object.keys(noise).sort(), ["Handshake", "NoiseError", "generateKeypair"]);
    await assert.rejects(import("@tinfoilsh/noise/dist/index.js"), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
    const protocol = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
    const [client, server] = [noise.generateKeypair(), noise.generateKeypair()];
    const initiator = noise.Handshake.initiator({ protocol, staticPrivateKey: client.privateKey });
    const responder = noise.Handshake.responder({ protocol, staticPrivateKey: server.privateKey });
    responder.readMessage(initiator.writeMessage());
    initiator.readMessage(responder.writeMessage());
    responder.readMessage(initiator.writeMessage());
    const [a, b] = [initiator.intoTransport(), responder.intoTransport()];
    assert.deepEqual(b.readMessage(a.writeMessage(new Uint8Array([1, 2, 3]))), new Uint8Array([1, 2, 3]));
    assert.deepEqual(b.remoteStaticPublicKey, client.publicKey);
    console.log("node import ok");
  `,
  "consumer.ts": `
    import { Handshake, type HandshakeOptions, type Transport } from "@tinfoilsh/noise";
    const options: HandshakeOptions = { protocol: "Noise_NN_25519_ChaChaPoly_BLAKE2s" };
    const transport: Transport = Handshake.initiator(options).intoTransport();
    const hash: Uint8Array<ArrayBuffer> = transport.handshakeHash;
    // @ts-expect-error Transport is exported as a type only
    new Transport();
  `,
};
for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
run(dir, "bun", "install", "--silent");
run(dir, "node", "consumer.mjs");
run(dir, join(root, "node_modules/.bin/tsc"), "-p", ".");
console.log(`declarations ok (${dir})`);
