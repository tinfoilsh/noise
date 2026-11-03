import { NoiseError } from "./errors.js";

export type DhToken = "ee" | "es" | "se" | "ss";
/** Carries its modifier position, e.g. `{ psk: 2 }` for `psk2`. */
export type PskToken = { readonly psk: number };
export type Token = "e" | "s" | DhToken | PskToken;

export interface Pattern {
  readonly protocol: string;
  readonly initiatorPreMessage: boolean;
  readonly responderPreMessage: boolean;
  /** Token lists, alternating from the initiator, with PSK modifiers applied. */
  readonly messages: readonly (readonly Token[])[];
  readonly pskPositions: readonly number[];
}

// Initiator pre-message, responder pre-message, then messages from the Noise spec (rev. 34) sections 7.4, 7.5 and 18.1.
const PATTERNS: Readonly<Record<string, readonly string[]>> = {
  N: ["", "s", "e es"],
  K: ["s", "s", "e es ss"],
  X: ["", "s", "e es s ss"],
  NN: ["", "", "e", "e ee"],
  NK: ["", "s", "e es", "e ee"],
  NX: ["", "", "e", "e ee s es"],
  XN: ["", "", "e", "e ee", "s se"],
  XK: ["", "s", "e es", "e ee", "s se"],
  XX: ["", "", "e", "e ee s es", "s se"],
  KN: ["s", "", "e", "e ee se"],
  KK: ["s", "s", "e es ss", "e ee se"],
  KX: ["s", "", "e", "e ee se s es"],
  IN: ["", "", "e s", "e ee se"],
  IK: ["", "s", "e es s ss", "e ee se"],
  IX: ["", "", "e s", "e ee se s es"],
  NK1: ["", "s", "e", "e ee es"],
  NX1: ["", "", "e", "e ee s", "es"],
  X1N: ["", "", "e", "e ee", "s", "se"],
  X1K: ["", "s", "e es", "e ee", "s", "se"],
  XK1: ["", "s", "e", "e ee es", "s se"],
  X1K1: ["", "s", "e", "e ee es", "s", "se"],
  X1X: ["", "", "e", "e ee s es", "s", "se"],
  XX1: ["", "", "e", "e ee s", "es s se"],
  X1X1: ["", "", "e", "e ee s", "es s", "se"],
  K1N: ["s", "", "e", "e ee", "se"],
  K1K: ["s", "s", "e es", "e ee", "se"],
  KK1: ["s", "s", "e", "e ee se es"],
  K1K1: ["s", "s", "e", "e ee es", "se"],
  K1X: ["s", "", "e", "e ee s es", "se"],
  KX1: ["s", "", "e", "e ee se s", "es"],
  K1X1: ["s", "", "e", "e ee s", "se es"],
  I1N: ["", "", "e s", "e ee", "se"],
  I1K: ["", "s", "e es s", "e ee", "se"],
  IK1: ["", "s", "e s", "e ee se es"],
  I1K1: ["", "s", "e s", "e ee es", "se"],
  I1X: ["", "", "e s", "e ee s es", "se"],
  IX1: ["", "", "e s", "e ee se s", "es"],
  I1X1: ["", "", "e s", "e ee s", "se es"],
};

const PROTOCOL = /^Noise_([A-Z0-9]+)([a-z0-9+]*)_25519_ChaChaPoly_BLAKE2s$/;
const PSK_MODIFIER = /^psk(0|[1-9][0-9]*)$/;

/**
 * Parses a protocol name into its handshake pattern with PSK modifiers applied. Only patterns in the table
 * are supported, and PSK modifiers must be sorted, distinct, and in range (Noise spec sections 8.1 and 9).
 */
export function parsePattern(protocol: string): Pattern {
  const [, base = "", modifiers = ""] = PROTOCOL.exec(protocol) ?? [];
  if (!Object.hasOwn(PATTERNS, base)) throw new NoiseError("unsupported", `unsupported Noise protocol: ${protocol}`);
  const [initiatorPreMessage, responderPreMessage, ...messages] = PATTERNS[base];
  const tokens = messages.map((message) => message.split(" ") as Token[]);
  const pskPositions: number[] = [];
  for (const modifier of modifiers === "" ? [] : modifiers.split("+")) {
    const digits = PSK_MODIFIER.exec(modifier)?.[1];
    const position = Number(digits);
    if (digits === undefined || position <= (pskPositions.at(-1) ?? -1) || position > tokens.length) {
      throw new NoiseError("unsupported", `unsupported Noise modifiers: ${protocol}`);
    }
    pskPositions.push(position);
    if (position === 0) tokens[0].unshift({ psk: position });
    else tokens[position - 1].push({ psk: position });
  }
  return {
    protocol,
    initiatorPreMessage: initiatorPreMessage === "s",
    responderPreMessage: responderPreMessage === "s",
    messages: tokens,
    pskPositions,
  };
}
