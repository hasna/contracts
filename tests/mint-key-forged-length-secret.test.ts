// A SIGNING SECRET THAT LIES ABOUT ITS OWN LENGTH MUST NOT MINT.
//
// `toBuffer` used to open with `Buffer.isBuffer(secret)` and return the
// CALLER'S OBJECT unconverted. `Buffer.isBuffer` is `instanceof`-based, but the
// brand was never the lie here: the object genuinely WAS a `Buffer`. The lie was
// `length`, which is an accessor on `%TypedArray%.prototype` and is therefore
// shadowed by an own property defined on the instance.
//
// The two halves then disagreed about the same value. `mintApiKey`'s entropy
// floor reads `secret.length` and saw 4096; `createHmac` reads the internal
// slots and keyed with the four real bytes. Measured on `b518f81a`:
//
//   FORGED length data-property = 4096
//     -> MINTED  keyedWith4=true  keyedWith32=false
//
// WHAT "MINTED" MEANS IN THIS FILE, because the weaker reading is what makes a
// test like this vacuous: not that `mintApiKey` returned, but that the returned
// token's signature REPRODUCES under an HMAC keyed with the bytes the input
// really carried. A test that only asserts "did not throw" cannot tell "signed
// with four bytes" from "signed with something else that also did not throw".
//
// TWO TRAPS THIS FILE DELIBERATELY AVOIDS.
//
//  1. HMAC ZERO-PADS any key shorter than its 64-byte block, so `[1,2,3,4]` and
//     those same four bytes followed by twelve zeros ARE THE SAME KEY. A
//     "different key" control built by zero-extending the short key therefore
//     proves nothing. `GENUINE_32` below is all high bytes for exactly that
//     reason, and `the zero-padding trap` test pins the fact so nobody
//     reintroduces the mistake.
//  2. The floor this protects is a LENGTH floor, not an entropy measure. It
//     counts bytes; it cannot assess their quality, and sixteen identical bytes
//     pass it. Nothing here should be read as claiming otherwise.

import { describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mintApiKey, verifyApiKeyToken } from "../src/auth/keys";

const APP = "todos";
const SCOPES = ["todos:read"];

/** The four real bytes every forged shape below actually carries. */
const REAL_FOUR = Buffer.from([1, 2, 3, 4]);

/**
 * A genuine 32-byte key. Every byte is >= 0x40, so it cannot stand in a
 * zero-padding relationship to `REAL_FOUR` — see trap 1 in the header.
 */
const GENUINE_32 = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x40 + i));

function splitToken(token: string): { signingInput: string; sig: string } {
  const dot = token.lastIndexOf(".");
  return { signingInput: token.slice(0, dot), sig: token.slice(dot + 1) };
}

/** base64url HMAC-SHA256 — the reference computation the token must match. */
function refSig(key: Buffer, message: string): string {
  return createHmac("sha256", key).update(message, "utf8").digest("base64url");
}

/** A REAL four-byte `Buffer` whose own `length` claims 4096. */
function forgedLengthDataProperty(): Buffer {
  const b = Buffer.from(REAL_FOUR);
  Object.defineProperty(b, "length", { value: 4096, configurable: true });
  return b;
}

/** The same lie told by a getter rather than a data property. */
function forgedLengthGetter(): Buffer {
  const b = Buffer.from(REAL_FOUR);
  Object.defineProperty(b, "length", { get: () => 4096, configurable: true });
  return b;
}

/**
 * A four-byte `Buffer` that also restates `byteLength` and `byteOffset`.
 *
 * Present because the obvious narrow fix — keep returning the caller's object
 * but read `byteLength` instead of `length` — would pass the two tests above
 * and fail this one. Own properties shadow the prototype accessor whichever of
 * the three names you pick, so only reading the intrinsic slot accessor closes
 * the shape.
 */
function forgedByteLength(): Buffer {
  const b = Buffer.from(REAL_FOUR);
  Object.defineProperty(b, "length", { value: 4096, configurable: true });
  Object.defineProperty(b, "byteLength", { value: 4096, configurable: true });
  Object.defineProperty(b, "byteOffset", { value: 0, configurable: true });
  return b;
}

describe("mintApiKey: a signing secret cannot lie about its length", () => {
  for (const [label, build] of [
    ["an own `length` data property", forgedLengthDataProperty],
    ["an own `length` getter", forgedLengthGetter],
    ["own `byteLength`/`byteOffset` as well", forgedByteLength],
  ] as const) {
    test(`refuses a 4-byte Buffer that claims 4096 via ${label}`, () => {
      expect(() => mintApiKey({ app: APP, scopes: SCOPES, signingSecret: build() })).toThrow(
        /at least 16 bytes/,
      );
    });
  }

  // NEGATIVE CONTROL. The floor must already refuse an honestly short key, so a
  // refusal above is attributable to the forgery being defeated rather than to
  // the floor rejecting everything, or to it having been absent all along.
  test("NEGATIVE CONTROL: an honest 4-byte Buffer is refused for being short", () => {
    expect(() => mintApiKey({ app: APP, scopes: SCOPES, signingSecret: Buffer.from(REAL_FOUR) })).toThrow(
      /at least 16 bytes/,
    );
  });

  // POSITIVE CONTROL. Without this the suite would pass on a `toBuffer` that
  // simply threw for every input.
  test("POSITIVE CONTROL: a genuine 32-byte Buffer mints, and is keyed with ITS OWN bytes", () => {
    const minted = mintApiKey({ app: APP, scopes: SCOPES, signingSecret: Buffer.from(GENUINE_32) });
    const { signingInput, sig } = splitToken(minted.token);

    expect(sig).toBe(refSig(GENUINE_32, signingInput));
    expect(sig).not.toBe(refSig(REAL_FOUR, signingInput));

    const verified = verifyApiKeyToken(minted.token, { signingSecret: GENUINE_32 });
    expect(verified.ok).toBe(true);
  });

  // The two reference keys must be distinguishable, or every signature
  // comparison above is comparing a value with itself.
  test("CONTROL: the two reference keys produce different signatures", () => {
    const msg = "hasna_todos_control";
    expect(refSig(REAL_FOUR, msg)).not.toBe(refSig(GENUINE_32, msg));
  });

  // Trap 1 from the header, pinned so it cannot be reintroduced.
  test("the zero-padding trap: a zero-extended short key IS the same key", () => {
    const msg = "hasna_todos_control";
    const zeroExtended = Buffer.concat([REAL_FOUR, Buffer.alloc(12)]);
    expect(refSig(zeroExtended, msg)).toBe(refSig(REAL_FOUR, msg));
  });
});

describe("mintApiKey: honest byte-view secrets still mint and verify", () => {
  // The fix routes `Buffer` down the view branch, so these pin that the branch
  // did not regress for the shapes #86 deliberately restored.
  const shapes: Array<[string, () => Uint8Array | DataView | ArrayBuffer | Buffer]> = [
    ["Buffer", () => Buffer.from(GENUINE_32)],
    ["Uint8Array", () => new Uint8Array(GENUINE_32)],
    ["DataView", () => new DataView(new Uint8Array(GENUINE_32).buffer)],
    ["ArrayBuffer", () => new Uint8Array(GENUINE_32).buffer],
  ];

  for (const [label, build] of shapes) {
    test(`${label} mints a token that verifies under the same bytes`, () => {
      const minted = mintApiKey({ app: APP, scopes: SCOPES, signingSecret: build() as never });
      const { signingInput, sig } = splitToken(minted.token);
      expect(sig).toBe(refSig(GENUINE_32, signingInput));
      expect(verifyApiKeyToken(minted.token, { signingSecret: build() as never }).ok).toBe(true);
    });
  }

  // THE WINDOW, which is the property the fix could most easily have broken.
  // A view over part of a larger store must sign with its own window and not
  // with the whole backing store. Under Node's small-`Buffer` pooling every
  // short Buffer is such a view, so getting this wrong mints a valid-looking
  // token that no other holder of the same secret can verify.
  test("a subarray view signs with ITS OWN WINDOW, not the whole backing store", () => {
    const store = Buffer.from(Array.from({ length: 96 }, (_, i) => 0x40 + (i % 64)));
    const window = store.subarray(8, 40);

    expect(window.byteOffset).toBe(8);
    expect(window.length).toBe(32);

    const minted = mintApiKey({ app: APP, scopes: SCOPES, signingSecret: window });
    const { signingInput, sig } = splitToken(minted.token);

    expect(sig).toBe(refSig(Buffer.from(window), signingInput));
    expect(sig).not.toBe(refSig(store, signingInput));
    expect(verifyApiKeyToken(minted.token, { signingSecret: window }).ok).toBe(true);
  });

  // A FORGED `byteOffset` MOVES THE WINDOW WITHOUT CHANGING ITS LENGTH, so the
  // entropy floor is satisfied throughout and nothing upstream notices.
  //
  // This test exists because a mutation control caught its absence: replacing
  // the intrinsic `byteOffset` read with a plain `view.byteOffset` SURVIVED the
  // rest of this file. Every other arm here varies the LENGTH, and length is
  // what the floor and the `keyedWith*` comparisons were built around — so the
  // offset had no arm of its own until the mutation said so.
  //
  // The consequence is a wrong-key mint rather than a short-key one: the token
  // is signed with 32 bytes taken from the wrong place in the same store, so it
  // is a perfectly valid-looking token that the legitimate holder of that secret
  // cannot verify.
  test("a forged own `byteOffset` cannot move the signing window", () => {
    const store = Buffer.from(Array.from({ length: 96 }, (_, i) => 0x40 + (i % 64)));
    const window = store.subarray(8, 40);
    Object.defineProperty(window, "byteOffset", { value: 0, configurable: true });

    // The lie is in place, and it is the shape a plain property read would take.
    expect(window.byteOffset).toBe(0);

    const trueWindow = Buffer.from(Array.from(store.subarray(8, 40)));
    const movedWindow = Buffer.from(Array.from(store.subarray(0, 32)));
    // Guard the guard: if these two keys were equal the assertions below would
    // hold no matter which window was used.
    expect(Buffer.compare(trueWindow, movedWindow)).not.toBe(0);

    const minted = mintApiKey({ app: APP, scopes: SCOPES, signingSecret: window });
    const { signingInput, sig } = splitToken(minted.token);

    expect(sig).toBe(refSig(trueWindow, signingInput));
    expect(sig).not.toBe(refSig(movedWindow, signingInput));
  });
});
