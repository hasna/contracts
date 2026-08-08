// WHICH SHAPES OF `signingSecret` MINT A KEY, AND WHAT THE REFUSALS SAY.
//
// `mintApiKey` narrowed its accepted secret shapes in #85 — `Buffer.isBuffer`
// is strictly narrower than what `toBuffer`/`createHmac` accepted before it —
// and that narrowing was described in the PR as affecting "inputs that already
// threw". Measured on that PR's own base `a407b78f` with the same script, that
// is false: `Uint8Array`, `ArrayBuffer` and `DataView` secrets all minted VALID
// TOKENS at base and all threw at head.
//
// Two facts decide how this file resolves it, and both were measured rather
// than reasoned:
//
//  1. `verifyApiKeyToken` NEVER narrowed. It hands the secret straight to
//     `createHmac` (keys.ts), which takes Node's `BinaryLike`. So after #85 a
//     `Uint8Array` secret still VERIFIES and can no longer MINT — the issuer
//     breaks while every verifier sharing that secret keeps working. An
//     asymmetry between the two halves of one HMAC pair is not a tidy-up.
//
//  2. The narrowing nevertheless closed a real hole, which is why the fix is
//     not a revert. At base the entropy check read `.length`, and
//     `ArrayBuffer.prototype.length` does not exist — so `undefined < 16` is
//     false and a FOUR-BYTE `ArrayBuffer` secret minted a token. Restoring the
//     shapes has to keep that closed, so the floor is measured on the CONVERTED
//     buffer — the bytes that become the key — and not on any property the
//     caller supplies. The last describe block here is why: read off the raw
//     input, the floor is spoofable by three separate routes.
//
// The `app` narrowing is kept, deliberately and for a different reason, and the
// last test here pins the message that explains it.

import { describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { apiKeyPrefix, mintApiKey, verifyApiKeyToken } from "../src/auth/keys";

const SIGNING = "test-signing-secret-not-a-real-credential-000";
const APP = "todos";

const SECRET_BYTES = Buffer.from(SIGNING, "utf8");

/** The same bytes as `SIGNING`, in a standalone `ArrayBuffer`. */
function sameBytesArrayBuffer(): ArrayBuffer {
  const ab = new ArrayBuffer(SECRET_BYTES.byteLength);
  new Uint8Array(ab).set(SECRET_BYTES);
  return ab;
}

/**
 * Mint with `secret`, then verify the resulting token with the STRING form.
 *
 * Asserting only that the mint did not throw would pass on a build that
 * silently signed with the wrong bytes. Round-tripping through the string form
 * is what proves the shape conversion produced the SAME KEY, which is the
 * property a caller actually depends on.
 */
function mintsAndInteroperates(secret: unknown): boolean {
  const minted = mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: secret as never });
  return verifyApiKeyToken(minted.token, { signingSecret: SIGNING }).ok;
}

describe("mintApiKey: every byte-shaped signing secret Node accepts", () => {
  // The control for the three tests below: the two shapes that never stopped
  // working. If these ever fail, the failures underneath say nothing about
  // shape handling.
  test("control — a string and a Buffer secret mint and interoperate", () => {
    expect(mintsAndInteroperates(SIGNING)).toBe(true);
    expect(mintsAndInteroperates(Buffer.from(SIGNING, "utf8"))).toBe(true);
  });

  test("a Uint8Array secret mints, and its token verifies under the same bytes as a string", () => {
    expect(mintsAndInteroperates(new Uint8Array(sameBytesArrayBuffer()))).toBe(true);
  });

  test("an ArrayBuffer secret mints, and its token verifies under the same bytes as a string", () => {
    expect(mintsAndInteroperates(sameBytesArrayBuffer())).toBe(true);
  });

  test("a DataView secret mints, and its token verifies under the same bytes as a string", () => {
    expect(mintsAndInteroperates(new DataView(sameBytesArrayBuffer()))).toBe(true);
  });

  test("a byte view with an OFFSET reads only its own window", () => {
    // `Buffer.from(view.buffer)` without `byteOffset`/`byteLength` would sign
    // with the whole backing store instead of the caller's window — a silent
    // wrong-key bug that the round-trip above would catch only by luck, since
    // both sides would be wrong in the same way if the string form were not the
    // reference. Here the window is byte-identical to `SIGNING` while the
    // backing store is not.
    const padded = new Uint8Array(SECRET_BYTES.byteLength + 8);
    padded.set(SECRET_BYTES, 4);
    const window = new Uint8Array(padded.buffer, 4, SECRET_BYTES.byteLength);
    expect(Buffer.from(window).equals(SECRET_BYTES)).toBe(true);

    expect(mintsAndInteroperates(window)).toBe(true);
  });

  test("mint and verify agree on the shape — the asymmetry #85 opened", () => {
    // This is the finding that decided restore-over-document. `verify` never
    // narrowed, so on the build shipped by #85 this expectation held for
    // `verify` and failed for `mint`: one half of an HMAC pair accepted a
    // secret the other half refused.
    const token = mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: SIGNING }).token;
    const view = new Uint8Array(sameBytesArrayBuffer());

    expect(verifyApiKeyToken(token, { signingSecret: view as never }).ok).toBe(true);
    expect(mintsAndInteroperates(view)).toBe(true);
  });
});

describe("mintApiKey: the entropy floor holds on every shape", () => {
  test("a short ArrayBuffer is refused — the floor is measured on the converted bytes", () => {
    // REGRESSION AGAINST BASE, not against #85. At `a407b78f` this exact input
    // MINTED A TOKEN, because the floor read `toBuffer(secret).length` while
    // the conversion was not yet reached — `ArrayBuffer` has no `.length`, so
    // `undefined < 16` is false. #85 closed it as a side effect of narrowing;
    // this test is what keeps it closed now that the shape is accepted again.
    // Converting first makes the number an internal fact about the allocated
    // buffer, which is what `a407b78f` and the raw-`byteLength` revision both
    // lacked in their different ways.
    expect(() => mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: new ArrayBuffer(4) as never })).toThrow(
      "at least 16 bytes",
    );
  });

  test("a short Uint8Array, DataView and string are refused too", () => {
    const short = new Uint8Array([1, 2, 3, 4]);
    for (const secret of [short, new DataView(short.buffer), "too-short"]) {
      expect(() => mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: secret as never })).toThrow(
        "at least 16 bytes",
      );
    }
  });

  test("a string secret is measured in BYTES, not characters", () => {
    // 15 astral-plane characters are 60 UTF-8 bytes, and 5 are 20 — both above
    // the floor. 3 of them are 12 bytes and must be refused even though
    // `"...".length` reads 6. `Buffer.byteLength(s, "utf8")` is what makes the
    // floor mean what the message says it means; `s.length` would let a short
    // secret through and reject a long one.
    expect(() => mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: "𝓍".repeat(5) })).not.toThrow();
    expect(() => mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: "𝓍".repeat(3) })).toThrow(
      "at least 16 bytes",
    );
  });

  test("exactly 16 bytes is accepted and 15 is not — the boundary, on a view", () => {
    const sixteen = new Uint8Array(16).fill(7);
    expect(() => mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: sixteen as never })).not.toThrow();
    expect(() =>
      mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: new Uint8Array(15).fill(7) as never }),
    ).toThrow("at least 16 bytes");
  });
});

describe("mintApiKey: the entropy floor cannot be talked out of the way", () => {
  // THE MUTATION THESE EXIST FOR is moving the floor back above `toBuffer`, so
  // that it reads `requestedSecret.byteLength` off the caller's object again.
  // Every test in this block passes on the shipped build and fails on that one.
  //
  // Why the floor is spoofable when it reads the raw input: `isBinarySecret`
  // admits on `instanceof ArrayBuffer`, which consults the prototype chain, and
  // `byteLength` is then an ordinary property read. Neither is a fact about
  // memory; both are things the caller can simply say.
  //
  // Severity, stated so nobody re-derives it upward: a caller who can put an
  // object into `signingSecret` is already choosing the key material, so this is
  // not remote and it is not privilege escalation. It matters because the value
  // is a SERVER-HELD secret that arrives from config, a vault client or
  // `crypto.subtle`, and a wrapper in that path silently collapsing the key to
  // four bytes is indistinguishable from a healthy mint at every call site.

  /** The bytes every forgery below is really carrying. */
  const FOUR = Buffer.from([1, 2, 3, 4]);

  /**
   * Recover whether a token was signed with `FOUR`, rather than trusting that a
   * refusal happened. Asserting only `toThrow` would pass on a build that
   * accepted the input and signed with something else short.
   */
  function keyedWithFourBytes(token: string): boolean {
    const cut = token.lastIndexOf(".");
    return (
      createHmac("sha256", FOUR).update(token.slice(0, cut), "utf8").digest("base64url") === token.slice(cut + 1)
    );
  }

  test("control — the honest 4-byte shapes are refused, and 32 real bytes still mint", () => {
    // Without this the three tests below cannot distinguish "the forgery was
    // caught" from "the floor is refusing everything".
    expect(() =>
      mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: new ArrayBuffer(4) as never }),
    ).toThrow("at least 16 bytes");
    expect(mintsAndInteroperates(SECRET_BYTES)).toBe(true);
  });

  test("an object with ArrayBuffer.prototype grafted on cannot declare its own size", () => {
    // Not an ArrayBuffer at all — an array-like with the prototype swapped, so
    // `instanceof ArrayBuffer` is true and `byteLength` is whatever it says.
    const forged: Record<string, unknown> = { 0: 1, 1: 2, 2: 3, 3: 4, length: 4, byteLength: 4096 };
    Object.setPrototypeOf(forged, ArrayBuffer.prototype);
    expect(() => mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: forged as never })).toThrow(
      "at least 16 bytes",
    );
  });

  test("a Proxy whose get trap reports a false byteLength cannot mint", () => {
    const real = new Uint8Array([1, 2, 3, 4]).buffer;
    const lying = new Proxy(real, {
      get(target, prop) {
        if (prop === "byteLength") return 4096;
        const value = Reflect.get(target, prop, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    expect(() => mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: lying as never })).toThrow(
      "at least 16 bytes",
    );
  });

  test("an ArrayBuffer subclass overriding byteLength with a getter cannot mint", () => {
    // The one route of the three that is ALSO open at `a407b78f`; the other two
    // are refused there and at `0a037408`, and would be first opened here.
    class Overstated extends ArrayBuffer {
      override get byteLength() {
        return 4096;
      }
    }
    const forged = new Overstated(4);
    new Uint8Array(forged as ArrayBuffer).set([1, 2, 3, 4]);
    expect(() => mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: forged as never })).toThrow(
      "at least 16 bytes",
    );
  });

  test("no forged shape reaches the HMAC — checked on the signature, not the refusal", () => {
    // The assertion that survives a build which accepts the input instead of
    // throwing: whatever comes back must not be keyed with the four bytes.
    const forged: Record<string, unknown> = { 0: 1, 1: 2, 2: 3, 3: 4, length: 4, byteLength: 4096 };
    Object.setPrototypeOf(forged, ArrayBuffer.prototype);
    let token: string | null = null;
    try {
      token = mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: forged as never }).token;
    } catch {
      token = null;
    }
    expect(token === null || !keyedWithFourBytes(token)).toBe(true);

    // TWO CONTROLS, because the assertion above is an absence and an absence
    // proves nothing until the detector is shown to fire and to stay quiet.
    //
    // Positive: a token genuinely keyed with the four bytes must be RECOGNISED.
    // This is the only way to know `keyedWithFourBytes` can return true at all.
    // It is built by signing directly rather than through `mintApiKey`, which
    // now correctly refuses a four-byte secret.
    const fourKeyed = `${apiKeyPrefix(APP)}body`;
    const fourSig = createHmac("sha256", FOUR).update(fourKeyed, "utf8").digest("base64url");
    expect(keyedWithFourBytes(`${fourKeyed}.${fourSig}`)).toBe(true);

    // Negative: a real, accepted 16-byte secret must NOT be recognised.
    //
    // The bytes matter here and the obvious choice is wrong. HMAC zero-pads any
    // key shorter than the hash's 64-byte block, so `FOUR` and
    // `FOUR + 12 zero bytes` are THE SAME KEY and produce identical MACs — a
    // first draft of this control used exactly that and failed, correctly. The
    // padding fact is also why this floor is a LENGTH floor and not an entropy
    // measure: sixteen bytes with twelve trailing zeros buys nothing over four.
    const sixteen = Buffer.concat([FOUR, Buffer.alloc(12, 0xab)]);
    const honest = mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: sixteen }).token;
    expect(keyedWithFourBytes(honest)).toBe(false);
    const cut = honest.lastIndexOf(".");
    expect(createHmac("sha256", sixteen).update(honest.slice(0, cut), "utf8").digest("base64url")).toBe(
      honest.slice(cut + 1),
    );
  });
});

describe("mintApiKey: a refusal names what it refused", () => {
  test("a secret of the wrong SHAPE is not reported as one of the wrong LENGTH", () => {
    // The message #85 shipped for this case says "must be at least 16 bytes of
    // entropy", which sends the caller to count bytes on a value that has none
    // to count. Length and shape are different refusals and say so.
    for (const bad of [undefined, null, 42, {}, { length: 32 }, []]) {
      expect(() => mintApiKey({ app: APP, scopes: ["todos:read"], signingSecret: bad as never })).toThrow(
        /signingSecret must be a string, Buffer, TypedArray, DataView, or ArrayBuffer/,
      );
    }
  });

  test("a non-string `app` is named as a type, not as a malformed slug", () => {
    // THE NARROWING HERE IS KEPT, and this test is the truthful record of it.
    // A `String` object app MINTED A VALID TOKEN at `a407b78f`; it did not
    // "already throw". It is kept refused because the declared type is
    // `string`, because restoring it means calling `.trim()` on an unknown —
    // the `TypeError` path #85 closed — and because no adjacent API in this kit
    // accepts a boxed primitive specially.
    //
    // What is NOT acceptable is the message it shipped with:
    // `Invalid app slug 'myapp'` reads as though the slug `myapp` is malformed,
    // when `myapp` is a perfectly good slug and the object wrapping it is the
    // problem. A public package's error has to point at the real cause.
    expect(() => mintApiKey({ app: new String("todos") as never, scopes: ["todos:read"], signingSecret: SIGNING }))
      .toThrow(/app must be a string/);

    // And a genuinely malformed slug still gets the slug message.
    expect(() => mintApiKey({ app: "Not A Slug", scopes: ["todos:read"], signingSecret: SIGNING })).toThrow(
      "Invalid app slug 'Not A Slug'",
    );
  });

  test("a string app is still trimmed, and an empty one still refused", () => {
    // Both directions on the guard that was changed: legitimate input keeps
    // working. `'  todos  '` minted at base and must still mint.
    const minted = mintApiKey({ app: "  todos  ", scopes: ["todos:read"], signingSecret: SIGNING });
    expect(minted.claims.app).toBe(APP);
    expect(() => mintApiKey({ app: "   ", scopes: ["todos:read"], signingSecret: SIGNING })).toThrow(
      "Invalid app slug",
    );
  });
});
