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
//     shapes has to keep that closed, so the check reads `byteLength`.
//
// The `app` narrowing is kept, deliberately and for a different reason, and the
// last test here pins the message that explains it.

import { describe, expect, test } from "bun:test";
import { mintApiKey, verifyApiKeyToken } from "../src/auth/keys";

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
  test("a short ArrayBuffer is refused — the check reads byteLength, not `.length`", () => {
    // REGRESSION AGAINST BASE, not against #85. At `a407b78f` this exact input
    // MINTED A TOKEN, because `ArrayBuffer` has no `.length` and `undefined <
    // 16` is false. #85 closed it as a side effect of narrowing; this test is
    // what keeps it closed now that the shape is accepted again.
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
