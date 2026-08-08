import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import pg from "pg";
import { createPgPool } from "../src/kit/templates/pool";
import {
  connectionStringWithoutTlsParameters,
  resolveTlsConfig,
  sslModeFromConnectionString,
  sslNegotiationFromConnectionString,
} from "../src/kit/templates/tls";

// A REAL TLS HANDSHAKE, NOT A RETURNED OBJECT.
//
// The defect this file pins hid for the entire life of the kit because every
// test asserted what `resolveTlsConfig` RETURNED. pg re-parses the DSN after
// merging pool options and lets the parse win, so the returned object — CA
// bundle included — was discarded on the way to the socket. A test reading the
// return value passes in both worlds; only a handshake separates them.
//
// So this suite stands up an endpoint speaking the actual Postgres TLS
// negotiation (SSLRequest -> 'S' -> TLS upgrade), presents a private-CA cert on
// one port and a self-signed cert on another, and connects through the kit's own
// `createPgPool`. Ports are ephemeral (listen on 0) so nothing on the host can
// be collided with, and both servers are torn down in `afterAll`.
//
// Both directions are asserted for every claim: a config that must connect, and
// a config that must be refused. A suite where only one outcome is reachable
// cannot fail and is not evidence.

const SSL_REQUEST_CODE = 80877103;
const TLS_MARKER = "FAKE_PG_TLS_ESTABLISHED";
const PLAINTEXT_MARKER = "FAKE_PG_PLAINTEXT_NO_TLS";
const CERT_ERROR_CODES = new Set([
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "CERT_HAS_EXPIRED",
]);

type Outcome =
  | { kind: "TLS_ESTABLISHED" }
  | { kind: "TLS_REJECTED_CERT"; code: string; message: string }
  | { kind: "PLAINTEXT_NO_TLS" }
  | { kind: "OTHER"; code: string; message: string };

function openssl(args: string[], cwd: string): void {
  execFileSync("openssl", args, { cwd, stdio: ["ignore", "ignore", "pipe"] });
}

interface Fixtures {
  dir: string;
  caPem: string;
  caServer: { key: string; cert: string };
  selfSignedServer: { key: string; cert: string };
}

/**
 * Mint a private CA, a server certificate signed by it, and an unrelated
 * self-signed certificate — all for `localhost`. Generated at test time rather
 * than committed: a repository that ships private keys, even synthetic ones, is
 * a repository whose secret scanning has to learn exceptions.
 */
function mintFixtures(): Fixtures {
  const dir = mkdtempSync(join(tmpdir(), "kit-tls-"));
  const ext = join(dir, "san.ext");
  writeFileSync(ext, "subjectAltName=DNS:localhost,IP:127.0.0.1\n", "utf8");

  openssl(
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
      "-days", "3650", "-subj", "/CN=Hasna Kit Test CA",
      "-addext", "basicConstraints=critical,CA:TRUE"],
    dir,
  );
  openssl(
    ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "srv-ca.key", "-out", "srv-ca.csr",
      "-subj", "/CN=localhost"],
    dir,
  );
  openssl(
    ["x509", "-req", "-in", "srv-ca.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", "srv-ca.crt", "-days", "3650", "-extfile", ext],
    dir,
  );
  openssl(
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "srv-ss.key", "-out", "srv-ss.crt",
      "-days", "3650", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
    dir,
  );

  const read = (name: string) => readFileSync(join(dir, name), "utf8");
  return {
    dir,
    caPem: read("ca.crt"),
    caServer: { key: read("srv-ca.key"), cert: read("srv-ca.crt") },
    selfSignedServer: { key: read("srv-ss.key"), cert: read("srv-ss.crt") },
  };
}

function errorResponse(message: string): Buffer {
  const parts: Buffer[] = [];
  for (const [type, value] of [["S", "FATAL"], ["V", "FATAL"], ["C", "28000"], ["M", message]]) {
    parts.push(Buffer.from(type!, "ascii"), Buffer.from(value!, "utf8"), Buffer.from([0]));
  }
  parts.push(Buffer.from([0]));
  const body = Buffer.concat(parts);
  const len = Buffer.alloc(4);
  len.writeInt32BE(body.length + 4, 0);
  return Buffer.concat([Buffer.from("E", "ascii"), len, body]);
}

interface FakePostgres {
  port: number;
  directPort: number;
  close: () => Promise<void>;
}

function listen(server: net.Server | tls.Server): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("no ephemeral port"));
        return;
      }
      resolve(address.port);
    });
  });
}

/**
 * A Postgres endpoint, only as far as the TLS negotiation: it answers the
 * SSLRequest with 'S', completes a real TLS handshake, and then refuses the
 * StartupMessage with a distinctive ErrorResponse. Reaching that error means TLS
 * COMPLETED; a cert error on the client means the client verified and refused.
 *
 * THE FRONT-PROXY IS NOT DECORATION, it is a runtime workaround, and the client
 * cannot tell: MEASURED on bun 1.3.14, wrapping an accepted `net.Socket` in a
 * server-side `tls.TLSSocket` — the obvious way to write this, and what the
 * original measurement harness did under node — never completes the handshake
 * and never errors. A minimal probe printed `RESULT=TIMEOUT` under bun and
 * `SERVER_SECURE=1` / `RESULT=TLS_OK` under node v22.22.3 on the same certs.
 * `tls.createServer` works under both, so the plaintext SSLRequest is answered
 * on a front socket and the remaining bytes are piped into a real TLS server.
 * The client still performs the genuine SSLRequest -> 'S' -> TLS upgrade.
 */
async function startFakePostgres(material: { key: string; cert: string }): Promise<FakePostgres> {
  const sockets = new Set<net.Socket>();
  const track = (socket: net.Socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
  };

  const tlsServer = tls.createServer(material, (secured) => {
    track(secured);
    secured.once("data", () => {
      try {
        secured.write(errorResponse(TLS_MARKER));
        secured.end();
      } catch {}
    });
  });
  const tlsPort = await listen(tlsServer);

  const front = net.createServer((socket) => {
    track(socket);
    socket.once("data", (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "binary");
      const isSslRequest =
        buf.length >= 8 && buf.readInt32BE(0) === 8 && buf.readInt32BE(4) === SSL_REQUEST_CODE;
      if (!isSslRequest) {
        try {
          socket.write(errorResponse(PLAINTEXT_MARKER));
          socket.end();
        } catch {}
        return;
      }
      socket.write(Buffer.from("S", "ascii"));
      const upstream = net.connect(tlsPort, "127.0.0.1", () => {
        socket.pipe(upstream);
        upstream.pipe(socket);
      });
      track(upstream);
    });
  });
  const port = await listen(front);

  return {
    port,
    directPort: tlsPort,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => front.close(() => resolve()));
      await new Promise<void>((resolve) => tlsServer.close(() => resolve()));
    },
  };
}

async function classify(run: () => Promise<unknown>): Promise<Outcome> {
  try {
    await run();
    return { kind: "OTHER", code: "NO_ERROR", message: "query unexpectedly succeeded" };
  } catch (error) {
    const err = error as { code?: unknown; message?: unknown };
    const code = typeof err.code === "string" ? err.code : "";
    const message = typeof err.message === "string" ? err.message : String(error);
    if (message.includes(TLS_MARKER)) return { kind: "TLS_ESTABLISHED" };
    if (message.includes(PLAINTEXT_MARKER)) return { kind: "PLAINTEXT_NO_TLS" };
    if (CERT_ERROR_CODES.has(code)) return { kind: "TLS_REJECTED_CERT", code, message };
    return { kind: "OTHER", code, message };
  }
}

/** Connect through the kit's own factory and classify what the socket did. */
async function throughKit(
  connectionString: string,
  options: { ca?: string } = {},
): Promise<Outcome> {
  const pool = createPgPool({
    connectionString,
    env: {},
    connectionTimeoutMillis: 10_000,
    ...(options.ca !== undefined ? { ca: options.ca } : {}),
  });
  try {
    return await classify(() => pool.query("SELECT 1"));
  } finally {
    await pool.end().catch(() => {});
  }
}

/** Connect the way the kit used to: DSN intact, ssl object passed alongside. */
async function throughUnstrippedDsn(connectionString: string, ssl: object): Promise<Outcome> {
  const pool = new pg.Pool({ connectionString, ssl, connectionTimeoutMillis: 10_000 } as never);
  try {
    return await classify(() => pool.query("SELECT 1"));
  } finally {
    await pool.end().catch(() => {});
  }
}

let fixtures: Fixtures;
let privateCaServer: FakePostgres;
let selfSignedServer: FakePostgres;
let privateCaDsn: (query: string) => string;
let selfSignedDsn: (query: string) => string;
let privateCaDirectDsn: (query: string) => string;
let selfSignedDirectDsn: (query: string) => string;

beforeAll(async () => {
  fixtures = mintFixtures();
  privateCaServer = await startFakePostgres(fixtures.caServer);
  selfSignedServer = await startFakePostgres(fixtures.selfSignedServer);
  privateCaDsn = (query) => `postgres://u:p@localhost:${privateCaServer.port}/db${query}`;
  selfSignedDsn = (query) => `postgres://u:p@localhost:${selfSignedServer.port}/db${query}`;
  privateCaDirectDsn = (query) =>
    privateCaDsn(query).replace(`:${privateCaServer.port}/db`, `:${privateCaServer.directPort}/db`);
  selfSignedDirectDsn = (query) =>
    selfSignedDsn(query).replace(`:${selfSignedServer.port}/db`, `:${selfSignedServer.directPort}/db`);
});

afterAll(async () => {
  await privateCaServer?.close();
  await selfSignedServer?.close();
  if (fixtures?.dir) rmSync(fixtures.dir, { recursive: true, force: true });
});

describe("kit TLS handshake — the harness itself", () => {
  // Without these, every assertion below is unfalsifiable: a harness that can
  // only ever refuse, or only ever connect, proves nothing about the kit.
  test("both outcomes are reachable against the private-CA server", async () => {
    const trusted = await throughUnstrippedDsn(privateCaDsn(""), {
      rejectUnauthorized: true,
      ca: fixtures.caPem,
    });
    expect(trusted.kind).toBe("TLS_ESTABLISHED");

    const untrusted = await throughUnstrippedDsn(privateCaDsn(""), { rejectUnauthorized: true });
    expect(untrusted.kind).toBe("TLS_REJECTED_CERT");
    expect((untrusted as { code: string }).code).toBe("UNABLE_TO_VERIFY_LEAF_SIGNATURE");
  });

  test("the self-signed server is refused by a verifying client", async () => {
    const outcome = await throughUnstrippedDsn(selfSignedDsn(""), { rejectUnauthorized: true });
    expect(outcome.kind).toBe("TLS_REJECTED_CERT");
    expect((outcome as { code: string }).code).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
  });
});

describe("kit TLS handshake — pg discards a DSN-carried ssl config (the defect)", () => {
  // THE REGRESSION PIN. This is the behaviour that made the CA unusable, and it
  // is upstream: if it ever changes, the strip in pool.ts becomes unnecessary
  // and this test says so instead of leaving dead code in place.
  test("an unstripped sslmode throws away the caller's CA", async () => {
    const outcome = await throughUnstrippedDsn(privateCaDsn("?sslmode=verify-full"), {
      rejectUnauthorized: true,
      ca: fixtures.caPem,
    });
    expect(outcome.kind).toBe("TLS_REJECTED_CERT");
    expect((outcome as { code: string }).code).toBe("UNABLE_TO_VERIFY_LEAF_SIGNATURE");
  });
});

describe("kit TLS handshake — verify-full with a CA, both directions", () => {
  test("verify-full + correct CA CONNECTS to a private-CA server", async () => {
    // Was UNABLE_TO_VERIFY_LEAF_SIGNATURE before the DSN strip. Amazon RDS is in
    // this class: its root is not in Node's trust store.
    const outcome = await throughKit(privateCaDsn("?sslmode=verify-full"), { ca: fixtures.caPem });
    expect(outcome).toEqual({ kind: "TLS_ESTABLISHED" });
  });

  test("verify-full + correct CA REFUSES a self-signed server", async () => {
    // The half that must not regress: delivering the CA must not make anything
    // permissive.
    const outcome = await throughKit(selfSignedDsn("?sslmode=verify-full"), { ca: fixtures.caPem });
    expect(outcome.kind).toBe("TLS_REJECTED_CERT");
    expect((outcome as { code: string }).code).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
  });

  test("verify-full + sslrootcert in the DSN still works after the strip", async () => {
    // The interim workaround operators were told to use. The strip removes
    // `sslrootcert`, so tls.ts has to read it — otherwise this path breaks.
    const rootCert = join(fixtures.dir, "ca.crt");
    const connects = await throughKit(
      privateCaDsn(`?sslmode=verify-full&sslrootcert=${encodeURIComponent(rootCert)}`),
    );
    expect(connects).toEqual({ kind: "TLS_ESTABLISHED" });

    const refuses = await throughKit(
      selfSignedDsn(`?sslmode=verify-full&sslrootcert=${encodeURIComponent(rootCert)}`),
    );
    expect(refuses.kind).toBe("TLS_REJECTED_CERT");
  });
});

describe("kit TLS handshake — `require` still verifies", () => {
  // FORWARD HAZARD. pg-connection-string v3 / pg v9 adopt libpq semantics, under
  // which `require` stops verifying. Nothing would fail on that upgrade — the
  // guarantee would just quietly stop existing. These two assertions fail loudly
  // instead.
  test("require refuses a private-CA server when no CA is supplied", async () => {
    const outcome = await throughKit(privateCaDsn("?sslmode=require"));
    expect(outcome.kind).toBe("TLS_REJECTED_CERT");
    expect((outcome as { code: string }).code).toBe("UNABLE_TO_VERIFY_LEAF_SIGNATURE");
  });

  test("require refuses a self-signed server", async () => {
    const outcome = await throughKit(selfSignedDsn("?sslmode=require"));
    expect(outcome.kind).toBe("TLS_REJECTED_CERT");
    expect((outcome as { code: string }).code).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
  });

  test("require CONNECTS once the operator supplies the right CA", async () => {
    // The other direction, so the two tests above cannot pass vacuously.
    const outcome = await throughKit(privateCaDsn("?sslmode=require"), { ca: fixtures.caPem });
    expect(outcome).toEqual({ kind: "TLS_ESTABLISHED" });
  });

  test("prefer verifies exactly like require", async () => {
    const refused = await throughKit(selfSignedDsn("?sslmode=prefer"));
    expect(refused.kind).toBe("TLS_REJECTED_CERT");
    const connected = await throughKit(privateCaDsn("?sslmode=prefer"), { ca: fixtures.caPem });
    expect(connected).toEqual({ kind: "TLS_ESTABLISHED" });
  });
});

describe("kit TLS handshake — direct negotiation implies verified TLS", () => {
  test("sslnegotiation=direct connects with the right CA without an explicit sslmode", async () => {
    const outcome = await throughKit(privateCaDirectDsn("?sslnegotiation=direct"), {
      ca: fixtures.caPem,
    });
    expect(outcome).toEqual({ kind: "TLS_ESTABLISHED" });
  });

  test("sslnegotiation=direct refuses an untrusted certificate", async () => {
    const outcome = await throughKit(selfSignedDirectDsn("?sslnegotiation=direct"));
    expect(outcome.kind).toBe("TLS_REJECTED_CERT");
    expect((outcome as { code: string }).code).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
  });
});

describe("kit TLS handshake — sslmode=disable is still plaintext", () => {
  // THESE TESTS DRIVE THE REAL `process.env.PGSSLMODE`, DELIBERATELY.
  //
  // `throughKit` passes `env: {}`, and that isolates `loadCaBundle` ONLY. It
  // never reaches pg's own environment fallback: when `resolveTlsConfig`
  // returns `undefined` the pool carries no `ssl` key at all, so pg reaches
  // connection-parameters.js -> readSSLConfigFromEnvironment(), which reads the
  // real `process.env.PGSSLMODE` directly. The variable is therefore the only
  // instrument that can exercise this path, and it is restored in `finally`.
  //
  // Before row c317d0bf was fixed, this block passed under `env -u PGSSLMODE`
  // and failed under `PGSSLMODE=require` — so the defect was detectable only by
  // accident of the shell. Setting the variable in-process makes it explicit.
  async function withPgSslMode<T>(value: string | undefined, fn: () => Promise<T>): Promise<T> {
    const had = Object.hasOwn(process.env, "PGSSLMODE");
    const previous = process.env.PGSSLMODE;
    if (value === undefined) delete process.env.PGSSLMODE;
    else process.env.PGSSLMODE = value;
    try {
      return await fn();
    } finally {
      if (had) process.env.PGSSLMODE = previous;
      else delete process.env.PGSSLMODE;
    }
  }

  test("disable does not send an SSLRequest", async () => {
    const outcome = await withPgSslMode(undefined, () =>
      throughKit(selfSignedDsn("?sslmode=disable")),
    );
    expect(outcome).toEqual({ kind: "PLAINTEXT_NO_TLS" });
  });

  // REGRESSION, row c317d0bf. An EXPLICIT operator `sslmode=disable` must beat
  // an ambient PGSSLMODE. Measured failure before the fix, at 24df0fa:
  //   { kind: "TLS_REJECTED_CERT", code: "DEPTH_ZERO_SELF_SIGNED_CERT" }
  // i.e. TLS was attempted against a server the operator had asked to reach in
  // plaintext, and the instruction in the DSN said nothing at all.
  test("an explicit sslmode=disable beats an ambient PGSSLMODE=require", async () => {
    const outcome = await withPgSslMode("require", () =>
      throughKit(selfSignedDsn("?sslmode=disable")),
    );
    expect(outcome).toEqual({ kind: "PLAINTEXT_NO_TLS" });
  });

  test("an explicit ssl=false beats an ambient PGSSLMODE=require", async () => {
    const outcome = await withPgSslMode("require", () => throughKit(selfSignedDsn("?ssl=false")));
    expect(outcome).toEqual({ kind: "PLAINTEXT_NO_TLS" });
  });

  test("a DSN with no ssl parameters at all is still plaintext", async () => {
    const outcome = await withPgSslMode(undefined, () => throughKit(selfSignedDsn("")));
    expect(outcome).toEqual({ kind: "PLAINTEXT_NO_TLS" });
  });

  // THE OTHER HALF OF THE GATE, AND IT IS WHY THE FIX IS NOT A BLANKET `false`.
  //
  // A DSN carrying NO ssl parameter has expressed no instruction, so pg's
  // PGSSLMODE fallback is libpq's documented behaviour and must survive. If the
  // `disable` branch is ever widened to return `false` unconditionally — which
  // would make this whole block pass under any environment and look like a
  // tidier fix — an operator who sets PGSSLMODE=require to force TLS on bare
  // DSNs is silently downgraded to plaintext. This test fails loudly on that,
  // so the wrong fix cannot land quietly.
  test("a DSN with no ssl parameter still defers to PGSSLMODE (libpq behaviour)", async () => {
    const outcome = await withPgSslMode("require", () => throughKit(selfSignedDsn("")));
    expect(outcome.kind).toBe("TLS_REJECTED_CERT");
    expect((outcome as { code: string }).code).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
  });

  // REGRESSION, row feb638fa. A PRESENT-BUT-EMPTY `sslmode` IS A VALUE, NOT AN
  // ABSENCE, so it must not land on the row directly above.
  //
  // Measured on main at 010b0bb, before this fix:
  //   ?sslmode=     mode=disable  resolve=undefined
  //   ?sslmode=%20  mode=disable  resolve=undefined
  //   (absent)      mode=disable  resolve=undefined      <- byte-identical
  // so the DSN's statement was discarded and the environment decided instead.
  //
  // The two ambient states below are the point of the pair: whatever PGSSLMODE
  // says, the DSN parameter is what fails the build. A one-sided version of this
  // test would pass against the old code in whichever environment the author
  // happened to run it in — which is exactly how row c317d0bf stayed hidden.
  test("an empty sslmode is rejected, not silently deferred to an unset PGSSLMODE", async () => {
    // Before the fix this returned { kind: "PLAINTEXT_NO_TLS" }: an operator who
    // wrote `?sslmode=${PGSSLMODE}` with the variable unset got plaintext to a
    // cloud database, and nothing anywhere said so.
    await withPgSslMode(undefined, async () => {
      expect(() => createPgPool({ connectionString: selfSignedDsn("?sslmode="), env: {} })).toThrow(
        /Unknown sslmode ''/,
      );
    });
  });

  test("an empty sslmode is rejected, not silently deferred to an ambient PGSSLMODE=require", async () => {
    // Before the fix this attempted TLS — the right answer for the wrong reason.
    // The environment was deciding; the DSN was not consulted.
    await withPgSslMode("require", async () => {
      expect(() => createPgPool({ connectionString: selfSignedDsn("?sslmode="), env: {} })).toThrow(
        /Unknown sslmode ''/,
      );
    });
  });

  test("a whitespace-only sslmode is rejected the same way", async () => {
    await withPgSslMode(undefined, async () => {
      expect(() =>
        createPgPool({ connectionString: selfSignedDsn("?sslmode=%20"), env: {} }),
      ).toThrow(/Unknown sslmode ''/);
    });
  });

  // THE OTHER HALF, AND IT IS WHY THE FIX IS NOT "MAKE EVERYTHING THROW".
  // A blanket rejection of anything falsy would take the row above with it and
  // break every bare DSN on the fleet. This test fails loudly on that.
  test("an absent sslmode still connects and still defers — the fix did not widen", async () => {
    const deferred = await withPgSslMode("require", () => throughKit(selfSignedDsn("")));
    expect(deferred.kind).toBe("TLS_REJECTED_CERT");

    const plaintext = await withPgSslMode(undefined, () => throughKit(selfSignedDsn("")));
    expect(plaintext).toEqual({ kind: "PLAINTEXT_NO_TLS" });
  });

  test("recognised sslmode values are untouched by the fix", async () => {
    const disabled = await withPgSslMode("require", () =>
      throughKit(selfSignedDsn("?sslmode=disable")),
    );
    expect(disabled).toEqual({ kind: "PLAINTEXT_NO_TLS" });

    const verified = await withPgSslMode(undefined, () =>
      throughKit(privateCaDsn("?sslmode=require"), { ca: fixtures.caPem }),
    );
    expect(verified.kind).toBe("TLS_ESTABLISHED");
  });
});

describe("sslModeFromConnectionString — the recognised set is enumerated", () => {
  // The `ssl` parameter names its accepted values in two exported Sets; the
  // `sslmode` parameter did not, and the reviewer's sentence for row feb638fa is
  // the finding: "the enumerate-the-set discipline was applied to `ssl` and not
  // to `sslmode`". The enumeration existed as a `switch`, but sat behind a
  // truthiness test that one input class could never satisfy.
  const dsn = (query: string) => `postgres://u:p@h:5432/db${query}`;

  test("every value libpq accepts still maps as before", () => {
    expect(sslModeFromConnectionString(dsn("?sslmode=disable"))).toBe("disable");
    expect(sslModeFromConnectionString(dsn("?sslmode=allow"))).toBe("prefer");
    expect(sslModeFromConnectionString(dsn("?sslmode=prefer"))).toBe("prefer");
    expect(sslModeFromConnectionString(dsn("?sslmode=require"))).toBe("require");
    expect(sslModeFromConnectionString(dsn("?sslmode=verify-ca"))).toBe("verify-ca");
    expect(sslModeFromConnectionString(dsn("?sslmode=verify-full"))).toBe("verify-full");
  });

  test("case and surrounding whitespace are still normalized away", () => {
    expect(sslModeFromConnectionString(dsn("?sslmode=%20VERIFY-FULL%20"))).toBe("verify-full");
    expect(sslModeFromConnectionString(dsn("?SSLMode=Require"))).toBe("require");
  });

  test("an unrecognised value still throws, and now names the accepted set", () => {
    expect(() => sslModeFromConnectionString(dsn("?sslmode=bogus"))).toThrow(
      /Unknown sslmode 'bogus'/,
    );
    expect(() => sslModeFromConnectionString(dsn("?sslmode=bogus"))).toThrow(
      /disable, allow, prefer, require, verify-ca, verify-full/,
    );
  });

  test("an empty or whitespace-only value throws — it is a value, not an absence", () => {
    expect(() => sslModeFromConnectionString(dsn("?sslmode="))).toThrow(/Unknown sslmode ''/);
    expect(() => sslModeFromConnectionString(dsn("?sslmode=%20"))).toThrow(/Unknown sslmode ''/);
    expect(() => resolveTlsConfig(dsn("?sslmode="), { env: {} })).toThrow(/Unknown sslmode ''/);
  });

  test("the message points at the remedy the empty value was reaching for", () => {
    expect(() => sslModeFromConnectionString(dsn("?sslmode="))).toThrow(
      /Remove the parameter entirely to defer to PGSSLMODE/,
    );
  });

  test("an absent sslmode is undefined-not-empty and resolves to disable", () => {
    expect(sslModeFromConnectionString(dsn(""))).toBe("disable");
    expect(resolveTlsConfig(dsn(""), { env: {} })).toBeUndefined();
    // and the explicit off is still distinguishable from it — row c317d0bf.
    expect(resolveTlsConfig(dsn("?sslmode=disable"), { env: {} })).toBe(false);
  });

  test("a prototype key is a miss, not a hit on Object.prototype", () => {
    // `SSLMODE_VALUES` is a Map for the same reason `own.ts` exists. As an object
    // literal, `?sslmode=constructor` would resolve to a function and pass.
    expect(() => sslModeFromConnectionString(dsn("?sslmode=constructor"))).toThrow(
      /Unknown sslmode 'constructor'/,
    );
    expect(() => sslModeFromConnectionString(dsn("?sslmode=__proto__"))).toThrow(
      /Unknown sslmode '__proto__'/,
    );
  });
});

describe("connectionStringWithoutTlsParameters", () => {
  test("removes every parameter pg's parser inspects", () => {
    const stripped = connectionStringWithoutTlsParameters(
      "postgres://u:p@h:5432/db?sslmode=verify-full&sslrootcert=/ca.pem&sslcert=/c.pem" +
        "&sslkey=/k.pem&sslpassword=x&ssl=true&sslnegotiation=direct&uselibpqcompat=true",
    );
    expect(stripped).toBe("postgres://u:p@h:5432/db");
  });

  test("preserves non-TLS parameters, their order, and a fragment", () => {
    expect(
      connectionStringWithoutTlsParameters(
        "postgres://u@h/db?application_name=svc&sslmode=require&connect_timeout=5#frag",
      ),
    ).toBe("postgres://u@h/db?application_name=svc&connect_timeout=5#frag");
  });

  test("leaves a DSN with no query string untouched", () => {
    expect(connectionStringWithoutTlsParameters("postgres://u@h/db")).toBe("postgres://u@h/db");
  });

  test("matches parameter names case-insensitively", () => {
    expect(connectionStringWithoutTlsParameters("postgres://u@h/db?SSLMode=require&a=1")).toBe(
      "postgres://u@h/db?a=1",
    );
  });

  test("sslnegotiation survives the strip as an explicit option", () => {
    expect(sslNegotiationFromConnectionString("postgres://u@h/db?sslnegotiation=direct")).toBe("direct");
    expect(sslNegotiationFromConnectionString("postgres://u@h/db?sslmode=require")).toBeUndefined();
    expect(() => sslNegotiationFromConnectionString("postgres://u@h/db?sslnegotiation=sideways")).toThrow(
      /Unknown sslnegotiation/,
    );
  });
});
