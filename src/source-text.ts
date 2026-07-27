// Reading source the way a compiler does, not the way `grep` does.
//
// WHY THIS EXISTS. The no-cloud gate used bare substring matching over file
// text. That made three things indistinguishable: a dependency edge, a string
// that names a package, and a sentence in a comment explaining that the
// package was removed. The remediated repo `@hasna/connectors@1.4.0` failed
// the gate on a JSDoc line reading "previously imported from `@hasna/cloud`,
// which is retired" — prose describing the fix, scored as the defect.
//
// So: mask comments before matching, and know which identifiers actually came
// from an import.
//
// WHERE THE FAIL-OPEN GUARANTEE STOPS. When the masker DETECTS that it lost
// the thread — an unterminated string, template or block comment — it discards
// the whole mask and the caller scans raw text. That is a false positive, never
// a false negative, and it is the behaviour to preserve.
//
// It is not a blanket guarantee, and an earlier version of this file claimed it
// was. A masker that silently mis-parses believes it succeeded, so nothing
// falls back. Two such bugs were found by review, both of them blanking live
// code while leaving the comment intact:
//
//   - indexing the text as code points while addressing it in UTF-16 units, so
//     a single emoji shifted every later mask (see `toUnits`);
//   - lexing JSX text as code, where `<code>src/*</code>` opens a block comment
//     that runs to the next close anywhere in the file (see
//     `commentSyntaxForPath`).
//
// Anything added here needs the same question asked of it: not "does it mask
// the comment" but "can it mask something that is not one".

/** Families we can mask. Anything else is returned untouched. */
export type CommentSyntax = "c-like" | "hash" | "none";

const C_LIKE_EXTENSIONS = /\.(?:[cm]?[jt]s)$/i;
const HASH_EXTENSIONS = /\.(?:sh|bash|ya?ml|toml)$/i;

/**
 * Which comment syntax a path uses.
 *
 * Two families are deliberately "none", and both are load-bearing:
 *
 * `.json` — JSON has no comments and JSONC does. Guessing wrong would hide a
 * reference in the one format that actually carries dependency edges.
 *
 * `.jsx`/`.tsx` — JSX text is not lexable without a real parser, and guessing
 * costs a FALSE NEGATIVE rather than a false positive. `<code>src/*</code>`
 * opens what looks like a block comment, which then runs to the next `*&#47;`
 * anywhere in the file and masks every import in between. A bare URL in a text
 * node does the same to one line. So JSX is scanned exactly as it was before
 * comment masking existed: noisier, never blind.
 */
export function commentSyntaxForPath(path: string): CommentSyntax {
  const name = path.replaceAll("\\", "/").split("/").pop() ?? path;
  if (name === ".env" || name.startsWith(".env.")) return "hash";
  if (C_LIKE_EXTENSIONS.test(name)) return "c-like";
  if (HASH_EXTENSIONS.test(name)) return "hash";
  return "none";
}

/**
 * Split into UTF-16 code units, NOT code points.
 *
 * This has to match how the rest of this module addresses the text. Every
 * offset here comes from `String.prototype.indexOf` and `text[index]`, which
 * are UTF-16 based. `[...text]` iterates CODE POINTS, so one astral character
 * — an emoji in a CLI menu is enough — makes the array shorter than the string
 * and shifts every later mask left of where it belongs. The comment survives
 * and the code after it gets blanked instead, which is a false negative: the
 * masker believes it succeeded, so nothing falls back to raw text.
 */
function toUnits(text: string): string[] {
  return text.split("");
}

/** Replace a span with spaces, so every index in the masked text still lines up with the original. */
function blank(chars: string[], start: number, end: number): void {
  for (let index = start; index < end; index += 1) {
    if (chars[index] !== "\n") chars[index] = " ";
  }
}

/**
 * A `/` opens a regex literal only where a value may begin. Tracking that is
 * what keeps `const re = /["']/;` from being read as an unterminated string,
 * which would drag the rest of the file into string state.
 *
 * The classic heuristic: after a value (identifier, literal, `]`) a slash is
 * division; after an operator, punctuation, or a value-position keyword it
 * opens a regex.
 *
 * `)` is NOT decidable from the character alone and this function no longer
 * pretends otherwise — see `slashOpensRegex`.
 */
const VALUE_POSITION_KEYWORD = /(?:^|[^\w$])(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/;

function regexCanStart(before: string): boolean {
  const trimmed = before.replace(/\s+$/, "");
  if (trimmed === "") return true;
  const last = trimmed[trimmed.length - 1]!;
  if (/[\])}]/.test(last)) {
    // `}` closes a block far more often than an object literal in the positions
    // that matter here, so treat it as value-position; `]` is a value. `)` never
    // reaches here.
    return last === "}";
  }
  if (/[\w$]/.test(last)) return VALUE_POSITION_KEYWORD.test(trimmed);
  if (last === "'" || last === '"' || last === "`") return false;
  return true;
}

/**
 * What a `(` opened: the head of a control statement, or a value.
 *
 * This is the discriminator the masker was missing. After `)` the old rule said
 * "division, always", and in JS that is wrong for exactly the shape a guard
 * test writes: `if (s) /a[//]b/.test(s)` opens a REGEX after the `)`. Calling it
 * division walked the lexer into the regex body, met the `//` inside the
 * character class, and blanked the rest of the line — including a live
 * `require()` of the retired runtime. The masker believed it had succeeded, so
 * the fail-open path never fired and the scan reported a clean tree.
 *
 * The provenance of the `(` settles it: a control head (`if`, `for`, `while`,
 * `switch`, `catch`, `with`) is followed by a statement, where a `/` opens a
 * regex; anything else — a call, a grouping — is followed by an operator
 * position, where a `/` is division.
 */
type ParenKind = "control" | "value";
const CONTROL_HEAD_KEYWORD = /(?:^|[^\w$])(?:if|for|while|switch|catch|with)\s*$/;

/**
 * Would reading this `/` as a regex rather than as division change what gets
 * masked?
 *
 * Only when the would-be regex body contains a comment opener. If it does not,
 * both readings mask the same characters and the ambiguity is harmless; if it
 * does, one reading blanks live code and the other does not, and we have no way
 * to tell which is right. That is the "could not classify" case the header
 * promises to fail open on.
 */
function ambiguityChangesTheMask(text: string, index: number): boolean {
  const end = scanRegex(text, index);
  if (end === null) return false;
  const body = text.slice(index + 1, end);
  return body.includes("//") || body.includes("/*");
}

/**
 * Does the `/` at `index` open a regex literal?
 *
 * `null` means the lexer cannot tell, and the caller must discard the whole
 * mask rather than guess — the fail-open guarantee this module's header
 * describes.
 */
function slashOpensRegex(text: string, index: number, lastCloseParen: ParenKind | "unbalanced" | null): boolean | null {
  const before = text.slice(Math.max(0, index - 64), index);
  if (!before.replace(/\s+$/, "").endsWith(")")) return regexCanStart(before);
  if (lastCloseParen === "control") return true;
  // An unbalanced `)`, or one whose `(` fell outside anything we tracked, is a
  // parse we do not have. Refuse to blank on the strength of it.
  if (lastCloseParen === null || lastCloseParen === "unbalanced") return null;
  return ambiguityChangesTheMask(text, index) ? null : false;
}

/**
 * A span of the source that is not code: a comment, or a string/template
 * literal.
 *
 * The masker needs the comments. The guard-test mention audit needs the
 * literals and the bracket they sit inside, which is why one lexer produces
 * both rather than two state machines drifting apart.
 */
export interface SourceToken {
  kind: "comment" | "literal";
  start: number;
  /** Exclusive. */
  end: number;
  /**
   * Callees of every unclosed call this token sits inside, innermost last.
   * `null` entries are groupings and control heads, which call nothing.
   */
  callees?: ReadonlyArray<string | null>;
  /** A template chunk that RESUMES after `${…}`, so its own text is spliced with computed values. */
  interpolated?: true;
}

/** The callee immediately before a `(`, last member segment only: `Bun.resolveSync` -> `resolveSync`. */
const CALLEE_BEFORE_PAREN = /([A-Za-z_$][\w$]*)\s*$/;

/**
 * A `(` that calls whatever another expression produced, so the callee has no
 * name to check: `createRequire(import.meta.url)("@hasna/cloud")` and
 * `loaders["cjs"]("@hasna/cloud")`. Not an identifier, so it can never appear on
 * an allowlist — which is the point. Reading it as "no callee" made the
 * immediately-invoked form look like a plain grouping.
 */
const UNNAMEABLE_CALLEE = "()";

function calleeBefore(text: string, parenIndex: number): string | null {
  const before = text.slice(Math.max(0, parenIndex - 96), parenIndex).replace(/\s+$/, "");
  if (before.endsWith(")") || before.endsWith("]")) return UNNAMEABLE_CALLEE;
  return CALLEE_BEFORE_PAREN.exec(before)?.[1] ?? null;
}

/**
 * Lex C-family source into its comment and literal spans.
 *
 * Returns `null` when the scan ends inside a string, template, regex or block
 * comment, or when it hits a slash it cannot classify. That means the state
 * machine lost the thread — JSX text with an apostrophe is the common cause —
 * and the caller must fall back to raw text.
 */
function lexCLike(text: string): SourceToken[] | null {
  const tokens: SourceToken[] = [];
  let index = 0;
  const length = text.length;
  // Template-literal nesting: each `${` pushes a frame we must pop at its `}`.
  const templateDepths: number[] = [];
  let braceDepth = 0;
  // Bracket frames, so a literal knows which calls enclose it. `(` carries its
  // callee; `[` and `{` call nothing.
  const brackets: Array<{ paren: boolean; callee: string | null }> = [];
  const parens: ParenKind[] = [];
  let lastCloseParen: ParenKind | "unbalanced" | null = null;

  const enclosingCallees = (): ReadonlyArray<string | null> => brackets.filter((frame) => frame.paren).map((frame) => frame.callee);

  while (index < length) {
    const character = text[index]!;
    const next = text[index + 1];

    // Comments are invisible to the `)`-then-`/` rule, so they do not clear
    // `lastCloseParen`.
    if (character === "/" && next === "/") {
      let end = text.indexOf("\n", index);
      if (end === -1) end = length;
      tokens.push({ kind: "comment", start: index, end });
      index = end;
      continue;
    }

    if (character === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      if (end === -1) return null;
      tokens.push({ kind: "comment", start: index, end: end + 2 });
      index = end + 2;
      continue;
    }

    if (character === '"' || character === "'") {
      const end = scanQuoted(text, index, character);
      if (end === null) return null;
      tokens.push({ kind: "literal", start: index, end, callees: enclosingCallees() });
      index = end;
      lastCloseParen = null;
      continue;
    }

    if (character === "`") {
      const chunk = scanTemplateChunk(text, index + 1);
      if (chunk === null) return null;
      tokens.push({ kind: "literal", start: index, end: chunk.index, callees: enclosingCallees() });
      // A template that closes on the same chunk never opened a frame.
      if (!chunk.closed) templateDepths.push(braceDepth);
      index = chunk.index;
      lastCloseParen = null;
      continue;
    }

    if (character === "$" && next === "{" && templateDepths.length > 0) {
      braceDepth += 1;
      index += 2;
      lastCloseParen = null;
      continue;
    }

    if (character === "}" && templateDepths.length > 0 && braceDepth === templateDepths[templateDepths.length - 1]! + 1) {
      braceDepth -= 1;
      const chunk = scanTemplateChunk(text, index + 1);
      if (chunk === null) return null;
      tokens.push({ kind: "literal", start: index, end: chunk.index, callees: enclosingCallees(), interpolated: true });
      if (chunk.closed) templateDepths.pop();
      index = chunk.index;
      lastCloseParen = null;
      continue;
    }

    if (character === "{") braceDepth += 1;
    if (character === "}" && braceDepth > 0) braceDepth -= 1;

    if (character === "(") {
      // A control head calls nothing, so its `(` carries no callee: a condition
      // cannot resolve a specifier, and reading `if` as a callee name would put
      // every `if ("…" in pkg.dependencies)` on the wrong side of the audit.
      const control = CONTROL_HEAD_KEYWORD.test(text.slice(Math.max(0, index - 32), index));
      parens.push(control ? "control" : "value");
      brackets.push({ paren: true, callee: control ? null : calleeBefore(text, index) });
      lastCloseParen = null;
      index += 1;
      continue;
    }

    if (character === ")") {
      lastCloseParen = parens.pop() ?? "unbalanced";
      if (brackets[brackets.length - 1]?.paren) brackets.pop();
      index += 1;
      continue;
    }

    if (character === "[" || character === "{") {
      brackets.push({ paren: false, callee: null });
      lastCloseParen = null;
      index += 1;
      continue;
    }

    if (character === "]" || character === "}") {
      if (brackets[brackets.length - 1]?.paren === false) brackets.pop();
      lastCloseParen = null;
      index += 1;
      continue;
    }

    if (character === "/") {
      const opensRegex = slashOpensRegex(text, index, lastCloseParen);
      if (opensRegex === null) return null;
      if (opensRegex) {
        const end = scanRegex(text, index);
        // An unrecognised slash is division, not a broken parse: keep going.
        if (end !== null) {
          index = end;
          lastCloseParen = null;
          continue;
        }
      }
    }

    if (!/\s/.test(character)) lastCloseParen = null;
    index += 1;
  }

  if (templateDepths.length > 0) return null;
  return tokens;
}

/** Mask C-family comments, preserving length. `null` when the lexer lost the thread. */
function maskCLike(text: string): string | null {
  const tokens = lexCLike(text);
  if (tokens === null) return null;
  const chars = toUnits(text);
  for (const token of tokens) {
    if (token.kind === "comment") blank(chars, token.start, token.end);
  }
  return chars.join("");
}

/** Index just past the closing quote, or null if unterminated. */
function scanQuoted(text: string, start: number, quote: string): number | null {
  for (let index = start + 1; index < text.length; index += 1) {
    const character = text[index]!;
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (character === quote) return index + 1;
    // A bare newline ends a normal string literal; an unterminated one is a parse failure.
    if (character === "\n") return null;
  }
  return null;
}

/**
 * Consume template text up to the backtick that closes it or the `${` that
 * interrupts it.
 *
 * `closed` is what tells the caller whether a frame opened or shut. Getting
 * that wrong leaves the frame stack permanently non-empty, the parse is judged
 * a failure, and the file falls back to raw text — quietly restoring the exact
 * substring matching this module removes. It read as a masking failure on
 * files that were masked correctly.
 */
function scanTemplateChunk(text: string, start: number): { index: number; closed: boolean } | null {
  for (let index = start; index < text.length; index += 1) {
    const character = text[index]!;
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (character === "`") return { index: index + 1, closed: true };
    if (character === "$" && text[index + 1] === "{") return { index, closed: false };
  }
  return null;
}

/** Index just past the closing `/` and flags, or null if this slash was not a regex. */
function scanRegex(text: string, start: number): number | null {
  let inClass = false;
  for (let index = start + 1; index < text.length; index += 1) {
    const character = text[index]!;
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (character === "\n") return null;
    if (character === "[") inClass = true;
    else if (character === "]") inClass = false;
    else if (character === "/" && !inClass) {
      let end = index + 1;
      while (end < text.length && /[a-z]/i.test(text[end]!)) end += 1;
      return end;
    }
  }
  return null;
}

/**
 * Mask `#` comments for shell, YAML and TOML.
 *
 * YAML's rule — `#` opens a comment only at line start or after whitespace —
 * is the strict one, so `foo#bar` stays visible. Quote tracking is per line,
 * which is what shell and YAML flow scalars need.
 */
function maskHash(text: string): string {
  const chars = toUnits(text);
  let lineStart = 0;
  while (lineStart <= text.length) {
    let lineEnd = text.indexOf("\n", lineStart);
    if (lineEnd === -1) lineEnd = text.length;
    let inSingle = false;
    let inDouble = false;
    for (let index = lineStart; index < lineEnd; index += 1) {
      const character = text[index]!;
      if (character === "\\" && inDouble) {
        index += 1;
        continue;
      }
      if (character === "'" && !inDouble) inSingle = !inSingle;
      else if (character === '"' && !inSingle) inDouble = !inDouble;
      else if (character === "#" && !inSingle && !inDouble) {
        const previous = index === lineStart ? "" : text[index - 1]!;
        if (previous === "" || /\s/.test(previous)) {
          blank(chars, index, lineEnd);
          break;
        }
      }
    }
    if (lineEnd === text.length) break;
    lineStart = lineEnd + 1;
  }
  return chars.join("");
}

/**
 * The text with comments replaced by spaces, same length, same line numbers.
 *
 * Fails open to the original text: an unparseable file is scanned exactly as
 * it was before this module existed.
 */
export function maskComments(text: string, syntax: CommentSyntax): string {
  if (syntax === "hash") return maskHash(text);
  if (syntax === "c-like") return maskCLike(text) ?? text;
  return text;
}

/** Convenience: mask by file path. */
export function maskCommentsForPath(text: string, path: string): string {
  return maskComments(text, commentSyntaxForPath(path));
}

/**
 * Callees that can only READ a string, never resolve it to a module.
 *
 * An ALLOWLIST, and that direction is the whole point. The first version of the
 * guard-test exemption enumerated the two load shapes it knew about — `import(`
 * and `require(` — and every other way of reaching the package walked straight
 * past it while the scan reported a clean tree.
 *
 * What each of those shapes actually does, measured rather than asserted,
 * because the distinction is the reason this is a CAPABILITY check and not a
 * load check:
 *
 *   - `createRequire(import.meta.url)("…")` — loads and EXECUTES the module.
 *   - `Bun.resolveSync("…", dir)` — performs package resolution and returns a
 *     path. No execution, and it throws when the package is absent, so it is a
 *     working probe for presence either way.
 *   - `require.resolve("…")` — the same: resolves without executing.
 *   - `new Worker(new URL("…", import.meta.url))` — does NOT do package
 *     resolution. `new URL("@hasna/cloud/worker.js", "file:///repo/src/x.ts")`
 *     resolves RELATIVE, to `file:///repo/src/@hasna/cloud/worker.js`. It is
 *     here because a guard test asserting absence has no reason to construct a
 *     module URL at all, not because this particular spelling loads anything.
 *
 * So the rule is "this file can reach modules, and a file that only asserts
 * absence should not be able to", which is weaker than "this file loads the
 * package" and is the claim the code can actually support. Listing the dangerous
 * shapes is how you miss the next one, so this lists the safe ones and an
 * unrecognised callee withdraws the exemption.
 *
 * Matched on the LAST member segment, so `require.resolve` is read as `resolve`
 * and `Bun.resolveSync` as `resolveSync` — neither of which is here. That is
 * also why plain `resolve` is absent even though `node:path` exports one: it
 * cannot be told apart from a resolver's, and a guard test can use `join`.
 */
const INERT_CALLEES: ReadonlySet<string> = new Set([
  // Assertions. A guard test's whole job.
  "expect",
  "not",
  "toBe",
  "toEqual",
  "toStrictEqual",
  "toContain",
  "toContainEqual",
  "toMatch",
  "toMatchObject",
  "toHaveProperty",
  "toBeUndefined",
  "toBeDefined",
  // Test scaffolding, because the package name is a natural test title.
  "describe",
  "it",
  "test",
  // String and collection inspection.
  "includes",
  "indexOf",
  "lastIndexOf",
  "startsWith",
  "endsWith",
  "has",
  "match",
  "search",
  "split",
  "concat",
  // Reads bytes off disk, or composes a path string. Neither resolves a
  // specifier nor executes a module, and a guard test asserting the package is
  // absent from `node_modules` needs both. `resolve` is NOT here: `node:path`
  // exports one and so does every module resolver, and the last member segment
  // is all we match on.
  "existsSync",
  "statSync",
  "lstatSync",
  "readFileSync",
  "readdirSync",
  "join",
  "basename",
  "dirname",
  "extname",
  "relative",
  "normalize",
  "push",
  "add",
  "filter",
  "some",
  "every",
  "find",
  "map",
  // Pattern building: `new RegExp(String.raw`…`)` is the mandated guard shape.
  "RegExp",
  "raw"
]);

/**
 * Can this source only MENTION `moduleName`, never load it?
 *
 * Answers the one question the guard-test exemption rests on. The exemption
 * exists because the mandated guard test must name the retired runtime in order
 * to assert its absence; it must not become a way to load it. So every literal
 * occurrence has to sit somewhere that provably cannot resolve a specifier:
 * bound to a variable, an element of an array, a property value, or an argument
 * to one of `INERT_CALLEES`.
 *
 * Fails CLOSED — `false` — on anything it cannot read: a JSX file, a lexer that
 * lost the thread, an interpolated template chunk, an occurrence outside every
 * literal. A false positive costs a repo one line; a false negative costs the
 * gate its meaning.
 */
export function mentionsCannotLoad(text: string, path: string, moduleName: string): boolean {
  // Proving a mention inert needs the token stream, and JSX is not lexable
  // without a real parser — see `commentSyntaxForPath`. So a JSX guard test
  // cannot claim the exemption at all.
  if (commentSyntaxForPath(path) !== "c-like") return false;
  const tokens = lexCLike(text);
  if (tokens === null) return false;

  for (let at = text.indexOf(moduleName); at !== -1; at = text.indexOf(moduleName, at + 1)) {
    const end = at + moduleName.length;
    const token = tokens.find((candidate) => at >= candidate.start && end <= candidate.end);
    // Prose. The caller already masked it; this loop reads raw text so the
    // offsets line up with the lexer.
    if (token?.kind === "comment") continue;
    // Bare in code, or straddling a token boundary: not something we can read.
    if (token === undefined || token.kind !== "literal") return false;
    // A chunk spliced with computed values is a specifier under construction.
    if (token.interpolated) return false;
    if (!(token.callees ?? []).every((callee) => callee === null || INERT_CALLEES.has(callee))) return false;
  }
  return true;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * The three quotes a specifier can be written in.
 *
 * The backtick is the one that was missing, and leaving it out cost a FALSE
 * NEGATIVE rather than noise: a template-literal specifier is a real load the
 * loader honours, so reading only `"` and `'` reported "no import here" about
 * working code. In the one file the guard-test allowlist exempts, that was the
 * whole difference between a critical edge and a clean scan.
 */
const SPECIFIER_QUOTE = "[\"'`]";
/** Anything that is not a quote, so a run stays inside one specifier. */
const SPECIFIER_CHAR = "[^\"'`]";

/**
 * A quoted specifier that resolves to `moduleName`.
 *
 * The name is matched as a PATH SEGMENT anywhere in the specifier, not as a
 * prefix. Anchoring it at the opening quote read a re-scoped publish
 * (`@hasna/open-cloud`) and a vendored copy (`../vendor/cloud-mcp/index.js`)
 * as unrelated packages, and both are real imports of the retired runtime.
 *
 * Segment boundaries keep the match from sliding back into substrings:
 * `open-cloudy` and `@acme/my-open-cloud` stay out OF THIS MATCHER. They are
 * still reported by the caller's bare-mention fallback — the false-positive
 * direction, and deliberate — but this comment used to read as though the
 * scanner cleared them, and it does not.
 */
/**
 * Quote characters a module specifier may be written with. Backticks count:
 * `import(`@hasna/cloud`)` is a static, resolvable import that a matcher
 * accepting only " and ' walked straight past — inside the allowlisted guard
 * test, where it was then scored as a mention and exempted outright.
 */
function moduleSpecifier(moduleName: string): string {
  // Path SEGMENT, not prefix: an optional directory, the name, an optional
  // deep path. Segment boundaries keep `open-cloudy` and `@acme/my-open-cloud`
  // out of THIS matcher — the caller's bare-mention fallback still reports
  // them, which is the false-positive direction and deliberate.
  return `${SPECIFIER_QUOTE}(?:${SPECIFIER_CHAR}*/)?${escapeRegex(moduleName)}(?:/${SPECIFIER_CHAR}*)?${SPECIFIER_QUOTE}`;
}



/**
 * Does this text import the module — in any of the four forms that create an
 * edge — including deep imports like `@hasna/cloud/dist/adapter.js`?
 *
 * `from "x"` covers both `import ... from` and `export ... from`. The
 * whitespace after a bare `import` is optional because `import"x/register";`
 * is the same side-effect import with the space deleted.
 */
export function importsModule(maskedText: string, moduleName: string): boolean {
  const pattern = new RegExp(
    String.raw`(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s*)` + moduleSpecifier(moduleName),
  );
  return pattern.test(maskedText);
}

/**
 * Local names bound by importing `moduleName`.
 *
 * This is what separates `iapp-files`' own `registerCloudTools` — defined in
 * `src/mcp/cloud-tools.ts` and routed at the self-hosted service — from the
 * retired shared runtime's export of the same name. A bare identifier says
 * nothing about where it came from; the import statement says everything.
 */
export function importedBindings(maskedText: string, moduleName: string): Set<string> {
  const bindings = new Set<string>();
  const specifier = moduleSpecifier(moduleName);

  // import <clause> from "mod"  /  export <clause> from "mod"
  const statement = new RegExp(String.raw`\b(?:import|export)\s+([^;]*?)\bfrom\s*${specifier}`, "g");
  // const <clause> = require("mod")  /  = await import("mod")
  const assignment = new RegExp(
    String.raw`(?:const|let|var)\s+([^=;]*?)=\s*(?:await\s+)?(?:require|import)\s*\(\s*${specifier}\s*\)`,
    "g",
  );

  for (const pattern of [statement, assignment]) {
    for (const match of maskedText.matchAll(pattern)) {
      for (const name of clauseBindings(match[1] ?? "")) bindings.add(name);
    }
  }
  return bindings;
}

const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;

/**
 * Pull local names out of an import clause or destructuring pattern.
 *
 * Handles `{ a, b as c }`, `* as ns`, a default binding, and the mixed forms.
 * `as` renames bind the RIGHT-hand name — that is the one in scope.
 */
function clauseBindings(clause: string): string[] {
  const names: string[] = [];
  const braced = /\{([^}]*)\}/.exec(clause);
  if (braced) {
    for (const part of braced[1]!.split(",")) {
      const pieces = part.split(/\s+as\s+|:/);
      const name = (pieces[pieces.length - 1] ?? "").trim();
      if (IDENTIFIER.test(name)) names.push(name);
    }
  }
  const namespace = /\*\s+as\s+([A-Za-z_$][\w$]*)/.exec(clause);
  if (namespace) names.push(namespace[1]!);

  const head = clause.replace(/\{[^}]*\}/g, "").replace(/\*\s+as\s+[A-Za-z_$][\w$]*/g, "");
  for (const part of head.split(",")) {
    const name = part.replace(/\btype\b/g, "").trim();
    if (IDENTIFIER.test(name)) names.push(name);
  }
  return names;
}
