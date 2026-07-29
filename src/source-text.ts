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
 * What one pass of the lexer learned about the text.
 *
 * The token spans and the argument openers come off the SAME bracket stack on
 * purpose. Deciding "is this collection a call argument" from a second scan
 * would be a second state machine drifting apart from this one, which is the
 * class of bug this file's header is about.
 */
interface LexResult {
  tokens: SourceToken[];
  /**
   * Indices of the `[` and `{` that open DIRECTLY inside a call's argument
   * list — the `[` of `f(x, [...])`.
   *
   * The INNERMOST enclosing frame decides, and that bound is load-bearing: a
   * constant declared inside a callback body sits under a call frame too, and
   * `__commonJS((exports, module) => { var DENY = [...]; })` is what a bundler
   * emits for every CommonJS module it wraps. Rejecting on any enclosing call
   * would unattribute those.
   */
  callArgumentOpeners: Set<number>;
}

/**
 * Lex C-family source into its comment and literal spans.
 *
 * Returns `null` when the scan ends inside a string, template, regex or block
 * comment, or when it hits a slash it cannot classify. That means the state
 * machine lost the thread — JSX text with an apostrophe is the common cause —
 * and the caller must fall back to raw text.
 */
function lexCLike(text: string): LexResult | null {
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
  const callArgumentOpeners = new Set<number>();

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
      // A control head and a grouping call nothing, so neither makes what they
      // enclose an argument; a named callee and `UNNAMEABLE_CALLEE` both do.
      const enclosing = brackets[brackets.length - 1];
      if (enclosing?.paren === true && enclosing.callee !== null) callArgumentOpeners.add(index);
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
  return { tokens, callArgumentOpeners };
}

/** Mask C-family comments, preserving length. `null` when the lexer lost the thread. */
function maskCLike(text: string): string | null {
  const lexed = lexCLike(text);
  if (lexed === null) return null;
  const chars = toUnits(text);
  for (const token of lexed.tokens) {
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
  const lexed = lexCLike(text);
  if (lexed === null) return false;

  for (let at = text.indexOf(moduleName); at !== -1; at = text.indexOf(moduleName, at + 1)) {
    const end = at + moduleName.length;
    const token = lexed.tokens.find((candidate) => at >= candidate.start && end <= candidate.end);
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
 * A constant data structure spelled out in source: a literal array, a literal
 * record, or a string.
 *
 * WHY THIS EXISTS. A bundler that inlines a dependency copies that
 * dependency's constants into the consumer's output verbatim. The consumer did
 * not write them and cannot delete them. Deciding what to do about that needs
 * the STRUCTURE the names sit in, because that is the only place the answer
 * lives: a filename cannot tell a copied constant from a hand-written one, and
 * the presence or absence of import specifiers elsewhere in the file cannot
 * either — a bundle that inlines `package.json` carries a whole `dependencies`
 * map with no specifier anywhere near it.
 *
 * Deliberately NOT a JS parser. It reads one shape only: collections whose
 * leaves are all string literals. That shape can hold data and nothing else —
 * no call, no identifier, no computed member, no template with a substitution.
 * Anything else makes the parse fail, and a failed parse yields no region, so
 * the caller learns nothing and scans the text as it stands.
 */
export type InlineDataNode =
  | { kind: "string"; value: string; start: number; end: number }
  | { kind: "array"; items: readonly InlineDataNode[]; start: number; end: number }
  | { kind: "record"; entries: ReadonlyMap<string, InlineDataNode>; start: number; end: number };

/** An outermost inert collection, with the name it is bound to if it has one. */
export interface InlineDataRegion {
  root: InlineDataNode;
  /**
   * The identifier this collection is assigned to — `RUNTIME_PATTERNS` in
   * `var RUNTIME_PATTERNS = [...]`. `null` when the collection is not assigned
   * to anything, which is also the answer when we could not read a name.
   */
  boundName: string | null;
  start: number;
  end: number;
}

/**
 * How far back from an occurrence we look for the collection enclosing it.
 *
 * A bound, not a guess: the parse is attempted from every `[` and `{` in this
 * window, so an unbounded window would make a large file quadratic. The
 * declarations this exists to recognise are one line each; 4 KiB is three
 * orders of magnitude of headroom, and a structure that does not fit simply
 * yields no region — noise, never blindness.
 */
const INLINE_DATA_WINDOW = 4096;
const IDENTIFIER_TAIL = /([A-Za-z_$][\w$]*)\s*$/;
/** `readonly` is a type-only modifier, so what follows it is a type, not a value. */
const TYPE_POSITION_KEYWORD = /(?:^|[^\w$])readonly$/;
/** A record key, as it is written immediately before the `:` of its entry. */
const RECORD_KEY_TAIL = /(?:[A-Za-z_$][\w$]*|"[^"\n]*"|'[^'\n]*')\s*$/;

/** Read one string literal. Backticks count, but only without a substitution. */
function readStringLiteral(text: string, start: number): { value: string; end: number } | null {
  const quote = text[start];
  if (quote !== '"' && quote !== "'" && quote !== "`") return null;
  let value = "";
  for (let index = start + 1; index < text.length; index += 1) {
    const character = text[index]!;
    if (character === "\\") {
      const escaped = text[index + 1];
      if (escaped === undefined) return null;
      // Only the escapes needed to READ the literal are undone. An escape that
      // encodes a character another way — `\x40` for `@` — is left alone on
      // purpose: decoding it would let an obfuscated spelling claim whatever
      // the caller grants a recognised constant, and refusing to decode it
      // costs a missed recognition, which is the noisy direction.
      value += escaped === "\\" || escaped === '"' || escaped === "'" || escaped === "`" ? escaped : `\\${escaped}`;
      index += 1;
      continue;
    }
    if (character === quote) return { value, end: index + 1 };
    // A substitution makes this a template under construction, not a constant.
    if (quote === "`" && character === "$" && text[index + 1] === "{") return null;
    if (character === "\n" && quote !== "`") return null;
    value += character;
  }
  return null;
}

function skipSpace(text: string, index: number): number {
  let at = index;
  while (at < text.length && /\s/.test(text[at]!)) at += 1;
  return at;
}

/**
 * Parse one inert collection starting at `[` or `{`, or fail.
 *
 * Every failure is a refusal to describe the text, so the caller falls back to
 * reading it as it is. That is the direction this whole module fails in.
 */
function parseInlineData(text: string, start: number): InlineDataNode | null {
  const opener = text[start];
  if (opener === '"' || opener === "'" || opener === "`") {
    const literal = readStringLiteral(text, start);
    return literal === null ? null : { kind: "string", value: literal.value, start, end: literal.end };
  }
  if (opener === "[") {
    const items: InlineDataNode[] = [];
    let index = skipSpace(text, start + 1);
    while (index < text.length) {
      if (text[index] === "]") return { kind: "array", items, start, end: index + 1 };
      const item = parseInlineData(text, index);
      if (item === null) return null;
      items.push(item);
      index = skipSpace(text, item.end);
      if (text[index] === ",") index = skipSpace(text, index + 1);
      else if (text[index] !== "]") return null;
    }
    return null;
  }
  if (opener === "{") {
    const entries = new Map<string, InlineDataNode>();
    let index = skipSpace(text, start + 1);
    while (index < text.length) {
      if (text[index] === "}") return { kind: "record", entries, start, end: index + 1 };
      // A key is a bare identifier or a quoted string. A computed key `[k]` is
      // not a constant, so it ends the parse.
      const quoted = readStringLiteral(text, index);
      let key: string;
      if (quoted !== null) {
        key = quoted.value;
        index = skipSpace(text, quoted.end);
      } else {
        const identifier = /^[A-Za-z_$][\w$]*/.exec(text.slice(index, index + 128));
        if (identifier === null) return null;
        key = identifier[0];
        index = skipSpace(text, index + identifier[0].length);
      }
      if (text[index] !== ":") return null;
      index = skipSpace(text, index + 1);
      const value = parseInlineData(text, index);
      if (value === null) return null;
      // A REPEATED KEY IS AMBIGUITY, AND THE PARSER REFUSES TO DESCRIBE IT.
      // `Map.set` silently keeps the LAST value and shrinks the entry count, so
      // `{pattern, kind, message: <payload>, message: "…"}` would present itself
      // to a caller as a three-entry record whose every value equals a table row
      // — the shadowed value sits in no entry, so no entry-for-entry comparison
      // can reach it, while a span blanked on the strength of that comparison
      // still covers its characters. That is a free slot big enough for a
      // credential env key or a multi-line backtick, and it is reachable because
      // duplicate property names are legal JavaScript that a bundler preserves,
      // not a parse curiosity.
      //
      // Refusing is the cheap direction: nothing this package emits repeats a
      // key, so no real declaration is lost, and the caller falls back to reading
      // the text as it is — which is how every other failure here behaves.
      if (entries.has(key)) return null;
      entries.set(key, value);
      index = skipSpace(text, value.end);
      if (text[index] === ",") index = skipSpace(text, index + 1);
      else if (text[index] !== "}") return null;
    }
    return null;
  }
  return null;
}

/**
 * Is the text before a `:` the KEY of a record entry?
 *
 * The key on its own does not settle it, because a ternary alternate is written
 * the same way: `cond ? fallback : [...]`. What precedes the key does — the `{`
 * that opens the record, or the `,` that ends the previous entry.
 */
function recordKeyPrecedes(before: string): boolean {
  const key = RECORD_KEY_TAIL.exec(before);
  if (key === null) return false;
  const head = before.slice(0, key.index).replace(/\s+$/, "");
  return head.endsWith("{") || head.endsWith(",");
}

/**
 * Is this collection sitting where data sits, and does nothing read a member
 * out of it on the spot?
 *
 * Both halves close the same evasion: a collection is inert, but a member
 * PULLED OUT of one is an ordinary value that can be handed to a resolver.
 * `require(["a","b"][0])` is a real load whose specifier never appears as a
 * specifier. So the collection has to be in a position that only stores it —
 * after `=`, or as an element or property of another collection — and the
 * character after it must not be the `[`, `(`, `.` or `?.` that would consume
 * it in place.
 *
 * WHY THE BRACKET STACK AND NOT JUST THE CHARACTER BEFORE THE `[`. One character
 * can only see the FIRST argument of a call. `load([...])` was rejected on the
 * `(`, while `load(cfg, [...])`, `register("app", [...])` and
 * `loadAll(cfg, [...]).then(run)` landed on `,` and were read as stored
 * constants — attributed, and blanked. An argument is the callee's to do what it
 * likes with, and `list.forEach((m) => __require(m))` one module away is a load
 * whose specifier never appears in specifier position: the same shape as the
 * `for (const m of [...]) __require(m)` the position rule exists to reject.
 * `callArgumentOpeners` answers it for every argument position at once.
 */
function isInertPosition(text: string, start: number, end: number, callArgumentOpeners: ReadonlySet<number>): boolean {
  if (callArgumentOpeners.has(start)) return false;
  const before = text.slice(Math.max(0, start - 64), start).replace(/\s+$/, "");
  if (before !== "") {
    const last = before[before.length - 1]!;
    // `readonly [...]` is a tuple TYPE, erased at compile time and unreadable at
    // runtime. It is what `tsc` emits into the `.d.ts` beside every bundle, and
    // without it the scanner failed its own shipped `dist/schemas.d.ts`.
    // `readonly` is a type-only modifier, so this cannot admit a value position
    // by mistake — and it is accepted HERE rather than returned early, so the
    // consumed-in-place check below still applies to it. Returning early made
    // `readonly ["a","b"][0]` attributable; harmless, because an indexed access
    // on a type is still a type, but there is no reason to allow it.
    const typePosition = TYPE_POSITION_KEYWORD.test(before);
    if (!typePosition && !(last === "=" || last === "[" || last === "," || last === ":" || last === "(")) return false;
    // `=` must be assignment, not a comparison: `x === [...]` cannot store it,
    // and `!== [...]` is the same. `(` is allowed for a parenthesised value but
    // a CALL argument is not — that is `require([...][0])`'s outer shape.
    if (last === "=" && /[=!<>]$/.test(before.slice(0, -1))) return false;
    if (last === "(" && IDENTIFIER_TAIL.test(before.slice(0, -1))) return false;
    // `:` must introduce a record VALUE. A ternary alternate ends on the same
    // character and stores nothing, so the key has to be there and has to sit
    // where a key sits.
    if (!typePosition && last === ":" && !recordKeyPrecedes(before.slice(0, -1).replace(/\s+$/, ""))) return false;
  }
  const after = skipSpace(text, end);
  const next = text.slice(after, after + 2);
  if (next.startsWith("[") || next.startsWith("(") || next.startsWith(".") || next.startsWith("?.")) return false;
  return true;
}

function boundNameBefore(text: string, start: number): string | null {
  const before = text.slice(Math.max(0, start - 128), start).replace(/\s+$/, "");
  if (!before.endsWith("=")) return null;
  return IDENTIFIER_TAIL.exec(before.slice(0, -1))?.[1] ?? null;
}

/**
 * The outermost inert collections that contain any of `needles`.
 *
 * Driven from the occurrences rather than from every bracket in the file. A
 * file that names none of them costs one substring search per needle and
 * nothing else; a file that names one adds a single O(text) lex, which is what
 * tells a stored constant from a call ARGUMENT. Everything after that is
 * proportional to how many times the caller's names appear — a handful — and
 * not to the size of a bundle.
 *
 * OUTERMOST matters for `boundName`: the record `{ pattern: "…" }` is an
 * element of `RUNTIME_PATTERNS`, and it is the array that carries the name a
 * later `require(NAME[0])` would have to use.
 */
export function inlineDataRegions(text: string, needles: readonly string[]): InlineDataRegion[] {
  const regions: InlineDataRegion[] = [];
  const seen = new Set<number>();
  // Whether a collection is an ARGUMENT is a question about brackets, and the
  // lexer is what tracks them. It is O(text) where everything else here is
  // proportional to the occurrences, so it runs at the FIRST one rather than on
  // arrival: a file naming none of these — most of a tree — is never lexed.
  let lexed: LexResult | null | undefined;
  for (const needle of needles) {
    for (let at = text.indexOf(needle); at !== -1; at = text.indexOf(needle, at + 1)) {
      if (lexed === undefined) lexed = lexCLike(text);
      // A text the lexer cannot read yields no regions at all: nothing is
      // attributed, every occurrence in it is reported, which is the direction
      // the rest of this module fails in.
      if (lexed === null) return regions;
      const floor = Math.max(0, at - INLINE_DATA_WINDOW);
      const openers: number[] = [];
      for (let back = at; back >= floor; back -= 1) {
        const character = text[back];
        if (character === "[" || character === "{") openers.push(back);
      }
      // Farthest first: the widest collection that still parses and still
      // covers the occurrence is the outermost one.
      //
      // COVERAGE IS CHECKED BEFORE ANYTHING ELSE, and that ordering is the
      // whole correctness of this loop. An earlier version consulted `seen`
      // first, so an unrelated collection recorded a few hundred characters
      // upstream — a second declaration in the same bundle — ended the search
      // for an occurrence it does not contain, and the occurrence went
      // unattributed. It only reproduced when the two declarations were closer
      // together than this window, which is why a compact fixture caught it and
      // a real 336 KB bundle did not.
      for (const opener of openers.reverse()) {
        const root = parseInlineData(text, opener);
        if (root === null || root.kind === "string") continue;
        if (!(root.start <= at && at + needle.length <= root.end)) continue;
        // Enclosing, so it is the answer for this occurrence either way.
        if (seen.has(opener)) break;
        if (!isInertPosition(text, root.start, root.end, lexed.callArgumentOpeners)) break;
        seen.add(opener);
        regions.push({ root, boundName: boundNameBefore(text, root.start), start: root.start, end: root.end });
        break;
      }
    }
  }
  return regions;
}

/** Every node in a region, outermost first. */
export function inlineDataNodes(node: InlineDataNode): InlineDataNode[] {
  if (node.kind === "array") return [node, ...node.items.flatMap(inlineDataNodes)];
  if (node.kind === "record") return [node, ...[...node.entries.values()].flatMap(inlineDataNodes)];
  return [node];
}

/**
 * Callee shapes that resolve a module.
 *
 * `__require` is why this is not `\brequire`. `bun build --external` compiles a
 * CommonJS `require("x")` to `__require("x")`, and a word boundary does not
 * exist between `_` and `r`, so the plain spelling walked straight past the one
 * form that build output actually uses. A leading-underscore wrapper is the
 * convention across bundlers (`__require`, `__toESM`-fed requires), so the
 * underscores are matched rather than enumerated.
 *
 * `createRequire` and `Module._load` are spelled out because the underscore rule
 * does not reach them: `createRequire` has no boundary before `Require` AND
 * differs in case, and `_load` is a member. A review reached a copy of the
 * denylist through both.
 *
 * Widening this can only ADD findings, in both of its callers: `importsModule`
 * falls through to reporting the bare name when it fails to recognise a load, so
 * a name recognised here is reclassified rather than cleared; and
 * `loadCallMentions` only ever WITHDRAWS an attribution. There is no direction in
 * which a longer list here hides something.
 */
const LOAD_CALLEE = String.raw`(?:^|[^\w$])(?:_*(?:import|require)|createRequire|Module\s*\.\s*_load)`;

/**
 * How far past a load call's `(` we look for the `)` that closes it.
 *
 * A bound, not a guess. Reading to the end of the file whenever the brackets do
 * not balance — one `(` inside a regex character class is enough — would put
 * every identifier in the bundle inside "the argument list" and withdraw every
 * attribution in it. An argument list longer than this is not a call this rule
 * can read.
 */
const LOAD_ARGUMENT_WINDOW = 4096;

/**
 * The text between a call's `(` and the `)` that closes it.
 *
 * `[^)]*` stopped at the FIRST `)`, so `__require(norm(base), DENY[0])` handed
 * the bound-name test `norm(base` and nothing else. One nested call in an
 * earlier argument was the whole of what it took: the array it should have
 * withdrawn sits in inert position, so the name is the only thing linking it to
 * the load.
 *
 * String and template bodies are skipped for DEPTH only — their text stays in
 * the slice. A name that appears inside a literal can only ADD a withdrawal, and
 * a withdrawal only ever adds findings, which is the direction this module fails
 * in. An unreadable literal is read as an ordinary character rather than
 * abandoning the scan, so one stray apostrophe cannot decide this either.
 */
function loadCallArguments(text: string, open: number): string {
  const limit = Math.min(text.length, open + LOAD_ARGUMENT_WINDOW);
  let depth = 0;
  for (let index = open; index < limit; index += 1) {
    const character = text[index]!;
    if (character === '"' || character === "'" || character === "`") {
      const literalEnd = character === "`" ? scanTemplateLiteral(text, index) : scanQuoted(text, index, character);
      if (literalEnd !== null) {
        index = literalEnd - 1;
        continue;
      }
    }
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, index);
    }
  }
  return text.slice(open + 1, limit);
}

/** Index just past the backtick that closes the template at `start`, or null. */
function scanTemplateLiteral(text: string, start: number): number | null {
  for (let index = start + 1; index < text.length; index += 1) {
    const character = text[index]!;
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (character === "`") return index + 1;
  }
  return null;
}

/**
 * Does a load call in this text mention `name`?
 *
 * The companion to `isInertPosition`: that one refuses to explain away a
 * collection something reads a member out of ON THE SPOT, and this one refuses
 * when the collection was stored under a name and a load call names it —
 * `var X = [...]; __require(X[0]);`.
 *
 * Bounded to the argument list, because a load call is the only place a
 * specifier can arrive.
 */
export function loadCallMentions(text: string, name: string): boolean {
  const calls = new RegExp(`${LOAD_CALLEE}\\s*\\(`, "g");
  // Whole identifier, not a substring: `DENYLIST` is not `DENY`. The argument is
  // padded so the leading boundary always has a character to match — reading it
  // straight after the `(` left nothing there, and the check returned false for
  // the one shape it exists to catch, `__require(DENY[0])`.
  const bounded = new RegExp(`[^\\w$]${escapeRegex(name)}(?![\\w$])`);
  for (const match of text.matchAll(calls)) {
    const open = (match.index ?? 0) + match[0].length - 1;
    if (bounded.test(` ${loadCallArguments(text, open)}`)) return true;
  }
  return false;
}

/**
 * Replace the given spans with spaces, so every later offset still lines up.
 *
 * DELIBERATELY NOT EXPORTED. It takes an unconstrained `{start, end}`, so it is
 * the one function in this file that can suppress a byte nobody compared — and an
 * adversarial review used exactly that to restore the vulnerability in three
 * lines with ZERO casts and a green `tsc`: widen the span array's annotation in
 * `withoutInlinedDeclarations`, push `{start, end}`, and call this instead of
 * `blankConstantSpans`. Un-exporting it does not make that impossible, but it
 * moves the edit from "change one type annotation" to "re-export the unchecked
 * primitive", which is a line a reviewer will ask about.
 *
 * `blankConstantSpans` is the only caller, and the only way out of this module.
 */
function blankSpans(text: string, spans: ReadonlyArray<{ start: number; end: number }>): string {
  if (spans.length === 0) return text;
  const chars = toUnits(text);
  for (const span of spans) blank(chars, span.start, span.end);
  return chars.join("");
}

/**
 * A span whose BYTES have been read and found to be one quoted constant.
 *
 * `constant` is not decoration — it is the claim the span carries, and
 * `blankConstantSpans` re-checks it against the text before suppressing
 * anything. So a span cannot be moved, widened, or synthesised somewhere else
 * and still be blanked: it has to keep saying what it is, and be it.
 *
 * `quotedConstantSpan` is the only function that produces one. The TYPE is part of
 * the mechanism, but it is worth being exact about how much it buys, because the
 * first wording of this comment overstated it and a review measured the gap.
 *
 * WHAT IT DOES BUY: a plain `{start, end}` is not assignable here, so `tsc`
 * rejects the specific edit that reverted this rule four times in a row —
 * pushing the ENCLOSING node's span into the span list. That edit now needs an
 * explicit cast, which is greppable.
 *
 * WHAT IT DOES NOT BUY, measured: widening the span array's own annotation back
 * to `Array<{start: number; end: number}>` and calling an unchecked blanker
 * restores the vulnerability with ZERO casts and `tsc` green. So the type is a
 * guardrail against the obvious edit, NOT a proof. What actually catches a
 * determined revert is `blankConstantSpans`'s runtime re-check, the duplicate-key
 * forges, and the mutation audit. `blankSpans` is un-exported so that route needs
 * a visible re-export rather than a one-word annotation change.
 */
export interface ConstantSpan {
  readonly start: number;
  readonly end: number;
  /** The constant these bytes were compared against, quotes excluded. */
  readonly constant: string;
}

/** The three quotes a string literal can be written with. */
function quoteCharacter(character: string | undefined): boolean {
  return character === '"' || character === "'" || character === "`";
}

/**
 * The span of `node`, IF the bytes it covers are exactly one quoted `expected`.
 *
 * THIS IS THE WHOLE RULE, AND IT IS A BYTE COMPARISON ON PURPOSE.
 *
 * Four evasions reached a copy of this repo's own denylist through one gap:
 * every one of them was caught, or not caught, by a check that read a PARSED
 * structure while the caller suppressed RAW BYTES. The parse is lossy — most
 * recently and most cheaply, `parseInlineData` stores a record's entries in a
 * `Map`, so a duplicate key collapses last-wins and the shadowed value is a
 * region of text nothing ever looked at. Repeating one key was the entire cost
 * of getting a credential through a blanked span.
 *
 * So the comparison and the action are now on the SAME representation. What is
 * compared is `text.slice(node.start, node.end)`; what gets blanked is
 * `node.start .. node.end`. There is no third thing in between for a shape to
 * hide in.
 *
 * WHY THIS DELETES CHECKS INSTEAD OF ADDING ONE, which is the reason to believe
 * it is not another narrowing. Three separately-tested rules are strictly
 * implied by this single line and were removed with it:
 *
 *   - "the value must be a plain string, not a nested collection" — a record's
 *     span opens with `{` and an array's with `[`, so neither can equal
 *     `quote + expected + quote`;
 *   - "the value must equal the row's value" — that IS this comparison, on the
 *     stricter representation;
 *   - "the value's kind must be `string`" — subsumed by the opening quote.
 *
 * WHAT IT NEWLY REFUSES, and the refusal is deliberate: a literal that needs an
 * escape to spell the constant. `"a\"b"` decodes to `a"b`, so the old check
 * would call it equal — while the span it authorises is two bytes longer than
 * the thing that was compared. No pattern in the table contains a quote or a
 * backslash today, so this costs nothing measurable; it is here so that the
 * guarantee does not quietly depend on that staying true. A row that one day
 * needs an escape simply stops being attributed, which is the noisy direction.
 */
export function quotedConstantSpan(
  text: string,
  node: InlineDataNode | undefined,
  expected: string
): ConstantSpan | null {
  if (node === undefined) return null;
  const raw = text.slice(node.start, node.end);
  const quote = raw[0];
  if (!quoteCharacter(quote)) return null;
  if (raw !== `${quote}${expected}${quote}`) return null;
  return { start: node.start, end: node.end, constant: expected };
}

/**
 * Blank verified spans, re-checking each one's claim against the text first.
 *
 * The check is not belt-and-braces on `quotedConstantSpan`; it is what makes a
 * WRONG span observable instead of silent. A caller that casts its way past
 * `ConstantSpan` — or that computes an offset from one text and blanks it in
 * another — trips this, and it trips as a thrown error in the scanner's own
 * test suite rather than as a quietly clean scan of somebody's artifact.
 *
 * It throws rather than dropping the span, because a span that does not match
 * its own claim is a bug in this file, not something an input can cause. Every
 * shape an INPUT can produce is answered by returning `null` above.
 */
export function blankConstantSpans(text: string, spans: readonly ConstantSpan[]): string {
  for (const span of spans) {
    const raw = text.slice(span.start, span.end);
    const quote = raw[0];
    if (!quoteCharacter(quote) || raw !== `${quote}${span.constant}${quote}`) {
      throw new Error(
        `refusing to blank ${span.start}..${span.end}: its bytes are not the constant it claims`
      );
    }
  }
  return blankSpans(text, spans);
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
    String.raw`(?:\bfrom\s*|${LOAD_CALLEE}\s*\(\s*|\bimport\s*)` + moduleSpecifier(moduleName),
  );
  return pattern.test(maskedText);
}

/**
 * Local names bound by importing `moduleName`.
 *
 * This is what separates `iapp-files`' own `registerCloudTools` — defined in
 * `src/mcp/cloud-tools.ts` and routed at its own service — from the
 * retired shared runtime's export of the same name. A bare identifier says
 * nothing about where it came from; the import statement says everything.
 */
export function importedBindings(maskedText: string, moduleName: string): Set<string> {
  const bindings = new Set<string>();
  const specifier = moduleSpecifier(moduleName);

  // import <clause> from "mod"  /  export <clause> from "mod"
  const statement = new RegExp(String.raw`\b(?:import|export)\s+([^;]*?)\bfrom\s*${specifier}`, "g");
  // const <clause> = require("mod")  /  = await import("mod")  /  = __require("mod")
  const assignment = new RegExp(
    String.raw`(?:const|let|var)\s+([^=;]*?)=\s*(?:await\s+)?_*(?:require|import)\s*\(\s*${specifier}\s*\)`,
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
