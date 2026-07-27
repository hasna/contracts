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
 * The classic heuristic: after a value (identifier, literal, `)`, `]`) a slash
 * is division; after an operator, punctuation, or a value-position keyword it
 * opens a regex.
 */
const VALUE_POSITION_KEYWORD = /(?:^|[^\w$])(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/;

function regexCanStart(before: string): boolean {
  const trimmed = before.replace(/\s+$/, "");
  if (trimmed === "") return true;
  const last = trimmed[trimmed.length - 1]!;
  if (/[)\]}]/.test(last)) {
    // `}` closes a block far more often than an object literal in the positions
    // that matter here, so treat it as value-position; `)` and `]` are values.
    return last === "}";
  }
  if (/[\w$]/.test(last)) return VALUE_POSITION_KEYWORD.test(trimmed);
  if (last === "'" || last === '"' || last === "`") return false;
  return true;
}

/**
 * Mask C-family comments, preserving length.
 *
 * Returns `null` when the scan ends inside a string, template, regex or block
 * comment. That means the state machine lost the thread — JSX text with an
 * apostrophe is the common cause — and the caller must fall back to raw text.
 */
function maskCLike(text: string): string | null {
  const chars = toUnits(text);
  let index = 0;
  const length = text.length;
  // Template-literal nesting: each `${` pushes a frame we must pop at its `}`.
  const templateDepths: number[] = [];
  let braceDepth = 0;

  while (index < length) {
    const character = text[index]!;
    const next = text[index + 1];

    if (character === "/" && next === "/") {
      let end = text.indexOf("\n", index);
      if (end === -1) end = length;
      blank(chars, index, end);
      index = end;
      continue;
    }

    if (character === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      if (end === -1) return null;
      blank(chars, index, end + 2);
      index = end + 2;
      continue;
    }

    if (character === '"' || character === "'") {
      const end = scanQuoted(text, index, character);
      if (end === null) return null;
      index = end;
      continue;
    }

    if (character === "`") {
      const chunk = scanTemplateChunk(text, index + 1);
      if (chunk === null) return null;
      // A template that closes on the same chunk never opened a frame.
      if (!chunk.closed) templateDepths.push(braceDepth);
      index = chunk.index;
      continue;
    }

    if (character === "$" && next === "{" && templateDepths.length > 0) {
      braceDepth += 1;
      index += 2;
      continue;
    }

    if (character === "}" && templateDepths.length > 0 && braceDepth === templateDepths[templateDepths.length - 1]! + 1) {
      braceDepth -= 1;
      const chunk = scanTemplateChunk(text, index + 1);
      if (chunk === null) return null;
      if (chunk.closed) templateDepths.pop();
      index = chunk.index;
      continue;
    }

    if (character === "{") braceDepth += 1;
    if (character === "}" && braceDepth > 0) braceDepth -= 1;

    if (character === "/" && regexCanStart(text.slice(Math.max(0, index - 64), index))) {
      const end = scanRegex(text, index);
      // An unrecognised slash is division, not a broken parse: keep going.
      if (end !== null) {
        index = end;
        continue;
      }
    }

    index += 1;
  }

  if (templateDepths.length > 0) return null;
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

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * A quoted specifier that resolves to `moduleName`.
 *
 * The name is matched as a PATH SEGMENT anywhere in the specifier, not as a
 * prefix. Anchoring it at the opening quote read a re-scoped publish
 * (`@hasna/open-cloud`) and a vendored copy (`../vendor/cloud-mcp/index.js`)
 * as unrelated packages, and both are real imports of the retired runtime.
 *
 * Segment boundaries are what keep the match from sliding back into substrings:
 * `open-cloudy` and `@acme/my-open-cloud` are different packages and stay out.
 */
function moduleSpecifier(moduleName: string): string {
  return String.raw`["'](?:[^"']*/)?${escapeRegex(moduleName)}(?:/[^"']*)?["']`;
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
