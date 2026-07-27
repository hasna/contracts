// The dependency edge, resolved from the manifest and the lockfile.
//
// WHY THIS EXISTS. The gate's whole claim is "this package has no edge to the
// retired shared cloud runtime". It was checking that claim by looking for the
// package name as a substring of `bun.lock`. That is not the same question.
//
// `hasna/logs` is the case that decides how this module has to work, and the
// obvious reading of it is wrong. Its `bun.lock` names the retired runtime
// twice, so the substring check fails it, and the repo's own guard test
// dismisses those hits as "a dev-only lockfile that is never shipped". Both
// the check and the dismissal are guesses about what gets installed.
//
// It was measured instead. bun 1.3.14, isolated probe repos, both directions:
// a registry dependency's devDependencies are NOT installed, but a
// `file:`-linked dependency's ARE. `logs` reaches the retired runtime through
// a `file:`-linked devDependency, so the package really does land in the
// tree — it is a true positive that the old check found for the wrong reason.
//
// So walk the graph with the install semantics that were observed, not the
// ones npm documents. That catches the edges a substring only ever found by
// luck — a transitive *production* dependency whose name never appears in the
// manifest — and stops scoring a resolution record as an installed package.

/** How a reachable package got into the tree. */
export type EdgeScope = "production" | "development";

export interface DependencyEdge {
  /** The forbidden package that is reachable. */
  packageName: string;
  scope: EdgeScope;
  /** Root -> ... -> packageName, for the finding message. */
  path: string[];
  source: "package.json" | "bun.lock";
  /** The manifest section that opened the path, when it starts at the root. */
  section?: string;
}

/**
 * Sections that pull a package into an install.
 *
 * `overrides`/`resolutions` are here because pinning a version is an edge even
 * when nothing else names the package, and `trustedDependencies`/
 * `bundleDependencies` because they are arrays of names, not version maps.
 */
export const PRODUCTION_SECTIONS = ["dependencies", "optionalDependencies", "peerDependencies"] as const;
export const DEVELOPMENT_SECTIONS = ["devDependencies"] as const;
export const PIN_SECTIONS = ["overrides", "resolutions"] as const;
export const NAME_LIST_SECTIONS = ["bundleDependencies", "bundledDependencies", "trustedDependencies"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/**
 * Parse JSON that may carry trailing commas.
 *
 * `bun.lock` is JSONC: it is written with a trailing comma after the last
 * entry of most objects. Stripping them has to skip string contents, or a
 * `file:../open-cloud` specifier could be mangled.
 */
export function parseLooseJson(text: string): unknown | null {
  try {
    return JSON.parse(text);
  } catch {
    // fall through to the tolerant path
  }
  const chars = [...text];
  let inString = false;
  for (let index = 0; index < chars.length; index += 1) {
    const character = chars[index]!;
    if (inString) {
      if (character === "\\") index += 1;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      continue;
    }
    if (character !== ",") continue;
    let ahead = index + 1;
    while (ahead < chars.length && /\s/.test(chars[ahead]!)) ahead += 1;
    if (chars[ahead] === "}" || chars[ahead] === "]") chars[index] = " ";
  }
  try {
    return JSON.parse(chars.join(""));
  } catch {
    return null;
  }
}

function namesInSection(container: Record<string, unknown>, section: string): string[] {
  const value = container[section];
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string");
  if (isRecord(value)) return Object.keys(value);
  return [];
}

/** Direct edges declared by the scanned package's own manifest. */
export function manifestEdges(manifest: unknown, forbidden: readonly string[]): DependencyEdge[] {
  if (!isRecord(manifest)) return [];
  const edges: DependencyEdge[] = [];
  const scopes: Array<{ sections: readonly string[]; scope: EdgeScope }> = [
    { sections: [...PRODUCTION_SECTIONS, ...PIN_SECTIONS, ...NAME_LIST_SECTIONS], scope: "production" },
    { sections: DEVELOPMENT_SECTIONS, scope: "development" },
  ];
  for (const { sections, scope } of scopes) {
    for (const section of sections) {
      for (const name of namesInSection(manifest, section)) {
        if (!forbidden.includes(name)) continue;
        edges.push({ packageName: name, scope, path: [name], source: "package.json", section });
      }
    }
  }
  return edges;
}

interface LockNode {
  /** Package name as the lockfile records it in the resolution id. */
  name: string;
  /** The package this entry really installs, when the key is an alias — see `resolutionTarget`. */
  alias: string | null;
  production: string[];
  development: string[];
  /** Resolved from a local path rather than a registry — see `isLinkedResolution`. */
  linked: boolean;
}

/**
 * Is this resolution a local path link rather than a registry download?
 *
 * It decides whether the package's devDependencies get installed, and the
 * answer is NOT the one you would guess from npm semantics. Measured on bun
 * 1.3.14, both directions:
 *
 *   - a registry dependency's devDependencies are NOT installed. A root
 *     depending on `commander@13.1.0` gets `commander` and none of its six
 *     devDependencies.
 *   - a `file:` dependency's devDependencies ARE installed, hoisted to the
 *     root. A root depending on `file:../pkg-a` gets `pkg-a` AND `pkg-a`'s
 *     dev-only `commander`.
 *
 * That second case is why `hasna/logs` is not the false positive it looks
 * like: `@hasna/agent-registry` is a `file:` dependency, so its dev-only edge
 * to the retired runtime is a package that really does land in the tree.
 */
export function isLinkedResolution(id: string): boolean {
  const name = nameFromResolutionId(id);
  if (name === null) return false;
  return /^(?:file|link|workspace):/.test(id.slice(name.length + 1));
}

/**
 * The package name inside a bun lockfile resolution id.
 *
 * Ids look like `pg@8.22.0` or `@hasna/cloud@file:../open-cloud`; the scope
 * sigil means the separating `@` is not the first character.
 */
export function nameFromResolutionId(id: string): string | null {
  const separator = id.indexOf("@", id.startsWith("@") ? 1 : 0);
  if (separator <= 0) return null;
  return id.slice(0, separator);
}

/**
 * The package a resolution id really installs, when its key is an alias for
 * something else.
 *
 * `file:`, `link:` and `workspace:` name a DIRECTORY and `npm:` names a
 * registry package, so any of them can pull the retired runtime into the tree
 * under a name that is on no list: `bun install` records a dependency on
 * `../open-cloud` declared as `@hasna/legacy` as
 * `@hasna/legacy@file:../open-cloud`, and the key alone says nothing at all.
 *
 * Returns null for the ordinary case where the id resolves to its own name.
 */
export function resolutionTarget(id: string): string | null {
  const name = nameFromResolutionId(id);
  if (name === null) return null;
  const specifier = id.slice(name.length + 1);
  const aliased = /^npm:(.+)$/.exec(specifier);
  if (aliased) {
    const target = nameFromResolutionId(aliased[1]!) ?? aliased[1]!;
    return target === name ? null : target;
  }
  const linked = /^(?:file|link|workspace):(.+)$/.exec(specifier);
  if (!linked) return null;
  // The directory the specifier points at, which is the name the package is
  // published under far more often than not.
  const segments = linked[1]!.split("/").filter((segment) => segment !== "" && segment !== "." && segment !== "..");
  const target = segments[segments.length - 1];
  return target === undefined || target === name ? null : target;
}

function nodesByName(lock: Record<string, unknown>): Map<string, LockNode[]> {
  const byName = new Map<string, LockNode[]>();
  const packages = lock.packages;
  if (!isRecord(packages)) return byName;
  for (const [key, entry] of Object.entries(packages)) {
    if (!Array.isArray(entry)) continue;
    const id = typeof entry[0] === "string" ? entry[0] : null;
    // Fall back to the map key's last path element when there is no id.
    const name = (id ? nameFromResolutionId(id) : null) ?? key.split("/").slice(-1)[0] ?? key;
    const meta = entry.find((element): element is Record<string, unknown> => isRecord(element));
    const node: LockNode = {
      name,
      alias: id === null ? null : resolutionTarget(id),
      production: meta ? PRODUCTION_SECTIONS.flatMap((section) => namesInSection(meta, section)) : [],
      development: meta ? [...DEVELOPMENT_SECTIONS].flatMap((section) => namesInSection(meta, section)) : [],
      linked: id !== null && isLinkedResolution(id),
    };
    const existing = byName.get(name);
    if (existing) existing.push(node);
    else byName.set(name, [node]);
  }
  return byName;
}

/** A workspace entry the install starts from, with the label a trail should use for it. */
interface InstallRoot {
  /** Null for the install root itself, which needs no prefix in a trail. */
  label: string | null;
  record: Record<string, unknown>;
}

/**
 * Every workspace entry `bun install` seeds the tree from.
 *
 * ALL of them, not `workspaces[""]`. Reading only the root entry is what made
 * this check useless on a real monorepo, and the shape is not a guess: a bun
 * 1.3.14 `bun install` in a `workspaces` repo writes the root as
 * `{ "name": "mono-root" }` with NO dependency sections and hangs every
 * declared dependency off the member workspaces. Seeding from the root entry
 * alone produced zero seeds, so the walk never ran and returned an EMPTY edge
 * list — a clean verdict, not the null that would have fallen back to the text
 * scan — for a tree that installs the retired runtime.
 *
 * Every workspace in the table is installed by the same command, so every one
 * of them is a real seed rather than an over-approximation.
 */
function installRoots(lock: Record<string, unknown>): InstallRoot[] {
  const workspaces = lock.workspaces;
  if (!isRecord(workspaces)) return [];
  const roots: InstallRoot[] = [];
  for (const [key, record] of Object.entries(workspaces)) {
    if (!isRecord(record)) continue;
    roots.push({ label: key === "" ? null : typeof record.name === "string" ? record.name : key, record });
  }
  return roots;
}

/**
 * Which forbidden package this reachable name IS, if any.
 *
 * The lockfile key is normally the package name and an exact match on it is
 * the whole answer. It does not have to be: an aliased resolution installs the
 * retired runtime under a name of the declarer's choosing, so the resolution
 * target counts too. A SUBSTRING still does not — `@hasna/cloudflare` is not
 * `@hasna/cloud`, and confusing the two is what this module exists to stop.
 */
function forbiddenIdentity(name: string, nodes: readonly LockNode[], forbidden: readonly string[]): string | null {
  if (forbidden.includes(name)) return name;
  for (const node of nodes) {
    if (node.alias !== null && forbidden.includes(node.alias)) return node.alias;
  }
  return null;
}

/**
 * Every forbidden package reachable from the workspaces of `bun.lock`.
 *
 * Install semantics as bun actually implements them:
 *
 *   - every workspace's production AND development sections are installed;
 *   - a registry package's production edges are followed, its dev edges are
 *     not — nobody installs a dependency's devDependencies;
 *   - a LINKED package's dev edges ARE followed, because bun installs them.
 *     See `isLinkedResolution` for the measurement.
 *
 * Anything reached through a development hop is reported as development, so a
 * dev-only edge cannot be laundered into a production verdict by a later
 * production hop.
 *
 * Reachability is keyed by NAME rather than by the lockfile's nesting path.
 * Where one name has several entries their edges are unioned, which can only
 * over-approximate — the safe direction for a gate.
 *
 * Returns null when the lockfile cannot be understood, so the caller can fall
 * back to the text scan rather than silently reporting a clean tree.
 */
export function lockfileEdges(lockText: string, forbidden: readonly string[]): DependencyEdge[] | null {
  const lock = parseLooseJson(lockText);
  if (!isRecord(lock)) return null;
  const roots = installRoots(lock);
  if (roots.length === 0) return null;
  const nodes = nodesByName(lock);

  interface Visit {
    name: string;
    trail: string[];
    section: string;
    scope: EdgeScope;
  }

  const seeds: Visit[] = [];
  for (const { label, record } of roots) {
    // A member workspace is named at the head of the trail, so a finding says
    // which package in the repo pulled the runtime in.
    const head = label === null ? [] : [label];
    for (const section of [...PRODUCTION_SECTIONS, ...PIN_SECTIONS, ...NAME_LIST_SECTIONS]) {
      for (const name of namesInSection(record, section)) seeds.push({ name, trail: [...head, name], section, scope: "production" });
    }
    for (const section of DEVELOPMENT_SECTIONS) {
      for (const name of namesInSection(record, section)) seeds.push({ name, trail: [...head, name], section, scope: "development" });
    }
  }

  // Production first, so a package reachable both ways is reported at the
  // higher severity and the weaker path never overwrites it.
  const queue = [...seeds].sort((left, right) => (left.scope === right.scope ? 0 : left.scope === "production" ? -1 : 1));
  const seen = new Set<string>(queue.map((visit) => `${visit.scope}:${visit.name}`));
  const best = new Map<string, DependencyEdge>();

  while (queue.length > 0) {
    const current = queue.shift()!;
    const reachable = nodes.get(current.name) ?? [];
    const identity = forbiddenIdentity(current.name, reachable, forbidden);
    if (identity !== null) {
      const existing = best.get(identity);
      if (!existing || (existing.scope === "development" && current.scope === "production")) {
        best.set(identity, {
          packageName: identity,
          scope: current.scope,
          path: current.trail,
          source: "bun.lock",
          section: current.section
        });
      }
    }
    for (const node of reachable) {
      const next: Array<{ name: string; scope: EdgeScope }> = node.production.map((name) => ({ name, scope: current.scope }));
      // A linked package's devDependencies land in the tree; a registry
      // package's do not.
      if (node.linked) {
        for (const name of node.development) next.push({ name, scope: "development" });
      }
      for (const candidate of next) {
        const key = `${candidate.scope}:${candidate.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        queue.push({ name: candidate.name, trail: [...current.trail, candidate.name], section: current.section, scope: candidate.scope });
      }
    }
  }
  return [...best.values()];
}
