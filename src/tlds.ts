// Top-level domains the asset-inventory guard will believe.
//
// WHY A LIST AT ALL. Without one, `label.label` matches half of every codebase:
// the first draft of this guard reported `agents.list`, `config.replace` and
// `pool.connectionTimeoutMillis` as domains and failed on this very repo. A
// mandatory gate that fires on compliant repos gets switched off, and then it
// protects nothing — the same end state as a gate that cannot fail. So the
// last label must be a real TLD.
//
// WHY THIS LIST AND NOT IANA'S FULL ~1450. This is ISO 3166-1 alpha-2 (every
// ccTLD, a fixed and stable set) plus the established gTLDs. It is short enough
// to read and audit, and it covers what a vendor could plausibly own. The cost
// of omitting an exotic new gTLD is an UNDER-count in a file that, if it really
// is an inventory, will almost certainly trip on its other entries too.
//
// A bare TLD has no dot, so this list does not trip the guard that uses it.

/** ISO 3166-1 alpha-2 country codes — every ccTLD. */
const COUNTRY_CODE_TLDS = [
  "ac","ad","ae","af","ag","ai","al","am","ao","aq","ar","as","at","au","aw","ax","az",
  "ba","bb","bd","be","bf","bg","bh","bi","bj","bm","bn","bo","br","bs","bt","bw","by","bz",
  "ca","cd","cf","cg","ch","ci","ck","cl","cm","cn","co","cr","cu","cv","cw","cx","cy","cz",
  "de","dj","dk","dm","do","dz",
  "ec","ee","eg","er","es","et","eu",
  "fi","fj","fk","fm","fo","fr",
  "ga","gd","ge","gf","gg","gh","gi","gl","gm","gn","gp","gq","gr","gs","gt","gu","gw","gy",
  "hk","hm","hn","hr","ht","hu",
  "id","ie","il","im","in","io","iq","ir","is","it",
  "je","jm","jo","jp",
  "ke","kg","kh","ki","km","kn","kp","kr","kw","ky","kz",
  "la","lb","lc","li","lk","lr","ls","lt","lu","lv","ly",
  "ma","mc","md","me","mg","mh","mk","ml","mm","mn","mo","mp","mq","mr","ms","mt","mu","mv","mw","mx","my","mz",
  "na","nc","ne","nf","ng","ni","nl","no","np","nr","nu","nz",
  "om",
  "pa","pe","pf","pg","ph","pk","pl","pm","pn","pr","ps","pt","pw","py",
  "qa",
  "re","ro","rs","ru","rw",
  "sa","sb","sc","sd","se","sg","sh","si","sk","sl","sm","sn","so","sr","ss","st","su","sv","sx","sy","sz",
  "tc","td","tf","tg","th","tj","tk","tl","tm","tn","to","tr","tt","tv","tw","tz",
  "ua","ug","uk","us","uy","uz",
  "va","vc","ve","vg","vi","vn","vu",
  "wf","ws",
  "ye","yt",
  "za","zm","zw"
] as const;

/** Established generic and sponsored TLDs, plus the widely-used new gTLDs. */
const GENERIC_TLDS = [
  "com","net","org","edu","gov","mil","int","info","biz","name","pro",
  "aero","coop","museum","jobs","mobi","tel","travel","asia","cat","post","xxx",
  "agency","blog","cloud","company","design","digital","direct","email","events",
  "finance","group","host","media","network","news","online","site","software",
  "solutions","space","store","studio","systems","team","tech","today","tools",
  "ventures","website","works","world","xyz","zone"
] as const;

/**
 * TLDs that are ALSO ubiquitous programming vocabulary, deliberately excluded.
 *
 * `.app`, `.dev`, `.io`-adjacent short words, `.list`, `.map`, `.page`, `.link`,
 * `.run`, `.new`, `.one` and the common file extensions all exist as real TLDs,
 * and all appear constantly as method names, object keys, and filenames inside a
 * bundle. Counting them buries a real finding in noise.
 *
 * THE RESIDUAL, STATED: an inventory built exclusively from domains under these
 * TLDs would not be detected by count. Clause B is not a count — it is a
 * prohibition, and it applies whether or not this guard can see the violation.
 */
const PROGRAMMING_COLLISION_TLDS = new Set([
  "app","dev","list","map","page","link","run","new","one","id","so","sh","js","md","py","rs","go","db","bar","best","codes","fyi","how","ing","ly","md","sh","wiki","zip","mov"
]);

/** The TLDs the asset-inventory guard counts. */
export const RECOGNIZED_TLDS: ReadonlySet<string> = new Set(
  [...COUNTRY_CODE_TLDS, ...GENERIC_TLDS].filter((tld) => !PROGRAMMING_COLLISION_TLDS.has(tld))
);

/** Is `label` a TLD this guard is willing to count? */
export function isRecognizedTld(label: string): boolean {
  return RECOGNIZED_TLDS.has(label);
}
