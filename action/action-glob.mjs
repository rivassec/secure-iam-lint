// action-glob.mjs - linear, ReDoS-safe glob path matcher for the GitHub Action file selector (splitPaths, globMatchPath, globToRegExp, complexity caps). Extracted from index.mjs (behavior-preserving; self-contained).

export function splitPaths(raw) {
  if (typeof raw !== 'string') return [];
  return raw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// A pattern is a glob (not a literal path) iff it contains a glob magic character.
export function hasMagic(pattern) {
  return /[*?[]/.test(String(pattern));
}

// Strip a single leading "./" so "./a/b" and "a/b" resolve identically.
export function normalizePattern(pattern) {
  let p = String(pattern);
  if (p.startsWith('./')) p = p.slice(2);
  return p;
}

// Escape a single literal character for embedding in a RegExp.
export function escapeRegexChar(c) {
  return /[.+^${}()|\\]/.test(c) ? `\\${c}` : c;
}

// --- ReDoS-safe LINEAR path-glob matcher (S3-dos-budget-all) ------------------
// The action `paths` input is ATTACKER-CONTROLLED and is resolved BEFORE any scan
// wall-clock budget is armed, so a glob compiled to a backtracking RegExp is a
// pre-budget ReDoS: a crafted pattern such as `*a*a*a*...*b` (many '*' separated by
// a repeated literal) matched against a moderately long file path drives the anchored
// RegExp into exponential backtracking and hangs the whole Action - a denial of
// service that no downstream budget can stop because it fires during glob resolution.
// This matcher decides the SAME path-glob language with a DYNAMIC-PROGRAMMING
// automaton that is O(patternTokens x pathLength) with NO backtracking, so its cost
// is a bounded polynomial of the (capped) pattern and path lengths - the ReDoS class
// is removed, not merely the one crafted spelling. globToRegExp() is retained for its
// exported contract but is length/wildcard-capped below and is no longer on the
// resolveFiles hot path.

// Hard caps applied BEFORE any glob work. A pattern beyond these bounds is not a
// legitimate path filter; it fails CLOSED to a usage error rather than being matched.
export const MAX_GLOB_PATTERN_LENGTH = 4096;
export const MAX_GLOB_WILDCARDS = 256;

// Count the glob "magic" characters ('*', '?', '[') in a pattern - the axis a ReDoS
// pattern maximizes. Used purely to reject an over-complex pattern up front.
export function countGlobWildcards(pattern) {
  let n = 0;
  const s = String(pattern);
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '*' || c === '?' || c === '[') n += 1;
  }
  return n;
}

// A pattern is REJECTABLE (too long, or too many wildcards) and must fail closed.
export function globPatternTooComplex(pattern) {
  const s = String(pattern);
  return s.length > MAX_GLOB_PATTERN_LENGTH || countGlobWildcards(s) > MAX_GLOB_WILDCARDS;
}

// Parse a bracket char-class starting at `chars[start]` === '['. Returns
// { pred, next } where pred(ch) tests one character and `next` is the index of the
// char AFTER the closing ']'. If the class is unterminated, returns null so the caller
// treats '[' as a literal (mirrors globToRegExp's unterminated-class fallback).
export function parseCharClass(chars, start) {
  let j = start + 1;
  let negate = false;
  if (chars[j] === '!') { negate = true; j += 1; }
  const singles = new Set();
  const ranges = []; // [lo, hi] inclusive code points
  // A ']' immediately after '[' (or '[!') is a literal member, not the terminator.
  if (chars[j] === ']') { singles.add(']'); j += 1; }
  let closed = false;
  while (j < chars.length) {
    const c = chars[j];
    if (c === ']') { closed = true; j += 1; break; }
    // Range a-z: a member, then '-', then a member that is not the closing ']'.
    if (chars[j + 1] === '-' && chars[j + 2] !== undefined && chars[j + 2] !== ']') {
      ranges.push([c.codePointAt(0), chars[j + 2].codePointAt(0)]);
      j += 3;
      continue;
    }
    singles.add(c);
    j += 1;
  }
  if (!closed) return null; // unterminated -> caller treats '[' as a literal
  const pred = (ch) => {
    let inSet = singles.has(ch);
    if (!inSet) {
      const cp = ch.codePointAt(0);
      for (const [lo, hi] of ranges) {
        if (cp >= lo && cp <= hi) { inSet = true; break; }
      }
    }
    return negate ? !inSet : inSet;
  };
  return { pred, next: j };
}

// Token kinds for the linear matcher.
export const TOK_STAR2SLASH = 0; // '**/'  -> zero or more full path segments  ((?:.*/)?)
export const TOK_STAR2 = 1;      // '**'   -> any run incl. '/'                (.*)
export const TOK_STAR1 = 2;      // '*'    -> any run excl. '/'                ([^/]*)
export const TOK_ONE = 3;        // '?' / class / literal -> exactly one char via pred

// Compile a glob pattern into a token list with the SAME semantics globToRegExp
// encodes. Deterministic; no RegExp is ever constructed. Returns an array of tokens.
export function compileGlobTokens(pattern) {
  const chars = [...String(pattern)];
  const tokens = [];
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c === '*') {
      if (chars[i + 1] === '*') {
        const after = chars[i + 2];
        if (after === '/') {
          tokens.push({ k: TOK_STAR2SLASH });
          i += 2; // consume the second '*' and the '/'
        } else {
          tokens.push({ k: TOK_STAR2 }); // trailing '**' or '**' not path-bounded
          i += 1; // consume the second '*'
        }
      } else {
        tokens.push({ k: TOK_STAR1 });
      }
    } else if (c === '?') {
      tokens.push({ k: TOK_ONE, pred: (ch) => ch !== '/' });
    } else if (c === '[') {
      const parsed = parseCharClass(chars, i);
      if (parsed === null) {
        tokens.push({ k: TOK_ONE, pred: (ch) => ch === '[' }); // literal '['
      } else {
        tokens.push({ k: TOK_ONE, pred: parsed.pred });
        i = parsed.next - 1; // -1 because the for-loop will i++
      }
    } else {
      tokens.push({ k: TOK_ONE, pred: (ch) => ch === c });
    }
  }
  return tokens;
}

// Decide whether `pattern` matches the whole path `text`, LINEARLY (dynamic
// programming, no backtracking). O(tokens x textLength). ReDoS-immune.
export function globMatchPath(pattern, text) {
  const tokens = compileGlobTokens(pattern);
  const t = String(text);
  const T = t.length;
  // dp[j] = can tokens[i..end] match text[j..end]. Seed for i === tokens.length:
  // only a fully-consumed text matches the empty token suffix.
  let dp = new Array(T + 1).fill(false);
  dp[T] = true;
  for (let i = tokens.length - 1; i >= 0; i--) {
    const tok = tokens[i];
    const ndp = new Array(T + 1).fill(false);
    if (tok.k === TOK_ONE) {
      for (let j = 0; j < T; j++) {
        if (dp[j + 1] && tok.pred(t[j])) ndp[j] = true;
      }
    } else if (tok.k === TOK_STAR1) {
      // '[^/]*': match zero (dp[j]) or one more non-'/' char and stay (ndp[j+1]).
      for (let j = T; j >= 0; j--) {
        let v = dp[j];
        if (!v && j < T && t[j] !== '/' && ndp[j + 1]) v = true;
        ndp[j] = v;
      }
    } else if (tok.k === TOK_STAR2) {
      // '.*': match zero (dp[j]) or one more char of any kind and stay (ndp[j+1]).
      for (let j = T; j >= 0; j--) {
        let v = dp[j];
        if (!v && j < T && ndp[j + 1]) v = true;
        ndp[j] = v;
      }
    } else { // TOK_STAR2SLASH: '(?:.*/)?'
      for (let j = T; j >= 0; j--) {
        let v = dp[j]; // zero path segments
        if (!v && j < T && ndp[j + 1]) v = true; // stay inside the '.*' run
        if (!v && j < T && t[j] === '/' && dp[j + 1]) v = true; // closing '/', advance token
        ndp[j] = v;
      }
    }
    dp = ndp;
  }
  return dp[0];
}

// S1-DIRSYMLINK: decide whether `pattern` could match SOME path strictly UNDER directory
// `dir` - i.e. some string of the form `dir + '/' + <nonempty suffix>`. A DIRECTORY symlink
// is never followed, so its whole hidden subtree is invisible to enumeration; if that subtree
// could contain a policy file the scan pattern selects, the run must FAIL CLOSED even though
// the symlink's OWN path does not itself match the file glob (e.g. pattern `**/*.json` or
// `configs/*.json` vs a directory symlink named `configs`). Without this, a directory symlink
// smuggles an entire subtree of policies past the aggregate and the run reports exit 0 clean.
//
// Implemented as a LINEAR forward NFA simulation over the fixed prefix `dir + '/'` (no
// backtracking, no RegExp - same ReDoS-immunity rationale as globMatchPath), using the SAME
// token semantics compileGlobTokens encodes. After consuming `dir/`, if ANY pattern token
// remains reachable the pattern can still match a nonempty filename/suffix under the directory,
// so a hidden file could match -> return true. If the prefix cannot be consumed at all the
// pattern cannot descend into this directory -> false (an UNRELATED directory symlink does not
// false-fail). Deterministic.
export function globCanMatchUnderDir(pattern, dir) {
  const d = String(dir);
  if (d.length === 0) return false;
  const tokens = compileGlobTokens(pattern);
  const N = tokens.length;
  // Epsilon-closure: a star token can be SKIPPED (match zero), advancing to i+1.
  const closure = (set) => {
    const stack = [...set];
    while (stack.length > 0) {
      const i = stack.pop();
      if (i >= N) continue;
      const k = tokens[i].k;
      if ((k === TOK_STAR1 || k === TOK_STAR2 || k === TOK_STAR2SLASH) && !set.has(i + 1)) {
        set.add(i + 1);
        stack.push(i + 1);
      }
    }
    return set;
  };
  // Advance the NFA state set by consuming exactly one character `c`.
  const step = (set, c) => {
    const next = new Set();
    for (const i of set) {
      if (i >= N) continue;
      const tok = tokens[i];
      if (tok.k === TOK_ONE) {
        if (tok.pred(c)) next.add(i + 1);
      } else if (tok.k === TOK_STAR1) {
        if (c !== '/') next.add(i); // '[^/]*': consume a non-'/' char, stay
      } else if (tok.k === TOK_STAR2) {
        next.add(i); // '.*': consume any char, stay
      } else { // TOK_STAR2SLASH: '(?:.*/)?' - any run of chars closing on a '/'
        next.add(i); // still inside the '.*' run (any char, incl '/')
        if (c === '/') next.add(i + 1); // this '/' closes the run -> advance the token
      }
    }
    return next;
  };
  const prefix = `${d}/`;
  let states = closure(new Set([0]));
  for (let p = 0; p < prefix.length; p++) {
    states = closure(step(states, prefix[p]));
    if (states.size === 0) return false; // pattern cannot descend into this directory
  }
  // A remaining token (state i < N) means the pattern can still match a nonempty suffix
  // (a hidden filename) under `dir/` -> the directory symlink could smuggle a matching file.
  for (const i of states) {
    if (i < N) return true;
  }
  return false;
}

// Translate a POSIX-style glob into an ANCHORED RegExp. Path-aware:
//   **/ or trailing ** matches any number of path segments (incl. zero)
//   *   matches any run of non-'/' characters
//   ?   matches a single non-'/' character
//   [..] is a character class (a leading ! is negation)
// Deterministic; no external glob dependency.
export function globToRegExp(pattern) {
  // S3-dos-budget-all: retained for its exported contract, but HARD-CAPPED so it can
  // never be used to build a catastrophically-backtracking RegExp from an over-long or
  // wildcard-dense attacker pattern. Beyond the caps it throws a tagged error; callers
  // that resolve untrusted `paths` use the linear globMatchPath() instead and never
  // reach this. (An anchored RegExp of many adjacent '.*'/'[^/]*' quantifiers is the
  // ReDoS vector; the cap bounds the quantifier count so the fallback stays safe too.)
  if (globPatternTooComplex(pattern)) {
    const err = new Error('glob pattern exceeds complexity limits');
    err.code = 'INVALID_GLOB';
    throw err;
  }
  const chars = [...String(pattern)];
  let re = '';
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c === '*') {
      if (chars[i + 1] === '*') {
        const after = chars[i + 2];
        if (after === '/') {
          re += '(?:.*/)?'; // **/  -> any depth, including zero segments
          i += 2;
        } else if (after === undefined) {
          re += '.*'; // trailing ** -> anything to end
          i += 1;
        } else {
          re += '.*'; // ** not path-bounded -> anything
          i += 1;
        }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if (c === '[') {
      // Character class: copy through the matching ']'.
      let j = i + 1;
      let cls = '[';
      if (chars[j] === '!') { cls += '^'; j += 1; }
      if (chars[j] === ']') { cls += '\\]'; j += 1; }
      while (j < chars.length && chars[j] !== ']') {
        cls += chars[j] === '\\' ? '\\\\' : chars[j];
        j += 1;
      }
      if (j >= chars.length) {
        // Unterminated class -> treat the '[' as a literal.
        re += '\\[';
      } else {
        re += `${cls}]`;
        i = j;
      }
    } else {
      re += escapeRegexChar(c);
    }
  }
  return new RegExp(`^${re}$`);
}
