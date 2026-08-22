// IAM Blast Radius - IAM JSON parser (IAM-002).
//
// Second stage of the pipeline (see docs/architecture.md data-flow):
//   text -> validate() -> raw (null-proto) -> parse() -> model()
//
// parse() is tolerant of the shapes AWS accepts at the *container* level:
//   - Statement may be a single object or an array of objects.
//   - Version / Id are optional strings.
// It extracts the ordered list of raw statement objects and surfaces the
// optional top-level fields. It does NOT normalize action/resource types or
// validate per-statement schema; that is model.js's job. It never throws.
//
// Public API:
//   parse(raw) -> { ok, errors[], version, id, statements[] }
// where `raw` is the sanitized null-prototype object produced by validate().
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. Deterministic.

function err(code, message, path) {
  return { code, message, path: path === undefined ? null : path };
}

/**
 * Extract the top-level policy fields and the ordered list of raw statement
 * objects from a validated policy document.
 *
 * @param {object} raw sanitized null-prototype policy object (from validate())
 * @returns {{ok:boolean, errors:Array<{code:string,message:string,path:?string}>,
 *            version:(string|null), id:(string|null), statements:Array<object>}}
 */
export function parse(raw) {
  const errors = [];

  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    errors.push(err('NOT_AN_OBJECT', 'Top-level policy must be a JSON object.'));
    return { ok: false, errors, version: null, id: null, statements: [] };
  }

  // Bracket access is safe: raw is null-prototype so there is no inherited
  // "Version"/"Id"/"Statement" to confuse us.
  const version = typeof raw['Version'] === 'string' ? raw['Version'] : null;
  const id = typeof raw['Id'] === 'string' ? raw['Id'] : null;

  const stmtRaw = raw['Statement'];
  let statements;
  if (Array.isArray(stmtRaw)) {
    statements = stmtRaw.slice();
  } else if (stmtRaw !== null && typeof stmtRaw === 'object') {
    // Single-statement form: AWS allows Statement to be one object.
    statements = [stmtRaw];
  } else {
    errors.push(
      err(
        'NO_STATEMENT',
        'Policy is missing a "Statement" object or array.',
        'Statement',
      ),
    );
    return { ok: false, errors, version, id, statements: [] };
  }

  return { ok: true, errors, version, id, statements };
}

export default parse;
