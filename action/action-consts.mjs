// action-consts.mjs - shared SARIF aggregate output ceilings + truncation code for the
// GitHub Action. Read by readInputs() (index.mjs) and the aggregate builder
// (action-aggregate.mjs). Extracted from index.mjs (behavior-preserving; pure data).
//
// The aggregate SARIF output caps, chosen to sit under GitHub code-scanning's ingest limits:
//   - RESULTS below 5000 (the silent-drop cap), and
//   - an uncompressed BYTE proxy below the 10 MB gzip cap. 9 MiB uncompressed is safe even for
//     incompressible content (9 MiB ~= 9.44 MB < 10 MB) and SARIF gzips far smaller in practice;
//     it also stays above the per-run 8 MiB cap so a single maximal run still fits.
// Both are CONFIGURABLE (max-sarif-results / max-sarif-bytes inputs) so a legitimately large
// aggregate can raise them rather than be false-truncated.
export const DEFAULT_MAX_SARIF_RESULTS = 4500;
export const DEFAULT_MAX_SARIF_BYTES = 9 * 1024 * 1024; // 9 MiB (9437184 bytes) uncompressed proxy
// The aggregate truncation analyzer-state code. Deliberately the SAME code the per-run budget
// emits (cli/sarif.mjs truncationState) so a consumer recognizes ONE "output was truncated"
// signal on either surface.
export const SARIF_OUTPUT_TRUNCATED_REASON = 'SARIF_OUTPUT_TRUNCATED';
