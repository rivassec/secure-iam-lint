// action-output.mjs - GitHub Action step output + job-summary formatting (control-char-inert key=value output block, human summary). Extracted from index.mjs (behavior-preserving).
import { randomUUID } from 'node:crypto';
import { KEY_CONTROL_CHAR_RE, VALUE_CONTROL_CHAR_RE } from './action-aggregate.mjs';
import { EXIT } from '../cli/scan.mjs';

export function formatOutputs(outputs) {
  let body = '';
  for (const [k, v] of Object.entries(outputs || {})) {
    const key = String(k);
    const val = String(v);
    if (KEY_CONTROL_CHAR_RE.test(key)) {
      throw new Error(`unsafe control character in output key ${JSON.stringify(key)}`);
    }
    if (VALUE_CONTROL_CHAR_RE.test(val)) {
      throw new Error(`unsafe control character in output value for ${key}`);
    }
    if (val.includes('\n')) {
      const delim = `ghadelim_${randomUUID()}_EOF`;
      if (val.split('\n').includes(delim)) {
        throw new Error(`output ${key} collides with its heredoc delimiter`);
      }
      body += `${key}<<${delim}\n${val}\n${delim}\n`;
    } else {
      body += `${key}=${val}\n`;
    }
  }
  return body;
}

// A short, low-leakage markdown step summary. Carries ONLY verdict metadata - no
// policy content, ARNs, or account ids (threat-model: do not leak policy text into
// logs or the Security tab of a private repo).
export function formatSummary(outputs, exitCode) {
  const passed = exitCode === EXIT.CLEAN;
  const verdict = passed ? 'PASS (no blocking findings)' : `FAIL (exit ${exitCode})`;
  const o = outputs || {};
  return [
    '## IAM Blast Radius',
    '',
    `- Result: ${verdict}`,
    `- Analysis status: ${o['analysis-status']}`,
    `- Findings: ${o['findings-count']} (blocking: ${o['blocking-findings-count']})`,
    `- SARIF: ${o['sarif-path']}`,
    '',
    'Reports POTENTIAL blast radius from the supplied policy context only; not effective permissions.',
    '',
  ].join('\n');
}

// --- Core (pure over an injected IO surface; NEVER touches the process) --------

/**
 * Run the action's work and return a structured result WITHOUT writing anything or
 * touching the process. Deterministic given its inputs. Never throws: any
 * unexpected error fails CLOSED to exit 4 (INTERNAL), never 0.
 *
 * @param {object} args
 * @param {object} args.env       environment (INPUT_* map)
 * @param {object} args.io        { listFiles(): string[], readFile(rel): string }
 * @param {(input:object)=>object} [args.scanFn]  injectable scan (default: real scan)
 * @param {object} [args.manifest] injectable version manifest
 * @returns {{exitCode:number, reason:string, analysisStatus:string,
 *   findingsCount:number, blockingCount:number, sarifPath:string,
 *   outputs:object, sarifLog:object, units:Array}}
 */
