import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
// Reproduce actionGrants semantics loosely: we just enumerate short globs of the form
// 's3:' + A + wc + B  that match 's3:GetObject', and let analyze() decide. But to know
// how many DISTINCT short patterns match, generate candidates and test via a broad-Allow
// single-statement analyze -> count DATA-EXFIL actions. Simpler: generate 'A*B' + 'A?B'
// forms over target 'GetObject' and dedupe.
const T = 'GetObject';
const set = new Set();
// single '*' inserted: A*B with A prefix, B suffix, |A|+|B|<=9
for (let a=0;a<=T.length;a++) for (let b=0;b+a<=T.length;b++){
  set.add('s3:'+T.slice(0,a)+'*'+T.slice(T.length-b));
}
// single '?' replacing one char (exact-length match)
for (let i=0;i<T.length;i++){ set.add('s3:'+T.slice(0,i)+'?'+T.slice(i+1)); }
// '*' plus a trailing/leading '?': A*B? style up to two wildcards for more distinct
for (let a=0;a<=T.length;a++) for (let b=0;b+a<=T.length;b++){
  const mid=T.slice(a, T.length-b);
  // replace one interior char of mid with '?' won't necessarily match; skip for safety
}
console.log('distinct short single-wildcard patterns:', set.size);
