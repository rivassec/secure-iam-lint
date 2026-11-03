// trusted-accounts.mjs - parse the explicit trusted-account list (--trusted-account-id /
// trusted-account-ids). Pure: no I/O. An invalid entry is a usage error; the value is never echoed.

/**
 * @param {string|string[]|undefined|null} raw  comma/newline separated string(s)
 * @returns {{ ids: string[]|null } | { error: string }}  sorted unique ids, or null when absent
 */
export function parseTrustedAccountIds(raw) {
  if (raw == null) return { ids: null };
  const parts = (Array.isArray(raw) ? raw : [raw])
    .flatMap((v) => String(v).split(/[,\r\n]+/))
    .map((v) => v.trim())
    .filter((v) => v !== '');
  if (parts.length === 0) return { ids: null };
  if (parts.some((v) => !/^\d{12}$/.test(v))) {
    return { error: 'Each trusted account id must be a 12-digit AWS account id.' };
  }
  return { ids: [...new Set(parts)].sort() };
}
