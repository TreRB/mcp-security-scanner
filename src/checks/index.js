// Registry of all checks.

import * as a1 from './a1_schema.js';
import * as a2 from './a2_shell_sql.js';
import * as a3 from './a3_fs_scope.js';
import * as a4 from './a4_fetch_ssrf.js';
import * as a5 from './a5_cred_leak.js';
import * as s1 from './s1_pinning.js';
import * as s2 from './s2_known_bad.js';
import * as s3 from './s3_shared_state.js';

export const CHECKS = {
  A1: a1,
  A2: a2,
  A3: a3,
  A4: a4,
  A5: a5,
  S1: s1,
  S2: s2,
  S3: s3,
};

export const CHECK_IDS = Object.keys(CHECKS);

export const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

export function sevRank(sev) {
  return SEVERITY_ORDER.indexOf(sev);
}
