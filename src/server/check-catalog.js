// Check Catalog — reference knowledge for the universal scan framework.
//
// The agent is recon-first and self-directed: it maps the target, decides its
// own test plan, announces it as [PLAN] lines and accounts for each area with
// [CHECK] lines. This module provides:
//
//   resolveChecks({ type, profile, options })
//     → the reference area set (launcher preview / typical coverage)
//
//   buildMissionPrompt(profile)
//     → the mission briefing: recon first, self-directed plan, the
//       [PLAN]/[CHECK] protocol, depth calibration per profile
//
// Every scan type (assessment / pentest) and profile (quick / full / custom)
// flows through the same mission protocol — only depth calibration differs.

// Check statuses (result protocol)
export const CHECK_STATUS = {
  PASS: 'pass',           // check executed, no issue found
  ISSUE: 'issue',         // check executed, issue confirmed
  SKIP: 'skip',           // check intentionally skipped (declared reason)
  NOT_COMPLETED: 'not-completed', // scan ended before the check ran
};

// Custom-option groups (user-facing in the launcher)
export const CHECK_GROUPS = {
  headers: 'Security settings & headers',
  cookies: 'Cookie & session safety',
  forms: 'Forms & input handling',
  secrets: 'Exposed keys and secrets',
  js: 'Website scripts & code',
  network: 'Open ports & services',
  deep: 'Deep application testing',
};

// Universal check catalog.
// category maps to the user-facing scan phase the check belongs to.
// groups: null → always included (foundation checks); otherwise included when
// the group is enabled (full profile enables all, quick enables its subset).
export const CHECK_CATALOG = [
  // ---- Preparation ----
  {
    id: 'chk-connectivity',
    title: 'Website reachability & response health',
    category: 'preparing',
    groups: null,
    guidance: 'Load the target, confirm it responds normally, and note the overall health of responses.',
  },
  {
    id: 'chk-sitemap',
    title: 'Sitemap & robots.txt discovery',
    category: 'preparing',
    groups: null,
    guidance: 'Fetch /sitemap.xml and /robots.txt; note declared areas, disallowed paths and anything sensitive they reveal.',
  },

  // ---- Exploration ----
  {
    id: 'chk-surface',
    title: 'Pages, links & attack-surface inventory',
    category: 'exploring',
    groups: null,
    guidance: 'Map the site structure: pages, internal links, visible entry points (forms, logins, search, uploads, APIs).',
  },
  {
    id: 'chk-tech',
    title: 'Technology fingerprinting',
    category: 'exploring',
    groups: null,
    guidance: 'Identify the technology stack (server, framework, CMS, notable scripts) from responses and page content.',
  },

  // ---- Configuration ----
  {
    id: 'chk-headers',
    title: 'HTTP security headers',
    category: 'config',
    groups: ['headers'],
    guidance: 'Check CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and report missing or weak values.',
  },
  {
    id: 'chk-tls',
    title: 'HTTPS & transport security posture',
    category: 'config',
    groups: ['headers'],
    guidance: 'Verify HTTPS enforcement, http→https redirect behavior and HSTS presence; flag mixed-content risks.',
  },
  {
    id: 'chk-cookies',
    title: 'Cookie & session flag safety',
    category: 'config',
    groups: ['cookies'],
    guidance: 'Inspect cookies for Secure, HttpOnly and SameSite flags, session token handling and any sensitive data in cookie values.',
  },
  {
    id: 'chk-info-leak',
    title: 'Information disclosure',
    category: 'config',
    groups: ['headers'],
    guidance: 'Look for server/version banners, verbose error pages, directory listings, source maps, backup files and comments leaking internals.',
  },

  // ---- Deep inspection ----
  {
    id: 'chk-forms',
    title: 'Form input handling & injection vectors',
    category: 'inspecting',
    groups: ['forms'],
    guidance: 'Analyze every form: fields, validation, error behavior. Probe inputs with safe, non-destructive payloads to gauge reflection and handling.',
  },
  {
    id: 'chk-secrets',
    title: 'Exposed keys, tokens & secrets',
    category: 'inspecting',
    groups: ['secrets'],
    guidance: 'Scan pages, scripts and common paths for API keys, tokens, credentials and internal endpoints accidentally exposed.',
  },
  {
    id: 'chk-js',
    title: 'Client-side script analysis',
    category: 'inspecting',
    groups: ['js'],
    guidance: 'Review loaded scripts for dangerous patterns (eval, document.write, unsafe DOM sinks), outdated libraries and third-party script risk.',
  },
  {
    id: 'chk-auth',
    title: 'Authentication & session management',
    category: 'inspecting',
    groups: ['deep'],
    guidance: 'Evaluate login flows, password handling hints, session lifecycle and account state transitions for weaknesses.',
  },
  {
    id: 'chk-access',
    title: 'Access control & authorization boundaries',
    category: 'inspecting',
    groups: ['deep'],
    guidance: 'Test whether protected pages, APIs or actions are reachable without authentication or with lower privileges.',
  },
  {
    id: 'chk-injection',
    title: 'Injection resistance (SQLi / XSS / command)',
    category: 'inspecting',
    groups: ['deep'],
    guidance: 'Run controlled, non-destructive injection probes against inputs and URL parameters; confirm behavior with evidence before claiming an issue.',
  },
  {
    id: 'chk-ports',
    title: 'Open ports & exposed services',
    category: 'inspecting',
    groups: ['network'],
    guidance: 'Discover listening ports and services on the target host; flag unexpected or risky exposures.',
  },
  {
    id: 'chk-server',
    title: 'Web server hardening',
    category: 'inspecting',
    groups: ['network'],
    guidance: 'Run industry-standard web-server checks (e.g. nikto-class) for known server-level misconfigurations.',
  },
];

// Profile → group policy. Foundation checks (groups: null) are always on.
const PROFILE_GROUPS = {
  quick: ['headers', 'cookies', 'forms', 'secrets'],
  full: Object.keys(CHECK_GROUPS),
};

const CATEGORY_ORDER = ['preparing', 'exploring', 'config', 'inspecting'];

/**
 * Resolve the deterministic check plan for a scan.
 * @param {{type: 'assessment'|'pentest', profile: 'quick'|'full'|'custom', options?: object}} params
 * @returns {{checks: Array, totalChecks: number, byCategory: object}}
 */
export function resolveChecks({ type, profile, options = {} } = {}) {
  let enabledGroups;
  if (profile === 'quick') enabledGroups = PROFILE_GROUPS.quick;
  else if (profile === 'full') enabledGroups = PROFILE_GROUPS.full;
  else if (profile === 'custom') {
    enabledGroups = Object.keys(CHECK_GROUPS).filter((g) => Boolean(options[g]));
  } else {
    throw new Error(`Unknown scan profile: ${profile}`);
  }
  const enabled = new Set(enabledGroups);

  const checks = CHECK_CATALOG
    .filter((c) => c.groups === null || c.groups.some((g) => enabled.has(g)))
    .sort((a, b) =>
      CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category));

  const byCategory = {};
  for (const c of checks) {
    byCategory[c.category] = (byCategory[c.category] || 0) + 1;
  }
  return { checks, totalChecks: checks.length, byCategory };
}

/**
 * The mission briefing injected into the agent's scoped prompt. No fixed
 * checklist: the agent runs initial reconnaissance, then decides its own test
 * plan — what to test, how deep, in what order — based on what recon reveals.
 * It announces the plan as [PLAN] lines (so the operator can watch progress)
 * and accounts for each planned area with [CHECK] lines. The catalog below is
 * reference knowledge for what professional coverage considers — never a
 * required list.
 */
export function buildMissionPrompt(profile = 'full') {
  const depth = profile === 'quick'
    ? `This is a QUICK scan: after recon, plan a focused set of areas (aim for 6\u201310) and work them breadth-first \u2014 one solid, evidence-based vector each; follow only high-value leads deeper; keep momentum.`
    : `This is a FULL scan: after recon, plan comprehensive coverage (aim for 8\u201314 areas) and work depth-first where the target warrants it \u2014 multiple vectors per area, leads followed to their end, findings chained and escalated.`;
  return [
    `### Mission (recon-first, self-directed)`,
    `There is no fixed checklist. You decide everything from what reconnaissance reveals:`,
    ``,
    `1. RECON FIRST \u2014 map the target before testing: tech stack, pages, endpoints, APIs, inputs,`,
    `   auth model, roles, cookies, headers, scripts, behaviors. Learn what this target actually is.`,
    `2. DECIDE YOUR PLAN \u2014 based on recon, choose the areas worth testing and how deep to go on`,
    `   each. Announce the plan immediately, one line per area, in this exact format:`,
    `   [PLAN] short-id | Area title`,
    `   (short-id: lowercase letters, numbers, hyphens \u2014 e.g. [PLAN] auth-session | Authentication & session handling)`,
    `3. EXECUTE YOUR PLAN \u2014 work the areas in the order you chose, adapting as you learn. When an`,
    `   area's work is done, account for it with exactly one line:`,
    `   [CHECK] short-id | pass | one-line plain-language note`,
    `   [CHECK] short-id | issue | one-line plain-language note (also announce a [SUSPECT] line for it)`,
    `   [CHECK] short-id | skip | reason it does not apply to this target`,
    ``,
    depth,
    ``,
    `Professional coverage reference \u2014 areas a complete assessment typically considers. This is`,
    `REFERENCE, not a required list: your recon decides what matters for THIS target. Add areas`,
    `recon reveals that are not listed (an API surface, an admin panel, a payment flow, a file`,
    `upload, a search function\u2026):`,
    Object.values(CHECK_GROUPS).join(' | '),
    ``,
    `Never re-mark an area. Every planned area must end up marked pass, issue or skip \u2014 nothing`,
    `silently dropped. Areas you never planned are not tracked; plan carefully during recon.`,
  ].join('\n');
}
