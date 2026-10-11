// Jev client — typed, calibrated decisions (TypeSafe System One decision model).
//
// Providers (JEV_PROVIDER):
//   openrouter (default) — Jev via the OpenRouter Decisions API
//     POST https://openrouter.ai/api/alpha/decisions
//     Auth: the existing OPENROUTER_API_KEY, billed to the same account.
//     Model: typesafe/jev-1.13 (alias ~typesafe/jev-latest tracks the newest).
//   typesafe — the hosted metered proxy at jevtypesafeai.com
//     POST https://jevtypesafeai.com/api/v1/decide
//     Auth: JEV_API_KEY (jv_live_...). Set JEV_ENDPOINT to
//     https://api.typesafe.ai/v1/systemone to use the official API instead.
//
// Enterprise posture:
//   - Typed questions only (choice / score / noul) — answers branch in plain
//     code, no free-text parsing, no format hallucination
//   - Timeout + bounded retry (5xx/network only), circuit breaker with
//     cool-down after repeated failures
//   - State trimming — billed per input token, so only decision-relevant
//     context is sent (Jev context window: 32k tokens)
//   - Secret-safe: API keys are never logged; failures log reason only
//   - Fails closed to `null` — callers keep their safe default behavior

const PROVIDERS = {
  openrouter: {
    endpoint: 'https://openrouter.ai/api/alpha/decisions',
    keyEnv: 'OPENROUTER_API_KEY',
    useModelField: true,
  },
  typesafe: {
    endpoint: 'https://jevtypesafeai.com/api/v1/decide',
    keyEnv: 'JEV_API_KEY',
    useModelField: false,
  },
};

export class JevClient {
  constructor({
    provider = process.env.JEV_PROVIDER || 'openrouter',
    apiKey = null, // resolved from the provider's env key by default
    model = process.env.JEV_MODEL || 'typesafe/jev-1.13',
    endpoint = process.env.JEV_ENDPOINT || null, // hard override (e.g. official api.typesafe.ai)
    timeoutMs = 6000,
    maxStateChars = 4000,
    failureThreshold = 3,
    coolDownMs = 60_000,
  } = {}) {
    const preset = PROVIDERS[provider] || PROVIDERS.openrouter;
    this.provider = preset === PROVIDERS[provider] ? provider : 'openrouter';
    this.endpoint = endpoint || preset.endpoint;
    this.apiKey = apiKey || process.env[preset.keyEnv] || null;
    this.model = model;
    this.useModelField = preset.useModelField;
    this.timeoutMs = timeoutMs;
    this.maxStateChars = maxStateChars;
    this.failureThreshold = failureThreshold;
    this.coolDownMs = coolDownMs;
    // Circuit breaker state
    this._failures = 0;
    this._openUntil = 0;
    this._disabled = false; // hard-off (auth rejected / balance empty)
  }

  // Whether a decision call should even be attempted right now.
  get available() {
    return Boolean(this.apiKey) && !this._disabled && Date.now() >= this._openUntil;
  }

  trimState(state) {
    const s = String(state ?? '');
    return s.length > this.maxStateChars ? `${s.slice(0, this.maxStateChars)}…[truncated]` : s;
  }

  // One round trip, any number of typed questions. Returns the `answers` map
  // or null (unavailable / failed) — never throws.
  async decide(state, questions) {
    if (!this.available) return null;
    const body = { state: this.trimState(state), questions };
    if (this.useModelField) body.model = this.model;

    for (let attempt = 0; attempt < 2; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const res = await fetch(this.endpoint, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
            ...(this.provider === 'openrouter' ? { 'X-Title': 'AEGIS WAF' } : {}),
          },
          body: JSON.stringify(body),
          signal: controller.signal,
        });

        if (res.status === 402) {
          this._disabled = true;
          console.warn('[Jev] Prepaid balance empty (402) — Jev triage disabled until restart. Top up at jevtypesafeai.com/pricing.');
          return null;
        }
        if (res.status === 401 || res.status === 403) {
          this._disabled = true;
          console.warn('[Jev] Auth rejected — check JEV_API_KEY. Jev triage disabled until restart.');
          return null;
        }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const data = await res.json();
        this._failures = 0;
        return data?.answers || null;
      } catch (err) {
        this._failures++;
        if (this._failures >= this.failureThreshold) {
          this._openUntil = Date.now() + this.coolDownMs;
          this._failures = 0;
          console.warn(`[Jev] Circuit open for ${Math.round(this.coolDownMs / 1000)}s after repeated failures.`);
        }
        if (attempt === 1) {
          console.warn(`[Jev] decide failed: ${err.message}`);
          return null;
        }
        await new Promise((r) => setTimeout(r, 400)); // brief backoff, then one retry
      } finally {
        clearTimeout(timer);
      }
    }
    return null;
  }
}
