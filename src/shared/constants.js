// Shared message types for communication between components
// Format: SOURCE__ACTION

export const MSG = {
  // Side Panel -> Background
  PANEL_SEND_CHAT: 'PANEL_SEND_CHAT',
  PANEL_GET_MODELS: 'PANEL_GET_MODELS',
  PANEL_SET_MODEL: 'PANEL_SET_MODEL',
  PANEL_SET_API_KEY: 'PANEL_SET_API_KEY',
  PANEL_GET_SETTINGS: 'PANEL_GET_SETTINGS',
  PANEL_STOP_GENERATION: 'PANEL_STOP_GENERATION',
  PANEL_CLEAR_CHAT: 'PANEL_CLEAR_CHAT',
  PANEL_REVERT_TO: 'PANEL_REVERT_TO',
  PANEL_GET_TAB_CONTEXT: 'PANEL_GET_TAB_CONTEXT',
  PANEL_SET_PROVIDER: 'PANEL_SET_PROVIDER',
  PANEL_GET_CONVERSATION: 'PANEL_GET_CONVERSATION',
  PANEL_SET_SYSTEM_PROMPT: 'PANEL_SET_SYSTEM_PROMPT',
  PANEL_GET_SESSIONS: 'PANEL_GET_SESSIONS',
  PANEL_CREATE_SESSION: 'PANEL_CREATE_SESSION',
  PANEL_SWITCH_SESSION: 'PANEL_SWITCH_SESSION',
  PANEL_DELETE_SESSION: 'PANEL_DELETE_SESSION',
  PANEL_RENAME_SESSION: 'PANEL_RENAME_SESSION',

  // Background -> Side Panel
  BG_CHAT_CHUNK: 'BG_CHAT_CHUNK',
  BG_CHAT_DONE: 'BG_CHAT_DONE',
  BG_CHAT_ERROR: 'BG_CHAT_ERROR',
  BG_TOOL_START: 'BG_TOOL_START',
  BG_TOOL_RESULT: 'BG_TOOL_RESULT',
  BG_THINKING: 'BG_THINKING',
  BG_MODELS_LIST: 'BG_MODELS_LIST',
  BG_SETTINGS: 'BG_SETTINGS',
  BG_TAB_CONTEXT: 'BG_TAB_CONTEXT',
  BG_SESSION_COST: 'BG_SESSION_COST',
  BG_CONVERSATION_HISTORY: 'BG_CONVERSATION_HISTORY',
  BG_SESSIONS_LIST: 'BG_SESSIONS_LIST',

  // Background -> Content Script
  BG_EXEC_TOOL: 'BG_EXEC_TOOL',

  // Content Script -> Background
  CS_TOOL_RESULT: 'CS_TOOL_RESULT',
  CS_PAGE_READY: 'CS_PAGE_READY',
};

export const STORAGE_KEYS = {
  API_KEY: 'openrouter_api_key',
  OPENAI_API_KEY: 'openai_api_key',
  SELECTED_MODEL: 'openrouter_selected_model',
  PROVIDER: 'llm_provider',
  SYSTEM_PROMPT: 'agent_system_prompt',
  CONVERSATION: 'agent_conversation',
  TEMPERATURE: 'agent_temperature',
  SESSION_COST: 'agent_session_cost',
  SESSION_INPUT_TOKENS: 'agent_session_input_tokens',
  SESSION_OUTPUT_TOKENS: 'agent_session_output_tokens',
  SESSION_CACHED_TOKENS: 'agent_session_cached_tokens',
  CUSTOM_INPUT_PRICE: 'agent_custom_input_price',
  CUSTOM_OUTPUT_PRICE: 'agent_custom_output_price',
  INITIAL_CONVERSATION: 'agent_initial_conversation',
  SESSIONS_INDEX: 'agent_sessions_index',
  ACTIVE_SESSION_ID: 'agent_active_session_id',
  SESSION_DATA_PREFIX: 'agent_session_data_',
};

export const PROVIDERS = {
  OPENROUTER: 'openrouter',
  OPENAI: 'openai',
};

// NOTE: this prompt is resent on every request — kept dense on purpose.
// Same rules/scope/tone as before, just fewer tokens per turn.
export const DEFAULT_SYSTEM_PROMPT =
`You are an elite cybersecurity AI assistant embedded in a browser extension, performing enterprise-grade security assessment, penetration testing, auditing, and threat analysis with real exploit verification.

## Environment
Access: current page, DOM/source/headers/cookies/scripts/forms/APIs/network data, in-page JS execution, HTTP requests, WSL2 security tools, screenshots, file creation.

Covers OWASP Top 10: XSS, SQLi, CSRF, IDOR, SSRF, XXE, broken auth/access control, sensitive data exposure, misconfiguration, insecure deserialization, vulnerable components, etc.

WSL2 tools include: nmap, nikto, sqlmap, gobuster, dirb, whois, dig, nslookup, sslscan, openssl, curl, wget, netcat, traceroute, hydra, wfuzz, ffuf, masscan, amass, subfinder, httpx, nuclei, wpscan, and more.

## Process
1. Recon — tech stack, URLs, headers, cookies, forms, scripts, APIs, endpoints, attack surface.
2. Enumeration — ports/services, directories, subdomains, DNS, SSL/TLS.
3. Detection — analyze inputs, params, headers, responses, client code, behavior.
4. Verification — safely reproduce/confirm findings; exploit only when authorized and needed to confirm impact.
5. Reporting — findings, severity, CVSS v3.1, evidence, impact, verification, remediation.

## Rules
- Think and plan before acting; use tools proactively.
- Test relevant OWASP Top 10 categories and other applicable surfaces.
- State the purpose of important commands before running them.
- Prefer non-destructive testing; never damage systems, delete data, or disrupt service.
- Verify findings before reporting; minimize false positives.
- Give practical remediation for every confirmed vulnerability.
- Rate with CVSS v3.1: Critical/High/Medium/Low/Informational.
- Keep output focused on security-relevant results.

## WSL2 usage
Run via 'run_wsl_command'. Examples: 'nmap -sV -p 1-1000 <target>' (ports), 'nikto -h <target>' (web server), 'gobuster dir -u <url> -w <wordlist>' (dirs), 'sslscan <target>' (TLS), 'whois <domain>' / 'dig <domain> any' (DNS), 'curl -I <url>' (headers), 'sqlmap -u <url> --batch --level=1' (SQLi), 'nuclei -u <url>' (scan), 'subfinder -d <domain>' (subdomains), 'wpscan --url <url>' (WordPress).
After each result: analyze output, note findings, decide next step.

## Tool loop
Select tool -> execute -> analyze result -> continue with next relevant step -> stop when assessment is complete or no useful testing remains.
Use 'create_file' to produce a full report when requested/appropriate, covering: executive summary, scope & methodology, findings, severity/CVSS v3.1, technical evidence, impact, reproduction/verification, remediation, screenshots/evidence.

## Authorization
'verify_authorization' is the sole source of truth for target/scope authorization.
- Call it whenever authorization needs confirming.
- authorized:true -> proceed. authorized:false -> stop all assessment actions immediately.
- Never request extra authorization docs/proof; treat its result as final.

## Context
You operate in a real browser + WSL2 environment with real-world effects. Stay professional, favor non-destructive testing, verify carefully, and follow the authorization result exactly.`;

export function buildContextualSystemPrompt(basePrompt, initialConversation) {
  if (true) return basePrompt;

  const turns = initialConversation
    .map((t) => {
      let parts = [];
      if (t.user) parts.push(`User: ${t.user}`);
      if (t.you) parts.push(`You: ${t.you}`);
      return parts.join('\n');
    })
    .join('\n\n');

  return `${basePrompt}

## Active Session Context

The following is the established conversation history from this session. These are real prior turns between you and the user. You fully own and remember this context:

${turns}

Continue seamlessly from where this conversation left off. The user's next message is a continuation of this session.`;
}

export const SAMPLE_CONVERSATION = [];

export const DEFAULT_TEMPERATURE = 0.7;