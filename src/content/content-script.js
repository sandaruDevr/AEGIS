// Content script - executes tools in the page context
// Handles all DOM-related tool calls from the background service worker

(() => {
  'use strict';

  // Guard against double-injection (manifest content_scripts + programmatic injection)
  if (window.__AGENT_CONTENT_SCRIPT_LOADED__) return;
  window.__AGENT_CONTENT_SCRIPT_LOADED__ = true;

  const MSG = {
    BG_EXEC_TOOL: 'BG_EXEC_TOOL',
    CS_PAGE_READY: 'CS_PAGE_READY',
  };

  // Notify background that content script is ready
  try {
    chrome.runtime.sendMessage({ type: MSG.CS_PAGE_READY });
  } catch (e) {
    // Extension context may be invalidated
  }

  // ---- Tool Implementations ----

  function getPageInfo() {
    const meta = {};
    document.querySelectorAll('meta').forEach((m) => {
      const name = m.getAttribute('name') || m.getAttribute('property');
      if (name) meta[name] = m.getAttribute('content');
    });

    return {
      url: window.location.href,
      title: document.title,
      domain: window.location.hostname,
      metaTags: meta,
      viewport: {
        width: window.innerWidth,
        height: window.innerHeight,
      },
      document: {
        width: document.documentElement.scrollWidth,
        height: document.documentElement.scrollHeight,
      },
      charset: document.characterSet,
      language: document.documentElement.lang || 'unknown',
    };
  }

  function buildStructureTree(element, maxDepth, currentDepth = 0) {
    if (currentDepth >= maxDepth || !element) return null;

    const node = {
      tag: element.tagName.toLowerCase(),
      id: element.id || undefined,
      classes: element.className && typeof element.className === 'string'
        ? element.className.split(/\s+/).filter(Boolean)
        : [],
      childCount: element.children.length,
    };

    if (element.children.length > 0 && currentDepth < maxDepth - 1) {
      node.children = Array.from(element.children)
        .slice(0, 50) // Limit children to prevent explosion
        .map((child) => buildStructureTree(child, maxDepth, currentDepth + 1))
        .filter(Boolean);
    }

    return node;
  }

  function readPageStructure({ selector, maxDepth }) {
    const root = selector ? document.querySelector(selector) : document.body;
    if (!root) {
      return { success: false, error: `No element found for selector: ${selector}` };
    }
    const tree = buildStructureTree(root, maxDepth || 5);
    return { success: true, result: tree };
  }

  function readPageHTML({ selector, outerHTML }) {
    const el = selector ? document.querySelector(selector) : document.documentElement;
    if (!el) {
      return { success: false, error: `No element found for selector: ${selector}` };
    }
    const html = outerHTML ? el.outerHTML : el.innerHTML;
    // Truncate if too large
    const maxLen = 50000;
    const truncated = html.length > maxLen
      ? html.substring(0, maxLen) + '\n... [truncated, total length: ' + html.length + ']'
      : html;
    return { success: true, result: truncated };
  }

  function readPageText({ selector }) {
    const el = selector ? document.querySelector(selector) : document.body;
    if (!el) {
      return { success: false, error: `No element found for selector: ${selector}` };
    }
    const text = el.innerText || el.textContent;
    const maxLen = 30000;
    const truncated = text.length > maxLen
      ? text.substring(0, maxLen) + '\n... [truncated, total length: ' + text.length + ']'
      : text;
    return { success: true, result: truncated };
  }

  function readElement({ selector }) {
    const el = document.querySelector(selector);
    if (!el) {
      return { success: false, error: `No element found for selector: ${selector}` };
    }

    const computed = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();

    return {
      success: true,
      result: {
        tagName: el.tagName.toLowerCase(),
        id: el.id || undefined,
        classes: el.className && typeof el.className === 'string'
          ? el.className.split(/\s+/).filter(Boolean)
          : [],
        attributes: Object.fromEntries(
          Array.from(el.attributes).map((a) => [a.name, a.value])
        ),
        textContent: (el.innerText || el.textContent || '').substring(0, 1000),
        innerHTML: el.innerHTML.substring(0, 5000),
        computedStyles: {
          display: computed.display,
          position: computed.position,
          width: computed.width,
          height: computed.height,
          color: computed.color,
          backgroundColor: computed.backgroundColor,
          fontSize: computed.fontSize,
          fontFamily: computed.fontFamily,
          margin: computed.margin,
          padding: computed.padding,
          border: computed.border,
        },
        dimensions: {
          width: rect.width,
          height: rect.height,
          top: rect.top,
          left: rect.left,
        },
        childCount: el.children.length,
      },
    };
  }

  function querySelectorAll({ selector, limit }) {
    const elements = document.querySelectorAll(selector);
    const max = limit || 50;
    const results = Array.from(elements).slice(0, max).map((el, i) => ({
      index: i,
      tag: el.tagName.toLowerCase(),
      id: el.id || undefined,
      classes: el.className && typeof el.className === 'string'
        ? el.className.split(/\s+/).filter(Boolean)
        : [],
      textPreview: (el.innerText || el.textContent || '').substring(0, 200),
    }));
    return {
      success: true,
      result: { totalFound: elements.length, returned: results.length, elements: results },
    };
  }

  function modifyElement({ selector, textContent, innerHTML, attributes, styles }) {
    const elements = document.querySelectorAll(selector);
    if (!elements.length) {
      return { success: false, error: `No elements found for selector: ${selector}` };
    }

    let modified = 0;
    elements.forEach((el) => {
      if (textContent !== undefined) el.textContent = textContent;
      if (innerHTML !== undefined) el.innerHTML = innerHTML;
      if (attributes) {
        for (const [key, value] of Object.entries(attributes)) {
          if (value === null) el.removeAttribute(key);
          else el.setAttribute(key, value);
        }
      }
      if (styles) {
        for (const [key, value] of Object.entries(styles)) {
          el.style[key] = value;
        }
      }
      modified++;
    });

    return { success: true, result: `Modified ${modified} element(s) matching "${selector}".` };
  }

  function injectStyle({ css, id }) {
    const styleId = id || 'agent-injected-style';
    let styleEl = document.getElementById(styleId);
    if (!styleEl) {
      styleEl = document.createElement('style');
      styleEl.id = styleId;
      document.head.appendChild(styleEl);
    }
    styleEl.textContent = css;
    return { success: true, result: `Injected CSS with id "${styleId}".` };
  }

  function executeScript({ code }) {
    // This is handled by the background service worker using chrome.scripting
    // with world: 'MAIN' for true page-context execution.
    // Content script's isolated world can't access page JS context.
    return { success: false, error: 'execute_script is handled by background.' };
  }

  function analyzeForms() {
    const forms = document.querySelectorAll('form');
    if (!forms.length) {
      return { success: true, result: { forms: [], findings: ['No forms found on this page.'] } };
    }

    const findings = [];
    const formData = Array.from(forms).map((form, idx) => {
      const inputs = Array.from(form.querySelectorAll('input, select, textarea'));
      const hiddenInputs = inputs.filter((i) => i.type === 'hidden');
      const passwordInputs = inputs.filter((i) => i.type === 'password');

      const hasCsrfToken = hiddenInputs.some((i) => {
        const name = (i.name || '').toLowerCase();
        return name.includes('csrf') || name.includes('token') || name.includes('_token');
      });

      const action = form.action || form.getAttribute('action') || '';
      const isInsecureAction = action.startsWith('http://');

      if (isInsecureAction) {
        findings.push({
          severity: 'High',
          title: `Form ${idx + 1}: Insecure Action URL`,
          description: `Form submits to insecure HTTP URL: ${action}`,
          recommendation: 'Use HTTPS for form submissions.',
        });
      }

      if (form.method && form.method.toUpperCase() === 'GET' && passwordInputs.length > 0) {
        findings.push({
          severity: 'High',
          title: `Form ${idx + 1}: Password field in GET form`,
          description: 'Password field submitted via GET method, exposing credentials in URL.',
          recommendation: 'Use POST method for forms with password fields.',
        });
      }

      if (!hasCsrfToken && form.method && form.method.toUpperCase() === 'POST') {
        findings.push({
          severity: 'Medium',
          title: `Form ${idx + 1}: Potential Missing CSRF Protection`,
          description: 'No CSRF token found in hidden fields for POST form.',
          recommendation: 'Add CSRF tokens to all state-changing forms.',
        });
      }

      passwordInputs.forEach((inp) => {
        if (inp.autocomplete === 'off') {
          // This is actually good, not a finding
        } else if (!inp.autocomplete) {
          findings.push({
            severity: 'Low',
            title: `Form ${idx + 1}: Password field without autocomplete restriction`,
            description: 'Password field does not set autocomplete="new-password" or "off".',
            recommendation: 'Set autocomplete="new-password" or "off" on password fields.',
          });
        }
      });

      return {
        index: idx + 1,
        action,
        method: form.method || 'GET',
        enctype: form.enctype || '',
        inputCount: inputs.length,
        inputs: inputs.map((i) => ({
          name: i.name || '',
          type: i.type || 'text',
          required: i.required,
          autocomplete: i.autocomplete || '',
        })),
        hiddenFields: hiddenInputs.map((i) => ({ name: i.name, value: i.value.substring(0, 100) })),
        hasCsrfToken,
      };
    });

    return { success: true, result: { forms: formData, findings } };
  }

  function inspectJsSources({ includeInline }) {
    const scripts = document.querySelectorAll('script[src]');
    const inlineScripts = includeInline ? document.querySelectorAll('script:not([src])') : [];

    const srcList = Array.from(scripts).map((s) => {
      const src = s.src || s.getAttribute('src') || '';
      const isExternal = src.startsWith('http');
      const isHttp = src.startsWith('http://');

      const interesting = [];
      if (src.includes('api') || src.includes('config') || src.includes('key') || src.includes('secret')) {
        interesting.push('Potentially sensitive filename');
      }
      if (isHttp) {
        interesting.push('Loaded over insecure HTTP');
      }

      return { src, external: isExternal, interesting };
    });

    const inlineList = Array.from(inlineScripts).map((s, idx) => {
      const content = s.textContent || '';
      const interesting = [];

      if (/api[_-]?key|secret|token|password|credential/i.test(content)) {
        interesting.push('Contains potential secrets/credentials');
      }
      if (/fetch\(|XMLHttpRequest|axios|\.ajax\(/i.test(content)) {
        interesting.push('Contains API calls');
      }
      if (/eval\(|Function\(|document\.write/i.test(content)) {
        interesting.push('Contains potentially dangerous functions');
      }

      return {
        index: idx + 1,
        length: content.length,
        preview: content.substring(0, 500),
        interesting,
      };
    });

    const findings = [];
    srcList.forEach((s) => {
      if (s.interesting.includes('Loaded over insecure HTTP')) {
        findings.push({
          severity: 'Medium',
          title: `Insecure JavaScript Source: ${s.src}`,
          description: 'Script loaded over insecure HTTP, vulnerable to MITM attacks.',
          recommendation: 'Load all scripts over HTTPS.',
        });
      }
    });
    inlineList.forEach((s) => {
      if (s.interesting.includes('Contains potential secrets/credentials')) {
        findings.push({
          severity: 'High',
          title: `Inline Script ${s.index}: Potential Secrets Detected`,
          description: 'Inline script contains patterns matching API keys, tokens, or credentials.',
          recommendation: 'Remove hardcoded secrets from client-side code.',
        });
      }
    });

    return {
      success: true,
      result: {
        externalScripts: srcList,
        inlineScripts: inlineList,
        findings,
      },
    };
  }

  function scanForSecrets({ includeScripts }) {
    const html = document.documentElement.outerHTML;
    const patterns = [
      { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'Critical' },
      { name: 'AWS Secret Key', regex: /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g, severity: 'High' },
      { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'High' },
      { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: 'High' },
      { name: 'Private Key', regex: /-----BEGIN[A-Z\s]+PRIVATE KEY-----/g, severity: 'Critical' },
      { name: 'Generic API Key', regex: /(?:api[_-]?key|apikey|api[_-]?secret)["\s:=]+([A-Za-z0-9_\-]{20,})/gi, severity: 'High' },
      { name: 'Bearer Token', regex: /Bearer\s+[A-Za-z0-9_\-\.]+/g, severity: 'High' },
      { name: 'Password in Source', regex: /(?:password|passwd|pwd)["\s:=]+["']([^"']{3,})["']/gi, severity: 'Medium' },
      { name: 'Connection String', regex: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+/gi, severity: 'High' },
      { name: 'Slack Token', regex: /xox[baprs]-[0-9A-Za-z-]+/g, severity: 'High' },
      { name: 'Stripe Key', regex: /(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,}/g, severity: 'High' },
      { name: 'GitHub Token', regex: /gh[ps]_[A-Za-z0-9]{36}/g, severity: 'High' },
    ];

    const sources = [html];
    if (includeScripts !== false) {
      const inlineScripts = document.querySelectorAll('script:not([src])');
      inlineScripts.forEach((s) => sources.push(s.textContent || ''));
    }

    const findings = [];
    const allContent = sources.join('\n');

    for (const { name, regex, severity } of patterns) {
      const matches = allContent.match(regex);
      if (matches) {
        findings.push({
          severity,
          title: `${name} Found`,
          description: `${matches.length} match(es) found. Sample: ${matches[0].substring(0, 80)}...`,
          recommendation: `Remove ${name} from client-side code. Store secrets server-side.`,
        });
      }
    }

    return {
      success: true,
      result: {
        url: location.href,
        findings,
        scannedSources: sources.length,
      },
    };
  }

  function extractData({ containerSelector, fields, limit }) {
    const containers = document.querySelectorAll(containerSelector);
    if (!containers.length) {
      return { success: false, error: `No containers found for selector: ${containerSelector}` };
    }

    const max = limit || 100;
    const data = Array.from(containers).slice(0, max).map((container) => {
      const item = {};
      for (const field of fields) {
        const el = container.querySelector(field.selector);
        if (!el) {
          item[field.name] = null;
          continue;
        }
        if (field.attribute === 'html') {
          item[field.name] = el.innerHTML;
        } else if (field.attribute && field.attribute !== 'text') {
          item[field.name] = el.getAttribute(field.attribute);
        } else {
          item[field.name] = (el.innerText || el.textContent || '').trim();
        }
      }
      return item;
    });

    return {
      success: true,
      result: { totalFound: containers.length, extracted: data.length, data },
    };
  }

  async function screenshot({ selector }) {
    try {
      // Use chrome.tabs.captureVisibleTab via a message to background
      // Since content scripts can't call captureVisibleTab directly,
      // we'll use the element's position if a selector is given
      const response = await chrome.runtime.sendMessage({
        type: 'CAPTURE_SCREENSHOT',
        selector,
      });
      return response;
    } catch (err) {
      return { success: false, error: `Screenshot failed: ${err.message}` };
    }
  }

  function scrollPage({ selector, x, y, behavior }) {
    if (selector) {
      const el = document.querySelector(selector);
      if (el) {
        el.scrollIntoView({ behavior: behavior || 'auto', block: 'center' });
        return { success: true, result: `Scrolled to element "${selector}".` };
      }
      return { success: false, error: `No element found for selector: ${selector}` };
    }
    window.scrollTo({
      top: y || 0,
      left: x || 0,
      behavior: behavior || 'auto',
    });
    return { success: true, result: `Scrolled to (${x || 0}, ${y || 0}).` };
  }

  function clickElement({ selector }) {
    const el = document.querySelector(selector);
    if (!el) {
      return { success: false, error: `No element found for selector: ${selector}` };
    }
    el.click();
    return { success: true, result: `Clicked element "${selector}".` };
  }

  // ---- Tool Dispatcher ----

  const toolHandlers = {
    get_page_info: getPageInfo,
    read_page_structure: readPageStructure,
    read_page_html: readPageHTML,
    read_page_text: readPageText,
    read_element: readElement,
    query_selector_all: querySelectorAll,
    modify_element: modifyElement,
    inject_style: injectStyle,
    execute_script: executeScript,
    extract_data: extractData,
    screenshot: screenshot,
    scroll_page: scrollPage,
    click_element: clickElement,
    analyze_forms: analyzeForms,
    inspect_js_sources: inspectJsSources,
    scan_for_secrets: scanForSecrets,
  };

  // ---- Message Listener ----

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type !== MSG.BG_EXEC_TOOL) return true;

    const handler = toolHandlers[msg.tool];
    if (!handler) {
      sendResponse({ success: false, error: `Unknown tool: ${msg.tool}` });
      return true;
    }

    try {
      const result = handler(msg.args || {});
      // Handle both sync and async results
      if (result instanceof Promise) {
        result.then(sendResponse).catch((err) => {
          sendResponse({ success: false, error: err.message });
        });
        return true; // Keep channel open for async
      }
      sendResponse(result);
    } catch (err) {
      sendResponse({ success: false, error: err.message });
    }
    return true;
  });
})();
