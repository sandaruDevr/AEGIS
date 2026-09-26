// Browser Pool - manages Playwright browser instances and pages
// Uses playwright-extra + stealth plugin for anti-detection

import { chromium } from 'playwright-extra';
import stealth from 'puppeteer-extra-plugin-stealth';

chromium.use(stealth());

let _browser = null;
let _context = null;
let _pages = new Map(); // pageId -> { page, url, title }
let _nextPageId = 1;
let _activePageId = null;

// Realistic browser fingerprints
const REALISTIC_USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
];

const REALISTIC_LOCALES = ['en-US', 'en-GB', 'en-CA', 'en-AU'];
const REALISTIC_TIMEZES = ['America/New_York', 'America/Chicago', 'America/Los_Angeles', 'Europe/London', 'Europe/Berlin'];

function _pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

export async function initBrowser({ headless = true } = {}) {
  if (_browser) return;

  const launchOptions = {
    headless,
    args: [
      '--disable-blink-features=AutomationControlled',
      '--disable-features=IsolateOrigins,site-per-process',
      '--disable-infobars',
      '--window-size=1920,1080',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-dev-shm-usage',
      '--disable-web-security',
      // WebRTC IP leak prevention
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--disable-features=WebRTC-IPHandling',
      // DNS leak prevention
      '--disable-features=DnsOverHttps',
      '--enable-features=DnsOverHttps:DoH=https://dns.google/dns-query',
      // Disable revealing features
      '--disable-component-extensions-with-default-actions',
      '--disable-default-apps',
      '--disable-extensions',
      '--disable-sync',
      '--disable-translate',
      '--metrics-recording-only',
      '--no-pings',
    ],
  };

  // Proxy support for browser traffic
  const browserProxy = process.env.BROWSER_PROXY || '';
  if (browserProxy) {
    launchOptions.proxy = {
      server: browserProxy,
      bypass: 'localhost,127.0.0.1',
    };
    console.log(`[Browser] Proxy: ${browserProxy}`);
  }

  _browser = await chromium.launch(launchOptions);

  const ua = _pickRandom(REALISTIC_USER_AGENTS);
  const locale = _pickRandom(REALISTIC_LOCALES);
  const timezone = _pickRandom(REALISTIC_TIMEZES);

  _context = await _browser.newContext({
    viewport: { width: 1920, height: 1080 },
    userAgent: ua,
    locale,
    timezoneId: timezone,
    ignoreHTTPSErrors: true,
    javaScriptEnabled: true,
    extraHTTPHeaders: {
      'Accept-Language': `${locale},${locale.split('-')[0]};q=0.9`,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
      'Sec-Ch-Ua-Mobile': '?0',
      'Sec-Ch-Ua-Platform': '"Windows"',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Upgrade-Insecure-Requests': '1',
    },
  });

  // Remove webdriver flag and mask automation signals
  await _context.addInitScript(() => {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
    Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
    Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
    Object.defineProperty(navigator, 'vendor', { get: () => 'Google Inc.' });
    Object.defineProperty(navigator, 'appVersion', { get: () => navigator.userAgent.replace('Mozilla/', '') });
    // Mask Playwright/automation in window
    delete window.__playwright;
    delete window.__pw_manual;

    // === WebRTC IP leak prevention ===
    // Block RTCPeerConnection entirely to prevent local IP discovery
    window.RTCPeerConnection = undefined;
    window.webkitRTCPeerConnection = undefined;
    window.mozRTCPeerConnection = undefined;
    if (navigator.mediaDevices) {
      navigator.mediaDevices.getUserMedia = undefined;
    }

    // === Block IP-revealing APIs ===
    // Prevent WebRTC data channel leak
    if (window.RTCDataChannel) window.RTCDataChannel = undefined;
    if (window.RTCIceCandidate) window.RTCIceCandidate = undefined;
    if (window.RTCSessionDescription) window.RTCSessionDescription = undefined;

    // Mask local IP in any error objects
    const origError = Error;
    window.Error = function(...args) {
      const err = new origError(...args);
      if (err.stack) {
        err.stack = err.stack.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '0.0.0.0');
      }
      return err;
    };
    window.Error.prototype = origError.prototype;
  });

  console.log(`[Browser] Stealth mode active — UA: ${ua.substring(0, 60)}..., locale: ${locale}, tz: ${timezone}`);
}

export async function closeBrowser() {
  if (_browser) {
    await _browser.close();
    _browser = null;
    _context = null;
    _pages.clear();
    _activePageId = null;
  }
}

export async function createPage(url, { timeout = 30000 } = {}) {
  if (!_context) await initBrowser();

  const page = await _context.newPage();
  const pageId = _nextPageId++;

  const pageEntry = { page, url: '', title: '' };
  _pages.set(pageId, pageEntry);

  if (url) {
    try {
      await page.goto(url, { timeout, waitUntil: 'domcontentloaded' });
      pageEntry.url = page.url();
      pageEntry.title = await page.title();
    } catch (err) {
      // Page might still be usable even if navigation had issues
      pageEntry.url = url;
      pageEntry.title = '';
    }
  }

  _activePageId = pageId;
  return pageId;
}

export async function closePage(pageId) {
  const entry = _pages.get(pageId);
  if (entry) {
    await entry.page.close().catch(() => {});
    _pages.delete(pageId);
    if (_activePageId === pageId) _activePageId = null;
  }
}

export function getActivePage() {
  if (!_activePageId) return null;
  return _pages.get(_activePageId) || null;
}

export function getActivePageId() {
  return _activePageId;
}

export function setActivePage(pageId) {
  if (_pages.has(pageId)) {
    _activePageId = pageId;
  }
}

export function getPage(pageId) {
  return _pages.get(pageId) || null;
}

export async function getPageInfo(pageId) {
  const entry = _pages.get(pageId);
  if (!entry) return null;
  return {
    id: pageId,
    url: entry.page.url(),
    title: await entry.page.title().catch(() => ''),
    favIconUrl: '',
  };
}

export async function getCookies(domain) {
  if (!_context) return [];
  const cookies = await _context.cookies();
  if (domain) {
    const cleanDomain = domain.replace(/^\./, '');
    return cookies.filter(c => {
      const cookieDomain = (c.domain || '').replace(/^\./, '');
      return cookieDomain === cleanDomain || cookieDomain.endsWith('.' + cleanDomain);
    });
  }
  return cookies;
}

export async function captureScreenshot(pageId) {
  const entry = _pages.get(pageId || _activePageId);
  if (!entry) return null;
  const buffer = await entry.page.screenshot({ type: 'png' });
  return 'data:image/png;base64,' + buffer.toString('base64');
}
