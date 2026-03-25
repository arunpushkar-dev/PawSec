/**
 * Browser compatibility shim — injected for Firefox MV2 builds.
 * Normalises chrome.action (MV3) → chrome.browserAction (MV2).
 * Also neutralises the service-worker-only self.addEventListener('fetch') call.
 */

// Polyfill chrome.action with chrome.browserAction for Firefox MV2
if (typeof chrome !== 'undefined' && !chrome.action && chrome.browserAction) {
  chrome.action = chrome.browserAction;
}

// Silence service-worker-specific fetch listener in MV2 background pages.
// In an MV2 event page `self` is the background window — adding a 'fetch'
// listener there is a no-op but we suppress the error just in case.
if (typeof self !== 'undefined' && typeof ServiceWorkerGlobalScope === 'undefined') {
  const _origAddEL = self.addEventListener.bind(self);
  self.addEventListener = function (type, ...args) {
    if (type === 'fetch') return; // suppress SW-only listener in background page
    return _origAddEL(type, ...args);
  };
}
