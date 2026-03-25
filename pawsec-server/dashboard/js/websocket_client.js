/**
 * WebSocket client with exponential backoff reconnect.
 * Reconnect delays: 1s → 2s → 4s → 8s → 30s (cap).
 */

export class WSClient extends EventTarget {
  #url;
  #ws = null;
  #retryDelay = 1000;
  #maxDelay = 30000;
  #retryTimer = null;
  #intentionallyClosed = false;

  constructor(url) {
    super();
    this.#url = url;
  }

  connect() {
    this.#intentionallyClosed = false;
    this.#open();
  }

  disconnect() {
    this.#intentionallyClosed = true;
    clearTimeout(this.#retryTimer);
    if (this.#ws) {
      this.#ws.close();
      this.#ws = null;
    }
    this.dispatchEvent(new CustomEvent('status', { detail: 'disconnected' }));
  }

  #open() {
    this.dispatchEvent(new CustomEvent('status', { detail: 'connecting' }));
    try {
      this.#ws = new WebSocket(this.#url);
    } catch {
      this.#scheduleRetry();
      return;
    }

    this.#ws.addEventListener('open', () => {
      this.#retryDelay = 1000;
      this.dispatchEvent(new CustomEvent('status', { detail: 'connected' }));
    });

    this.#ws.addEventListener('message', (ev) => {
      try {
        const data = JSON.parse(ev.data);
        this.dispatchEvent(new CustomEvent('message', { detail: data }));
      } catch {/* ignore malformed */}
    });

    this.#ws.addEventListener('close', () => {
      this.#ws = null;
      if (!this.#intentionallyClosed) {
        this.dispatchEvent(new CustomEvent('status', { detail: 'reconnecting' }));
        this.#scheduleRetry();
      }
    });

    this.#ws.addEventListener('error', () => {
      // close event will fire after error
      this.dispatchEvent(new CustomEvent('status', { detail: 'error' }));
    });
  }

  #scheduleRetry() {
    clearTimeout(this.#retryTimer);
    this.#retryTimer = setTimeout(() => {
      this.#retryDelay = Math.min(this.#retryDelay * 2, this.#maxDelay);
      this.#open();
    }, this.#retryDelay);
  }

  send(data) {
    if (this.#ws && this.#ws.readyState === WebSocket.OPEN) {
      this.#ws.send(JSON.stringify(data));
    }
  }
}
