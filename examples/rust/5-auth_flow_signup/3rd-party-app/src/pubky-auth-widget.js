import { LitElement, css, html } from "lit";
import { ref } from "lit/directives/ref.js";
import QRCode from "qrcode";

// ✅ Import the SDK as an ES module (no window global)
import * as pubky from "@synonymdev/pubky";

const DEFAULT_HTTP_RELAY = "https://httprelay.staging.pubky.app/inbox/";
const TESTNET_HTTP_RELAY = "http://localhost:15412/inbox";

/**
 * <pubky-auth-widget>
 * Third-party (unhosted) Pubky Auth widget:
 * - Creates an AuthFlow and renders a QR with the deep link.
 * - Await approval:
 *   - If `caps` is empty -> waits for an AuthToken and shows the public key it belongs to.
 *   - If `caps` is provided -> waits for a Session and shows the authenticated user's public key.
 *
 * Props/attrs:
 * - relay?: string  — optional HTTP relay base; if not set, defaults to staging or testnet.
 * - caps?: string   — comma-separated scopes (e.g. "/pub/app/:rw,/pub/foo.txt:r"). Empty means “authN only”.
 * - open?: boolean  — whether the widget is expanded.
 * - testnet?: boolean — toggled via switchTestnet().
 */
export class PubkyAuthWidget extends LitElement {
  static get properties() {
    return {
      relay: { type: String },
      caps: { type: String },
      signupToken: { type: String | null },
      homeserverPublicKey: { type: String },
      open: { type: Boolean },
      showCopied: { type: Boolean },
      testnet: { type: Boolean },
      // state
      _pubkyZ32: { type: String, state: true },
      _authUrl: { type: String, state: true },
    };
  }

  constructor() {
    super();
    if (typeof pubky.setLogLevel === "function") pubky.setLogLevel("debug");

    this.testnet = false;
    this.open = false;
    this.caps = this.caps || "";

    // Share one facade across flows
    this._sdk = new pubky.Pubky();

    // internal
    this._canvas = null;
  }

  // Public helpers for the demo page checkboxes
  switchTestnet() {
    this.testnet = !this.testnet;
    this._sdk = this.testnet ? pubky.Pubky.testnet() : new pubky.Pubky();
    this._resetFlowAndQr();
  }

  setCapabilities(caps) {
    this.caps = caps || "";
    this._resetFlowAndQr();
  }

  // ---- Flow + QR handling ---------------------------------------------------

  _resetFlowAndQr() {
    // If already open, restart the flow; then (re)draw when canvas is mounted
    if (this.open) this._generateFlow();
    this.updateComplete.then(() => this._updateQr());
  }

  _generateFlow() {
    const relay =
      this.relay || (this.testnet ? TESTNET_HTTP_RELAY : DEFAULT_HTTP_RELAY);

    // Start the flow with the facade’s client
    let homeserverPublicKey = pubky.PublicKey.from(this.homeserverPublicKey);
    const flow = this._sdk.startCookieAuthFlow(this.caps, pubky.AuthFlowKind.signup(homeserverPublicKey, this.signupToken), relay);

    // Capture the deep link *before* awaiting (await will consume the flow handle)
    this._authUrl = flow.authorizationUrl;

    // Redraw the QR now and again on next frame (covers initial layout/paint timing)
    this._updateQr();
    requestAnimationFrame(() => this._updateQr());

    // Waiting behavior depends on whether we request capabilities or not
    if (this.caps && this.caps.trim().length > 0) {
      // Capabilities requested -> wait for a Session
      flow
        .awaitApproval()
        .then((session) => {
          this._pubkyZ32 = session.info.publicKey.z32();
        })
        .catch((e) => console.error("Auth flow (session) failed:", e));
    } else {
      // No capabilities -> wait for an AuthToken and read the public key from it
      flow
        .awaitToken()
        .then((token) => {
          this._pubkyZ32 = token.publicKey.z32();
        })
        .catch((e) => console.error("Auth flow (token) failed:", e));
    }
  }

  _setQr(canvas) {
    this._canvas = canvas || null;
    this._updateQr();
  }

  _updateQr() {
    // We need both a canvas and the URL
    if (!this._canvas || !this._authUrl) return;
    try {
      QRCode.toCanvas(this._canvas, this._authUrl, {
        margin: 2,
        scale: 8,
        color: { light: "#fff", dark: "#000" },
      });
    } catch (e) {
      console.error("QR render error:", e);
    }
  }

  _toggleOpen() {
    this.open = !this.open;

    // First time opening? start a flow
    if (this.open && !this._authUrl) {
      this._generateFlow();
    }

    // Reset success label when closing
    if (!this.open) {
      this._pubkyZ32 = "";
      this._authUrl = "";
    }
  }

  async _copyToClipboard() {
    try {
      const url = this._authUrl || "";
      await navigator.clipboard.writeText(url);
      this.showCopied = true;
      setTimeout(() => (this.showCopied = false), 1000);
    } catch (e) {
      console.error("Failed to copy:", e);
    }
  }

  // ---- Template -------------------------------------------------------------

  render() {
    const showSuccess = Boolean(this._pubkyZ32);
    const headerLabel = this.open ? "Pubky Auth Signup" : "Click!";

    const instruction =
      this.caps && this.caps.trim().length
        ? "Scan or copy Pubky auth URL"
        : "Scan to authenticate (no capabilities requested)";

    return html`
      <div id="widget" class=${this.open ? "open" : ""}>
        <button
          class="header"
          @click=${this._toggleOpen}
          aria-label="Open Pubky Auth"
        >
          <div class="header-content">
            <svg
              id="pubky-icon"
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 452 690"
              aria-hidden="true"
            >
              <path
                fill-rule="evenodd"
                d="m0.1 84.7l80.5 17.1 15.8-74.5 73.8 44.2 54.7-71.5 55.2 71.5 70.3-44.2 19.4 74.5 81.6-17.1-74.5 121.5c-40.5-35.3-93.5-56.6-151.4-56.6-57.8 0-110.7 21.3-151.2 56.4zm398.4 293.8c0 40.6-14 78-37.4 107.4l67 203.8h-403.1l66.2-202.3c-24.1-29.7-38.6-67.6-38.6-108.9 0-95.5 77.4-172.8 173-172.8 95.5 0 172.9 77.3 172.9 172.8zm-212.9 82.4l-48.2 147.3h178.1l-48.6-148 2.9-1.6c28.2-15.6 47.3-45.6 47.3-80.1 0-50.5-41-91.4-91.5-91.4-50.6 0-91.6 40.9-91.6 91.4 0 35 19.7 65.4 48.6 80.8z"
              />
            </svg>
            <span class="text">${headerLabel}</span>
          </div>
        </button>

        <div class="line"></div>

        <div id="widget-content">
          ${showSuccess
            ? this.caps?.length
              ? html`
                  <p>Successfully authorized:</p>
                  <p class="pk">${this._pubkyZ32}</p>
                  <p>With capabilities</p>
                  ${this.caps.split(",").map((cap) => html`<p>${cap}</p>`)}
                `
              : html`
                  <p>Successfully authenticated:</p>
                  <p class="pk">${this._pubkyZ32}</p>
                `
            : html`
                <p>${instruction}</p>
                <div class="card">
                  <canvas id="qr" ${ref((c) => this._setQr(c))}></canvas>
                </div>
                <button
                  class="card url"
                  @click=${this._copyToClipboard}
                  title="Copy URL"
                >
                  <div class="copied ${this.showCopied ? "show" : ""}">
                    Copied to Clipboard
                  </div>
                  <p>${this._authUrl || ""}</p>
                  <svg
                    width="14"
                    height="16"
                    viewBox="0 0 14 16"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <rect width="10" height="12" rx="2" fill="white"></rect>
                    <rect
                      x="3"
                      y="3"
                      width="10"
                      height="12"
                      rx="2"
                      fill="white"
                      stroke="#3B3B3B"
                    ></rect>
                  </svg>
                </button>
              `}
        </div>
      </div>
    `;
  }

  static get styles() {
    return css`
      * {
        box-sizing: border-box;
      }
      :host {
        --full-width: 22rem;
        --full-height: 31rem;
        --header-height: 3.5rem;
        --closed-width: 14rem; /* big clickable pill */
      }

      button {
        padding: 0;
        background: none;
        border: 0;
        color: inherit;
        cursor: pointer;
      }
      p {
        margin: 0;
      }

      #widget {
        color: white;
        position: fixed;
        top: 2rem;
        left: 50%;
        transform: translateX(-50%);
        z-index: 99999;
        overflow: hidden;
        background: rgba(43, 43, 43, 0.74);
        border: 1px solid #3c3c3c;
        box-shadow: 0 10px 34px -10px rgba(236, 243, 222, 0.05);
        border-radius: 999px; /* pill when closed */
        -webkit-backdrop-filter: blur(8px);
        backdrop-filter: blur(8px);
        width: var(--closed-width);
        height: var(--header-height);
        transition:
          height 120ms ease,
          width 120ms ease,
          border-radius 120ms ease;
      }

      #widget.open {
        width: var(--full-width);
        height: var(--full-height);
        border-radius: 12px; /* card when open */
      }

      .header {
        width: 100%;
        height: var(--header-height);
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 0 0.9rem;
      }

      .header-content {
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }

      #pubky-icon {
        height: 1.6rem;
        width: auto;
        fill: currentColor;
      }

      .text {
        font-weight: 800;
        font-size: 1.1rem;
        letter-spacing: 0.2px;
      }

      .line {
        height: 1px;
        background-color: #3b3b3b;
        margin-bottom: 1rem;
        opacity: 0.6;
      }

      #widget-content {
        width: var(--full-width);
        padding: 0 1rem;
      }

      #widget p {
        font-size: 0.87rem;
        line-height: 1rem;
        text-align: center;
        color: #fff;
        opacity: 0.7;
        text-wrap: nowrap;
      }

      .pk {
        font-family:
          ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono",
          monospace;
        opacity: 0.9;
      }

      #qr {
        width: 18em !important;
        height: 18em !important;
      }

      .card {
        position: relative;
        background: #3b3b3b;
        border-radius: 8px;
        padding: 1rem;
        margin-top: 1rem;
        display: flex;
        justify-content: center;
        align-items: center;
      }

      .card.url {
        padding: 0.625rem;
        justify-content: space-between;
        max-width: 100%;
      }

      .card.url p {
        display: flex;
        align-items: center;
        line-height: 1 !important;
        width: 93%;
        overflow: hidden;
        text-overflow: ellipsis;
        text-wrap: nowrap;
      }

      .copied {
        transition: opacity 80ms ease-in;
        opacity: 0;
        position: absolute;
        right: 0;
        top: -1.6rem;
        font-size: 0.9em;
        background: rgb(43 43 43 / 98%);
        padding: 0.5rem;
        border-radius: 0.3rem;
        color: #ddd;
      }
      .copied.show {
        opacity: 1;
      }
    `;
  }
}

window.customElements.define("pubky-auth-widget", PubkyAuthWidget);
