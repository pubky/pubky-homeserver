import { LitElement, css, html } from "lit";
import { ref } from "lit/directives/ref.js";
import QRCode from "qrcode";

import * as pubky from "@synonymdev/pubky";

const CLIENT_ID = "grant-auth.example";
const DEFAULT_CAPABILITIES = "/pub/pubky.app/:rw,/pub/example.com/nested:rw";
const TESTNET_RELAY = "http://localhost:15412/inbox";

export class PubkyAuthWidget extends LitElement {
  static get properties() {
    return {
      caps: { type: String },
      showCopied: { type: Boolean },
      testnet: { type: Boolean },
      _authUrl: { type: String, state: true },
      _error: { type: String, state: true },
      _grantCapabilities: { type: Array, state: true },
      _grantClientId: { type: String, state: true },
      _grantExpiresAt: { type: String, state: true },
      _grantId: { type: String, state: true },
      _phase: { type: String, state: true },
      _pubkyZ32: { type: String, state: true },
      _tokenExpiresAt: { type: String, state: true },
    };
  }

  constructor() {
    super();
    if (typeof pubky.setLogLevel === "function") pubky.setLogLevel("debug");

    this.caps = DEFAULT_CAPABILITIES;
    this.showCopied = false;
    this.testnet = true;
    this._authUrl = "";
    this._error = "";
    this._grantCapabilities = [];
    this._grantClientId = "";
    this._grantExpiresAt = "";
    this._grantId = "";
    this._phase = "idle";
    this._pubkyZ32 = "";
    this._tokenExpiresAt = "";

    this._canvas = null;
    this._flowRunId = 0;
    this._sdk = pubky.Pubky.testnet();
  }

  _setTestnet(enabled) {
    this.testnet = enabled;
    this._sdk = this.testnet ? pubky.Pubky.testnet() : new pubky.Pubky();
    this._resetFlow();
  }

  _toggleTestnet(event) {
    this._setTestnet(event.target.checked);
  }

  _toggleCapabilities(event) {
    this.caps = event.target.checked ? DEFAULT_CAPABILITIES : "";
    this._resetFlow();
  }

  _resetFlow() {
    this._flowRunId += 1;
    this._authUrl = "";
    this._error = "";
    this._grantCapabilities = [];
    this._grantClientId = "";
    this._grantExpiresAt = "";
    this._grantId = "";
    this._phase = "idle";
    this._pubkyZ32 = "";
    this._tokenExpiresAt = "";
    this.updateComplete.then(() => this._updateQr());
  }

  async _startFlow() {
    const runId = ++this._flowRunId;
    this._authUrl = "";
    this._error = "";
    this._grantCapabilities = [];
    this._grantClientId = "";
    this._grantExpiresAt = "";
    this._grantId = "";
    this._phase = "connecting";
    this._pubkyZ32 = "";
    this._tokenExpiresAt = "";

    try {
      const options = { clientId: CLIENT_ID };
      if (this.testnet) options.relay = TESTNET_RELAY;

      const flow = await this._sdk.startGrantAuthFlow(
        this.caps,
        pubky.AuthFlowKind.signin(),
        options,
      );
      if (runId !== this._flowRunId) return;

      this._authUrl = flow.authorizationUrl;
      await this.updateComplete;
      this._updateQr();

      const session = await flow.awaitApproval();
      if (runId !== this._flowRunId) return;

      const grantInfo = await session.grant.sessionInfo();
      if (runId !== this._flowRunId) return;

      this._pubkyZ32 = session.info.publicKey.z32();
      this._grantClientId = grantInfo.clientId;
      this._grantId = grantInfo.grantId;
      this._grantCapabilities = grantInfo.capabilities;
      this._tokenExpiresAt = this._formatTime(grantInfo.tokenExpiresAt);
      this._grantExpiresAt = this._formatTime(grantInfo.grantExpiresAt);
      this._logGrantMetadata(grantInfo);
      this._phase = "approved";
    } catch (e) {
      if (runId !== this._flowRunId) return;
      console.error("Grant auth flow failed:", e);
      this._error = e?.message || String(e);
      this._phase = "error";
    }
  }

  _setQr(canvas) {
    this._canvas = canvas || null;
    this._updateQr();
  }

  _updateQr() {
    if (!this._canvas || !this._authUrl) return;

    QRCode.toCanvas(this._canvas, this._authUrl, {
      margin: 1,
      scale: 8,
      color: { light: "#fff", dark: "#0d0e0f" },
    }).catch((e) => console.error("QR render error:", e));
  }

  async _copyToClipboard() {
    try {
      await navigator.clipboard.writeText(this._authUrl || "");
      this.showCopied = true;
      setTimeout(() => (this.showCopied = false), 1000);
    } catch (e) {
      console.error("Failed to copy:", e);
    }
  }

  _requestedCaps() {
    return this.caps
      .split(",")
      .map((cap) => cap.trim())
      .filter(Boolean);
  }

  _formatTime(value) {
    if (value === null || value === undefined || value === "") return "";
    const date = new Date(typeof value === "number" ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  _logGrantMetadata(grantInfo) {
    console.log("Pubky grant metadata:", {
      publicKey: grantInfo.publicKey.z32(),
      homeserver: grantInfo.homeserver.z32(),
      clientId: grantInfo.clientId,
      grantId: grantInfo.grantId,
      capabilities: grantInfo.capabilities,
      createdAt: grantInfo.createdAt,
      tokenExpiresAt: grantInfo.tokenExpiresAt,
      grantExpiresAt: grantInfo.grantExpiresAt,
    });
  }

  _stepClass(step) {
    if (step === 1) return "step-index active";
    if (step === 2 && this._phase !== "idle") return "step-index active";
    if (step === 3 && this._phase === "approved") return "step-index active";
    return "step-index";
  }

  render() {
    const requestedCaps = this._requestedCaps();
    const approved = this._phase === "approved";
    const waiting = this._phase === "connecting";
    const idle = this._phase === "idle";
    const errored = this._phase === "error";

    return html`
      <section class="auth-shell">
        <div class="content">
          <p class="eyebrow">Pubky Grant Auth - JavaScript example</p>
          <h1>Grant Auth, step by step</h1>
          <p class="intro">
            A browser demo for using Pubky Grant Auth in an unhosted app. Create
            a request, approve it with the JS authenticator CLI, then receive a
            grant-backed session.
          </p>

          ${this._renderConfigureStep(requestedCaps)}
          ${this._renderApproveStep({ idle, waiting, approved, errored })}
          ${this._renderSessionStep(approved)}
        </div>
      </section>
    `;
  }

  _renderConfigureStep(requestedCaps) {
    return html`
      <div class="step">
        <div class="rail">
          <div class=${this._stepClass(1)}>1</div>
          <div class="line"></div>
        </div>
        <div class="step-body">
          <h2>Configure the request</h2>
          <div class="panel controls">
            <label>
              <input
                type="checkbox"
                .checked=${this.testnet}
                @change=${this._toggleTestnet}
              />
              <span title="Use the local Pubky test network instead of the public one.">
                Testnet
              </span>
            </label>
            <label>
              <input
                type="checkbox"
                .checked=${requestedCaps.length > 0}
                @change=${this._toggleCapabilities}
              />
              <span title="Scoped read/write paths on the user's Homeserver.">
                Request capabilities
              </span>
            </label>
            <div class="code-card">
              <div>client_id = ${CLIENT_ID}</div>
              <div>network = ${this.testnet ? "testnet" : "default"}</div>
              <div>relay = ${this.testnet ? TESTNET_RELAY : "default"}</div>
              <div>caps = ${requestedCaps.length ? requestedCaps.join(", ") : "none"}</div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  _renderApproveStep({ idle, waiting, approved, errored }) {
    return html`
      <div class="step">
        <div class="rail">
          <div class=${this._stepClass(2)}>2</div>
          <div class="line"></div>
        </div>
        <div class="step-body">
          <h2>Copy and approve</h2>
          <div class="panel approve-panel">
            ${idle
              ? html`
                  <p class="muted">Generate the link to see the QR code here.</p>
                  <button class="primary" @click=${this._startFlow}>
                    Generate auth link
                  </button>
                `
              : ""}
            ${waiting
              ? html`
                  <div class="qr-card">
                    <canvas ${ref((canvas) => this._setQr(canvas))}></canvas>
                  </div>
                  <button class="url-card" @click=${this._copyToClipboard}>
                    <span>${this._authUrl}</span>
                    <strong>${this.showCopied ? "Copied" : "Copy"}</strong>
                  </button>
                  <div class="code-card full-width">
                    node 2-authenticator.mjs "&lt;AUTH_URL&gt;" ${this.testnet ? "--testnet" : ""}
                  </div>
                  <div class="waiting-row">
                    <span class="spinner"></span>
                    <span>Waiting for authenticator approval...</span>
                  </div>
                `
              : ""}
            ${approved ? html`<p class="success">Approved by user</p>` : ""}
            ${errored
              ? html`
                  <p class="error">${this._error}</p>
                  <button class="primary" @click=${this._startFlow}>Try again</button>
                `
              : ""}
          </div>
        </div>
      </div>
    `;
  }

  _renderSessionStep(approved) {
    return html`
      <div class="step last">
        <div class="rail">
          <div class=${this._stepClass(3)}>3</div>
        </div>
        <div class="step-body">
          <h2>Receive the session</h2>
          <div class="panel session-panel">
            ${approved
              ? html`
                  <div class="detail-label">Public key</div>
                  <div class="mono break">${this._pubkyZ32}</div>
                  <div class="detail-grid">
                    <div>
                      <span>Client ID</span>
                      <strong>${this._grantClientId}</strong>
                    </div>
                    <div>
                      <span>Grant ID</span>
                      <strong>${this._grantId}</strong>
                    </div>
                    <div>
                      <span>Token expires</span>
                      <strong>${this._tokenExpiresAt}</strong>
                    </div>
                    <div>
                      <span>Grant expires</span>
                      <strong>${this._grantExpiresAt}</strong>
                    </div>
                  </div>
                  ${this._grantCapabilities.length
                    ? html`
                        <div class="detail-label">Capabilities</div>
                        ${this._grantCapabilities.map(
                          (cap) => html`<div class="cap mono">${cap}</div>`,
                        )}
                      `
                    : html`<div class="cap mono">No capabilities requested</div>`}
                  <button class="text-button" @click=${this._resetFlow}>Start over</button>
                `
              : html`<p class="muted">Waiting on step 2...</p>`}
          </div>
        </div>
      </div>
    `;
  }

  static get styles() {
    return css`
      @keyframes pubky-spin {
        to {
          transform: rotate(360deg);
        }
      }

      * {
        box-sizing: border-box;
      }

      :host {
        display: block;
        width: min(40rem, calc(100vw - 2rem));
        color: #f2f3f3;
      }

      button {
        font: inherit;
      }

      .auth-shell {
        overflow: hidden;
        border: 1px solid #24272a;
        border-radius: 16px;
        background: #111315;
        box-shadow: 0 24px 80px rgb(0 0 0 / 32%);
      }

      .content {
        padding: 3.5rem 2.5rem 2.75rem;
      }

      .eyebrow {
        margin: 0 0 0.5rem;
        color: #2fbf8f;
        font-size: 0.75rem;
        font-weight: 800;
        letter-spacing: 0.12em;
        text-transform: uppercase;
      }

      h1 {
        margin: 0 0 0.625rem;
        color: #f2f3f3;
        font-size: clamp(1.75rem, 5vw, 2rem);
        font-weight: 800;
        letter-spacing: -0.01em;
      }

      .intro {
        margin: 0 0 1.75rem;
        color: #9aa0a4;
        font-size: 0.875rem;
        line-height: 1.6;
      }

      .step {
        display: flex;
        gap: 1rem;
      }

      .step.last .step-body {
        padding-bottom: 0;
      }

      .rail {
        display: flex;
        flex-direction: column;
        align-items: center;
      }

      .step-index {
        display: grid;
        width: 1.875rem;
        height: 1.875rem;
        flex-shrink: 0;
        place-items: center;
        border: 1px solid #33373a;
        border-radius: 50%;
        background: #1a1c1e;
        color: #6f7478;
        font-size: 0.8125rem;
        font-weight: 800;
      }

      .step-index.active {
        border-color: #2fbf8f;
        background: #1a2e27;
        color: #5fe0b3;
      }

      .line {
        width: 2px;
        flex: 1;
        background: #26292b;
      }

      .step-body {
        flex: 1;
        min-width: 0;
        padding-bottom: 1.5rem;
      }

      h2 {
        margin: 0 0 0.625rem;
        color: #f2f3f3;
        font-size: 0.90625rem;
        font-weight: 700;
      }

      .panel {
        border: 1px solid #26292b;
        border-radius: 10px;
        background: #1a1c1e;
        padding: 1rem;
      }

      .controls,
      .session-panel {
        display: flex;
        flex-direction: column;
        gap: 0.625rem;
      }

      label {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        color: #c7cacc;
        font-size: 0.8125rem;
      }

      label span {
        border-bottom: 1px dotted #6f7478;
        cursor: help;
      }

      input {
        accent-color: #2fbf8f;
      }

      .code-card,
      .cap,
      .mono,
      .url-card {
        font-family: ui-monospace, Menlo, Consolas, "Liberation Mono", monospace;
      }

      .code-card {
        border-radius: 6px;
        background: #0d0e0f;
        color: #8b9096;
        font-size: 0.6875rem;
        line-height: 1.6;
        padding: 0.625rem 0.75rem;
      }

      .full-width {
        width: 100%;
        overflow-wrap: anywhere;
      }

      .approve-panel {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.75rem;
      }

      .muted {
        margin: 0;
        color: #6f7478;
        font-size: 0.8125rem;
      }

      .primary {
        all: unset;
        cursor: pointer;
        border-radius: 999px;
        background: #2fbf8f;
        color: #0c1a15;
        font-size: 0.8125rem;
        font-weight: 800;
        padding: 0.625rem 1.375rem;
      }

      .qr-card {
        display: flex;
        border-radius: 10px;
        background: #fff;
        padding: 0.5625rem;
      }

      .qr-card canvas {
        width: min(16rem, calc(100vw - 8rem)) !important;
        height: min(16rem, calc(100vw - 8rem)) !important;
      }

      .url-card {
        display: flex;
        width: 100%;
        min-width: 0;
        align-items: center;
        justify-content: space-between;
        gap: 0.75rem;
        border: 0;
        border-radius: 8px;
        background: #0d0e0f;
        color: #9aa0a4;
        cursor: pointer;
        font-size: 0.65625rem;
        padding: 0.5625rem 0.6875rem;
      }

      .url-card span {
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .url-card strong {
        color: #5fe0b3;
        font-family: inherit;
        font-size: 0.6875rem;
      }

      .waiting-row {
        display: flex;
        align-items: center;
        gap: 0.625rem;
        color: #c7cacc;
        font-size: 0.8125rem;
        padding: 0.25rem 0;
      }

      .spinner {
        width: 1rem;
        height: 1rem;
        border: 2px solid #3a3d3f;
        border-top-color: #2fbf8f;
        border-radius: 50%;
        animation: pubky-spin 0.8s linear infinite;
      }

      .success {
        margin: 0;
        color: #5fe0b3;
        font-size: 0.8125rem;
      }

      .error {
        margin: 0;
        color: #ffb4b4;
        font-size: 0.8125rem;
        line-height: 1.5;
        text-align: center;
      }

      .detail-label {
        color: #6f7478;
        font-size: 0.75rem;
        font-weight: 700;
      }

      .break {
        word-break: break-all;
      }

      .mono {
        color: #c7cacc;
        font-size: 0.6875rem;
        line-height: 1.5;
      }

      .detail-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 0.5rem;
      }

      .detail-grid div,
      .cap {
        border-radius: 6px;
        background: #0d0e0f;
        padding: 0.5rem 0.625rem;
      }

      .detail-grid span {
        display: block;
        color: #6f7478;
        font-size: 0.6875rem;
      }

      .detail-grid strong {
        display: block;
        overflow: hidden;
        color: #c7cacc;
        font-size: 0.75rem;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .text-button {
        all: unset;
        align-self: flex-start;
        color: #8b9096;
        cursor: pointer;
        font-size: 0.75rem;
        text-decoration: underline;
      }

      @media (max-width: 560px) {
        :host {
          width: min(100%, calc(100vw - 1rem));
        }

        .content {
          padding: 2rem 1rem;
        }

        .step {
          gap: 0.75rem;
        }

        .detail-grid {
          grid-template-columns: 1fr;
        }

        .qr-card canvas {
          width: min(14rem, calc(100vw - 6rem)) !important;
          height: min(14rem, calc(100vw - 6rem)) !important;
        }
      }
    `;
  }
}

window.customElements.define("pubky-auth-widget", PubkyAuthWidget);
