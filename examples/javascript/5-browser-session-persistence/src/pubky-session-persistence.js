import { LitElement, css, html } from "lit";

import * as pubky from "@synonymdev/pubky";
import { TESTNET_HOMESERVER } from "../../_testnet.mjs";

const CLIENT_ID = "multi-account.example";
const DEMO_PATH = "/pub/multi-account.example/profile.json";
const ACTIVE_SESSION_KEY = "pubky-browser-session-persistence-active-id";
const ACCOUNT_LABELS_KEY = "pubky-browser-session-persistence-account-labels";
const NEXT_ACCOUNT_NUMBER_KEY = "pubky-browser-session-persistence-next-account-number";
const AVATAR_COLORS = [
  "b6e3f4",
  "c0aede",
  "d1d4f9",
  "ffd5dc",
  "ffdfbf",
  "d5f5e3",
  "f9f7d9",
  "c7f9cc",
  "fbc4ab",
  "a3c4f3",
];

export class PubkySessionPersistence extends LitElement {
  static get properties() {
    return {
      _activeCaps: { type: Array, state: true },
      _activeId: { type: String, state: true },
      _activePubky: { type: String, state: true },
      _demoResult: { type: String, state: true },
      _error: { type: String, state: true },
      _phase: { type: String, state: true },
      _sessions: { type: Array, state: true },
      _status: { type: String, state: true },
      _storeAvailable: { type: Boolean, state: true },
    };
  }

  constructor() {
    super();
    if (typeof pubky.setLogLevel === "function") pubky.setLogLevel("debug");

    this._sdk = pubky.Pubky.testnet();
    this._store = this._sdk.browserSessionStore;
    this._activeSession = null;

    this._activeCaps = [];
    this._activeId = "";
    this._activePubky = "";
    this._demoResult = "";
    this._error = "";
    this._phase = "loading";
    this._sessions = [];
    this._status = "Loading browser session store...";
    this._storeAvailable = false;
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadSessions();
  }

  async _loadSessions() {
    try {
      this._storeAvailable = await this._store.isAvailable();
      this._sessions = await this._store.list();

      if (this._sessions.length === 0) {
        this._phase = "creating";
        this._status = "Creating two disposable testnet accounts...";
        await this._createRandomAccount();
        await this._createRandomAccount();
        await this._refreshSessions();
      }

      this._phase = "idle";
      this._status = "Browser session store is ready.";
      await this._restoreInitialActiveSession();
    } catch (error) {
      this._showError("Preparing demo accounts failed", error);
    }
  }

  async _restoreInitialActiveSession() {
    const previousId = localStorage.getItem(ACTIVE_SESSION_KEY);
    const fallbackId = this._sessions[0]?.id;
    const activeId = this._sessions.some((session) => session.id === previousId)
      ? previousId
      : fallbackId;

    if (activeId) await this._restoreSession(activeId);
  }

  async _addAccount() {
    try {
      this._error = "";
      this._phase = "creating";
      this._status = "Creating a disposable testnet account...";
      const { session, stored } = await this._createRandomAccount();
      this._activeSession = session;
      this._activateStoredSession(stored, session.info);
      await this._refreshSessions();
      this._phase = "idle";
      this._status = `${this._accountLabel(stored)} created and saved in IndexedDB.`;
    } catch (error) {
      this._showError("Creating random account failed", error);
    }
  }

  async _createRandomAccount() {
    const keypair = pubky.Keypair.random();
    const signer = this._sdk.signer(keypair);
    const homeserver = pubky.PublicKey.from(TESTNET_HOMESERVER);

    await signer.signup(homeserver);
    const session = await signer.signin(CLIENT_ID);
    const stored = await this._store.save(session);
    const label = this._accountLabel(stored);

    await session.storage.putJson(DEMO_PATH, {
      label,
      account: session.info.publicKey.z32(),
      createdAt: new Date().toISOString(),
      note: "demo account generated in the browser",
    });

    return { session, stored };
  }

  async _refreshSessions() {
    this._sessions = await this._store.list();
  }

  async _restoreSession(id) {
    try {
      this._error = "";
      const session = await this._store.restore(id);
      const stored = this._sessions.find((item) => item.id === id);
      this._activeSession = session;
      this._activateStoredSession(stored, session.info);
      this._phase = "idle";
      this._status = `${this._accountLabel(stored)} restored from IndexedDB.`;
    } catch (error) {
      localStorage.removeItem(ACTIVE_SESSION_KEY);
      this._showError("Restoring session failed", error);
    }
  }

  _activateStoredSession(stored, info) {
    this._activeId = stored?.id || "";
    this._activePubky = info.publicKey.z32();
    this._activeCaps = info.capabilities || [];
    this._demoResult = "";
    if (stored?.id) localStorage.setItem(ACTIVE_SESSION_KEY, stored.id);
  }

  async _forgetSession(id) {
    try {
      await this._store.remove(id);
      this._removeAccountLabel(id);
      if (this._activeId === id) this._clearActiveSession();
      await this._refreshSessions();
      this._status = "Stored session forgotten locally.";
    } catch (error) {
      this._showError("Removing stored session failed", error);
    }
  }

  async _clearStoredSessions() {
    try {
      await this._store.clear();
      this._clearAccountLabels();
      this._clearActiveSession();
      await this._refreshSessions();
      this._status = "All stored browser sessions were cleared locally.";
    } catch (error) {
      this._showError("Clearing stored sessions failed", error);
    }
  }

  _clearActiveSession() {
    this._activeSession = null;
    this._activeId = "";
    this._activePubky = "";
    this._activeCaps = [];
    this._demoResult = "";
    localStorage.removeItem(ACTIVE_SESSION_KEY);
  }

  async _writeDemoFile() {
    if (!this._activeSession) return;

    try {
      const value = {
        account: this._activePubky,
        note: "restored browser session works",
        updatedAt: new Date().toISOString(),
      };
      await this._activeSession.storage.putJson(DEMO_PATH, value);
      this._demoResult = JSON.stringify(value, null, 2);
      this._status = `Wrote profile.json as ${this._activeAccountLabel()}.`;
    } catch (error) {
      this._showError("Writing demo file failed", error);
    }
  }

  async _readDemoFile() {
    if (!this._activeSession) return;

    try {
      const value = await this._activeSession.storage.getJson(DEMO_PATH);
      this._demoResult = JSON.stringify(value, null, 2);
      this._status = `Read profile.json as ${this._activeAccountLabel()}.`;
    } catch (error) {
      this._showError("Reading demo file failed", error);
    }
  }

  _showError(context, error) {
    console.error(context, error);
    this._error = `${context}: ${error?.message || String(error)}`;
    this._phase = "error";
  }

  _accountLabel(session) {
    if (!session?.id) return "Account";

    const labels = this._loadAccountLabels();
    if (!labels[session.id]) {
      labels[session.id] = `Account ${this._nextAccountNumber()}`;
      this._saveAccountLabels(labels);
    }

    return labels[session.id];
  }

  _loadAccountLabels() {
    try {
      return JSON.parse(localStorage.getItem(ACCOUNT_LABELS_KEY) || "{}");
    } catch (_error) {
      return {};
    }
  }

  _saveAccountLabels(labels) {
    localStorage.setItem(ACCOUNT_LABELS_KEY, JSON.stringify(labels));
  }

  _nextAccountNumber() {
    const next = Number(localStorage.getItem(NEXT_ACCOUNT_NUMBER_KEY) || "1");
    localStorage.setItem(NEXT_ACCOUNT_NUMBER_KEY, String(next + 1));
    return next;
  }

  _removeAccountLabel(id) {
    const labels = this._loadAccountLabels();
    delete labels[id];
    this._saveAccountLabels(labels);
  }

  _clearAccountLabels() {
    localStorage.removeItem(ACCOUNT_LABELS_KEY);
    localStorage.removeItem(NEXT_ACCOUNT_NUMBER_KEY);
  }

  _activeAccountLabel() {
    const session = this._sessions.find((item) => item.id === this._activeId);
    return session ? this._accountLabel(session) : "Active account";
  }

  _shortKey(value) {
    if (!value) return "unknown";
    if (value.length <= 22) return value;
    return `${value.slice(0, 12)}...${value.slice(-8)}`;
  }

  _avatarUrl(publicKey) {
    const seed = encodeURIComponent(publicKey || "pubky-demo-account");
    const color = this._avatarColor(publicKey);
    return `https://api.dicebear.com/10.x/big-smile/svg?seed=${seed}&backgroundColor=${color}`;
  }

  _avatarColor(publicKey) {
    const value = publicKey || "pubky-demo-account";
    const hash = [...value].reduce((sum, char) => sum + char.charCodeAt(0), 0);
    return AVATAR_COLORS[hash % AVATAR_COLORS.length];
  }

  _formatDate(seconds) {
    if (!seconds) return "unknown";
    return new Date(seconds * 1000).toLocaleString();
  }

  render() {
    return html`
      <section class="dashboard-shell">
        <div class="content">
          <header class="hero">
            <div>
              <p class="eyebrow">Pubky Browser Persistence · JS example</p>
              <h1>Switch between saved testnet accounts</h1>
              <p class="intro">
                Disposable accounts are generated in the browser. Their grant-backed
                sessions are saved in IndexedDB and restored without a QR code,
                authenticator, or recovery file.
              </p>
            </div>
            <div class="store-pill">
              <span class=${this._storeAvailable ? "dot online" : "dot"}></span>
              IndexedDB ${this._storeAvailable ? "ready" : "unavailable"}
            </div>
          </header>

          ${this._renderActiveBanner()}

          <div class="dashboard-grid">
            ${this._renderSavedAccountsPanel()}
            ${this._renderWorkspacePanel()}
          </div>
        </div>
      </section>
    `;
  }

  _renderActiveBanner() {
    if (!this._activeSession) {
      return html`
        <section class="active-banner empty">
          <div>
            <span class="banner-kicker">No active account</span>
            <h2>Restore or create an account to start.</h2>
          </div>
          <button class="primary" ?disabled=${this._phase === "creating"} @click=${this._addAccount}>
            ${this._phase === "creating" ? "Creating..." : "Create account"}
          </button>
        </section>
      `;
    }

    return html`
      <section class="active-banner restored">
        <img
          class="active-avatar"
          src=${this._avatarUrl(this._activePubky)}
          alt="${this._activeAccountLabel()} avatar"
        />
        <div class="active-copy">
          <div class="badge-row">
            <span class="badge success">Active</span>
            <span class="badge">Restored from IndexedDB</span>
          </div>
          <h2>${this._activeAccountLabel()}</h2>
          <p class="active-key">${this._shortKey(this._activePubky)}</p>
        </div>
        <div class="active-actions">
          <button class="secondary" @click=${this._writeDemoFile}>Write profile</button>
          <button class="secondary" @click=${this._readDemoFile}>Read profile</button>
          <button class="ghost" @click=${this._clearActiveSession}>Deactivate</button>
        </div>
      </section>
    `;
  }

  _renderSavedAccountsPanel() {
    return html`
      <section class="panel accounts-panel">
        <div class="panel-heading">
          <div>
            <h2>Saved accounts</h2>
            <p>${this._sessions.length} browser session${this._sessions.length === 1 ? "" : "s"}</p>
          </div>
          <button class="ghost danger" @click=${this._clearStoredSessions}>Clear all</button>
        </div>

        ${this._phase === "creating" && this._sessions.length === 0
          ? html`<div class="loading-card"><span class="spinner"></span><span>Creating two demo accounts...</span></div>`
          : ""}

        <div class="account-list">
          ${this._sessions.length
            ? this._sessions.map((session) => this._renderStoredSession(session))
            : html`<p class="muted">No saved accounts yet.</p>`}
        </div>

        <button class="create-account" ?disabled=${this._phase === "creating"} @click=${this._addAccount}>
          <span>${this._phase === "creating" ? "Creating account..." : "+ Create disposable testnet account"}</span>
        </button>
      </section>
    `;
  }

  _renderStoredSession(session) {
    const active = session.id === this._activeId;

    return html`
      <article class=${active ? "account-card active" : "account-card"}>
        <div class="account-main">
          <img
            class="account-avatar"
            src=${this._avatarUrl(session.publicKey)}
            alt="${this._accountLabel(session)} avatar"
          />
          <div>
            <div class="account-name-row">
              <h3>${this._accountLabel(session)}</h3>
              ${active ? html`<span class="badge success">Active</span>` : ""}
            </div>
            <p>${this._shortKey(session.publicKey)}</p>
          </div>
          <span class="mode-pill">${session.storageMode}</span>
        </div>
        <div class="account-meta">
          <span>Client: ${session.clientId}</span>
          <span>Grant: ${this._shortKey(session.grantId)}</span>
          <span>Expires: ${this._formatDate(session.grantExpiresAt)}</span>
        </div>
        <details>
          <summary>Full identifiers</summary>
          <div class="detail-label">Public key</div>
          <div class="mono break">${session.publicKey}</div>
          <div class="detail-label">Grant ID</div>
          <div class="mono break">${session.grantId}</div>
        </details>
        <div class="card-actions">
          <button class=${active ? "secondary restored" : "secondary"} @click=${() => this._restoreSession(session.id)}>
            ${active ? "Currently restored" : "Restore this account"}
          </button>
          <button class="ghost danger" @click=${() => this._forgetSession(session.id)}>
            Forget locally
          </button>
        </div>
      </article>
    `;
  }

  _renderWorkspacePanel() {
    return html`
      <section class="workspace">
        <div class="panel status-panel">
          <div class="panel-heading">
            <div>
              <h2>Status</h2>
              <p>Testnet-only browser demo</p>
            </div>
          </div>
          <p class=${this._error ? "status error" : "status"}>${this._error || this._status}</p>
          <div class="technical-card">
            <div><span>Network</span><strong>local testnet</strong></div>
            <div><span>Client ID</span><strong>${CLIENT_ID}</strong></div>
            <div><span>Demo path</span><strong>${DEMO_PATH}</strong></div>
          </div>
        </div>

        <div class="panel active-panel">
          <div class="panel-heading">
            <div>
              <h2>Active session</h2>
              <p>${this._activeSession ? "Ready for authenticated storage" : "No session restored"}</p>
            </div>
          </div>

          ${this._activeSession
            ? html`
                <div class="cap-list">
                  ${this._activeCaps.map((cap) => html`<span>${cap}</span>`)}
                </div>
                <div class="workspace-actions">
                  <button class="secondary" @click=${this._writeDemoFile}>Write profile</button>
                  <button class="secondary" @click=${this._readDemoFile}>Read profile</button>
                  <button class="ghost" @click=${this._clearActiveSession}>Deactivate</button>
                </div>
                ${this._demoResult
                  ? html`<pre class="result">${this._demoResult}</pre>`
                  : html`<p class="muted">Use the buttons above to write or read profile.json as ${this._activeAccountLabel()}.</p>`}
              `
            : html`<p class="muted">Restore one of the saved accounts to activate storage actions.</p>`}
        </div>
      </section>
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
        width: min(58rem, calc(100vw - 2rem));
        color: #f2f3f3;
      }

      button {
        font: inherit;
      }

      button:disabled {
        cursor: wait;
        opacity: 0.72;
      }

      .dashboard-shell {
        overflow: hidden;
        border: 1px solid #24272a;
        border-radius: 22px;
        background:
          radial-gradient(circle at top right, rgba(47, 191, 143, 0.12), transparent 28rem),
          #111315;
        box-shadow: 0 24px 80px rgb(0 0 0 / 32%);
      }

      .content {
        padding: 3.5rem 2.5rem 2.75rem;
      }

      .hero,
      .active-banner,
      .dashboard-grid,
      .panel-heading,
      .account-main,
      .account-name-row,
      .card-actions,
      .workspace-actions,
      .active-actions,
      .badge-row {
        display: flex;
      }

      .hero {
        align-items: flex-start;
        justify-content: space-between;
        gap: 1.5rem;
        margin-bottom: 1.25rem;
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
        font-size: clamp(1.75rem, 5vw, 2.2rem);
        font-weight: 800;
        letter-spacing: -0.01em;
      }

      .intro {
        max-width: 42rem;
        margin: 0 0 1.75rem;
        color: #9aa0a4;
        font-size: 0.875rem;
        line-height: 1.6;
      }

      .store-pill,
      .badge,
      .mode-pill {
        border: 1px solid #303437;
        border-radius: 999px;
        background: #0d0e0f;
        color: #c7cacc;
        font-size: 0.6875rem;
        font-weight: 800;
      }

      .store-pill {
        display: inline-flex;
        flex-shrink: 0;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 0.75rem;
      }

      .dot {
        width: 0.5rem;
        height: 0.5rem;
        border-radius: 50%;
        background: #6f7478;
      }

      .dot.online {
        background: #5fe0b3;
        box-shadow: 0 0 16px rgba(95, 224, 179, 0.6);
      }

      h2 {
        margin: 0;
        color: #f2f3f3;
        font-size: 0.90625rem;
        font-weight: 700;
      }

      .panel {
        border: 1px solid #26292b;
        border-radius: 16px;
        background: #1a1c1e;
        padding: 1.125rem;
      }

      .dashboard-grid {
        display: grid;
        grid-template-columns: minmax(0, 1.15fr) minmax(19rem, 0.85fr);
        gap: 1rem;
      }

      .workspace,
      .accounts-panel,
      .account-list,
      .active-panel,
      .status-panel {
        display: flex;
        flex-direction: column;
        gap: 0.875rem;
      }

      .panel-heading {
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }

      .panel-heading p {
        margin: 0.25rem 0 0;
        color: #6f7478;
        font-size: 0.75rem;
      }

      .active-banner {
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        margin-bottom: 1rem;
        border: 1px solid #2a2d30;
        border-radius: 18px;
        background: linear-gradient(135deg, #171a1c, #101214);
        padding: 1.125rem;
      }

      .active-banner.restored {
        border-color: rgba(47, 191, 143, 0.7);
        background:
          linear-gradient(135deg, rgba(47, 191, 143, 0.18), rgba(16, 18, 20, 0.96)),
          #101214;
        box-shadow: 0 18px 60px rgba(47, 191, 143, 0.08);
      }

      .active-banner.empty {
        border-style: dashed;
      }

      .active-copy h2,
      .active-banner h2 {
        margin: 0.5rem 0 0;
        font-size: clamp(1.25rem, 4vw, 1.7rem);
      }

      .active-avatar,
      .account-avatar {
        flex-shrink: 0;
        border-radius: 50%;
        background: #0d0e0f;
        object-fit: cover;
      }

      .active-avatar {
        width: 4.75rem;
        height: 4.75rem;
        border: 2px solid rgba(95, 224, 179, 0.8);
        box-shadow: 0 0 0 6px rgba(47, 191, 143, 0.12);
      }

      .account-avatar {
        width: 3rem;
        height: 3rem;
        border: 1px solid #34383b;
      }

      .account-card.active .account-avatar {
        border-color: rgba(95, 224, 179, 0.85);
        box-shadow: 0 0 0 4px rgba(47, 191, 143, 0.12);
      }

      .banner-kicker,
      .active-key {
        color: #9aa0a4;
        font-size: 0.8125rem;
      }

      .active-key {
        margin: 0.25rem 0 0;
        font-family: ui-monospace, Menlo, Consolas, "Liberation Mono", monospace;
      }

      .badge-row,
      .active-actions,
      .card-actions,
      .workspace-actions {
        align-items: center;
        gap: 0.5rem;
        flex-wrap: wrap;
      }

      .badge,
      .mode-pill {
        padding: 0.25rem 0.5rem;
        text-transform: uppercase;
      }

      .badge.success {
        border-color: rgba(47, 191, 143, 0.65);
        background: rgba(47, 191, 143, 0.14);
        color: #5fe0b3;
      }

      .technical-card,
      .mono,
      .result {
        font-family: ui-monospace, Menlo, Consolas, "Liberation Mono", monospace;
      }

      .technical-card {
        display: grid;
        gap: 0.5rem;
      }

      .technical-card div {
        display: flex;
        min-width: 0;
        justify-content: space-between;
        gap: 0.75rem;
        border-radius: 10px;
        background: #0d0e0f;
        padding: 0.625rem 0.75rem;
      }

      .technical-card span {
        color: #8b9096;
        font-size: 0.6875rem;
      }

      .technical-card strong {
        overflow: hidden;
        color: #c7cacc;
        font-size: 0.6875rem;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .account-card {
        border: 1px solid #303437;
        border-left: 4px solid #303437;
        border-radius: 14px;
        background: #141618;
        padding: 1rem;
        transition:
          border-color 140ms ease,
          background 140ms ease,
          transform 140ms ease;
      }

      .account-card.active {
        border-color: #2fbf8f;
        background: linear-gradient(135deg, rgba(47, 191, 143, 0.13), #141618 68%);
        box-shadow: inset 0 0 0 1px rgba(47, 191, 143, 0.22);
      }

      .account-card:not(.active):hover {
        border-color: #42474b;
        transform: translateY(-1px);
      }

      .account-main,
      .account-name-row {
        align-items: center;
        gap: 0.75rem;
      }

      .account-main {
        justify-content: space-between;
      }

      .account-main > div {
        min-width: 0;
        flex: 1;
      }

      .account-name-row {
        justify-content: flex-start;
      }

      .account-main h3 {
        margin: 0;
        color: #f2f3f3;
        font-size: 1rem;
      }

      .account-main p {
        margin: 0.25rem 0 0;
        color: #9aa0a4;
        font-family: ui-monospace, Menlo, Consolas, "Liberation Mono", monospace;
        font-size: 0.75rem;
      }

      .account-meta {
        display: grid;
        gap: 0.35rem;
        margin: 0.875rem 0;
        color: #7f858a;
        font-size: 0.75rem;
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

      .primary,
      .secondary {
        all: unset;
        cursor: pointer;
        border-radius: 999px;
        font-size: 0.8125rem;
        font-weight: 800;
        padding: 0.625rem 1.125rem;
      }

      .primary {
        align-self: flex-start;
        background: #2fbf8f;
        color: #0c1a15;
      }

      .secondary {
        border: 1px solid #34383b;
        background: #202326;
        color: #f2f3f3;
      }

      .secondary.restored {
        border-color: rgba(47, 191, 143, 0.45);
        color: #5fe0b3;
      }

      .ghost {
        all: unset;
        color: #8b9096;
        cursor: pointer;
        font-size: 0.75rem;
        text-decoration: underline;
      }

      .ghost.danger {
        color: #ffb4b4;
      }

      .create-account {
        all: unset;
        cursor: pointer;
        border: 1px dashed rgba(47, 191, 143, 0.5);
        border-radius: 14px;
        background: rgba(47, 191, 143, 0.06);
        color: #5fe0b3;
        font-size: 0.875rem;
        font-weight: 800;
        padding: 0.875rem 1rem;
        text-align: center;
      }

      details {
        border-top: 1px solid #24272a;
        margin-top: 0.75rem;
        padding-top: 0.75rem;
      }

      summary {
        color: #8b9096;
        cursor: pointer;
        font-size: 0.75rem;
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

      .muted,
      .status,
      .error {
        margin: 0;
        font-size: 0.8125rem;
        line-height: 1.5;
      }

      .muted {
        color: #6f7478;
      }

      .error {
        color: #ffb4b4;
      }

      .status {
        border-radius: 12px;
        background: #0d0e0f;
        color: #c7cacc;
        padding: 0.75rem;
      }

      .result {
        overflow: auto;
        max-height: 14rem;
        margin: 0;
        color: #c7cacc;
        font-size: 0.6875rem;
        line-height: 1.5;
      }

      .cap-list {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
      }

      .cap-list span {
        border: 1px solid #303437;
        border-radius: 999px;
        background: #0d0e0f;
        color: #c7cacc;
        font-family: ui-monospace, Menlo, Consolas, "Liberation Mono", monospace;
        font-size: 0.6875rem;
        padding: 0.375rem 0.5625rem;
      }

      .loading-card {
        display: flex;
        align-items: center;
        gap: 0.625rem;
        border: 1px solid rgba(47, 191, 143, 0.3);
        border-radius: 14px;
        background: rgba(47, 191, 143, 0.08);
        color: #c7cacc;
        font-size: 0.8125rem;
        padding: 0.875rem;
      }

      @media (max-width: 760px) {
        :host {
          width: min(100%, calc(100vw - 1rem));
        }

        .content {
          padding: 2rem 1rem;
        }

        .hero,
        .active-banner,
        .account-main,
        .card-actions,
        .active-actions,
        .workspace-actions {
          align-items: flex-start;
          flex-direction: column;
        }

        .dashboard-grid {
          grid-template-columns: 1fr;
        }
      }
    `;
  }
}

window.customElements.define("pubky-session-persistence", PubkySessionPersistence);
