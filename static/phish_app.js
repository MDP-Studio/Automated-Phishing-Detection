(function () {
  const page = document.body.dataset.page || "analyze";
  const authView = document.getElementById("authView");
  const workspaceView = document.getElementById("workspaceView");
  const authNotice = document.getElementById("authNotice");
  const scanNotice = document.getElementById("scanNotice");
  const historyNotice = document.getElementById("historyNotice");
  const mailboxNotice = document.getElementById("mailboxNotice");
  const billingNotice = document.getElementById("billingNotice");
  const pricingPanel = document.getElementById("pricingPanel");
  const billingCycle = document.getElementById("billingCycle");
  const planGrid = document.getElementById("planGrid");
  const featureGrid = document.getElementById("featureGrid");
  const authTitle = document.getElementById("authTitle");
  const authSubtext = document.getElementById("authSubtext");
  const resultTitle = document.getElementById("resultTitle");
  const resultNote = document.getElementById("resultNote");
  const resultBody = document.getElementById("resultBody");
  const dropZone = document.getElementById("dropZone");
  const dropTitle = document.getElementById("dropTitle");
  const dropHint = document.getElementById("dropHint");
  const emailFile = document.getElementById("emailFile");
  const analyzeButton = document.getElementById("analyzeButton");
  const sampleEmailButton = document.getElementById("sampleEmailButton");
  const clearButton = document.getElementById("clearButton");
  const downloadResultButton = document.getElementById("downloadResultButton");
  const printResultButton = document.getElementById("printResultButton");
  const historyList = document.getElementById("historyList");
  const statsRow = document.getElementById("statsRow");
  const simulationStatsRow = document.getElementById("simulationStatsRow");
  const caseList = document.getElementById("caseList");
  const casesNotice = document.getElementById("casesNotice");
  const refreshCasesButton = document.getElementById("refreshCasesButton");
  const firstRunPanel = document.getElementById("firstRunPanel");
  const mailboxForm = document.getElementById("mailboxForm");
  const mailboxButton = document.getElementById("mailboxButton");
  const mailboxList = document.getElementById("mailboxList");
  const mailboxStatus = document.getElementById("mailboxStatus");
  const mailboxQuota = document.getElementById("mailboxQuota");
  const mailboxProviderSelect = mailboxForm ? mailboxForm.querySelector("[name='provider']") : null;
  const mailboxHostInput = mailboxForm ? mailboxForm.querySelector("[name='host']") : null;
  const mailboxPortInput = mailboxForm ? mailboxForm.querySelector("[name='port']") : null;
  const mailboxPasswordInput = mailboxForm ? mailboxForm.querySelector("[name='app_password']") : null;
  const settingsPortalButton = document.querySelector("[data-settings-portal]");
  const settingsTeamList = document.getElementById("settingsTeamList");
  const settingsTeamSummary = document.getElementById("settingsTeamSummary");
  const passkeyNotice = document.getElementById("passkeyNotice");
  const passkeyRegisterButton = document.getElementById("passkeyRegisterButton");
  const passkeyStepupButton = document.getElementById("passkeyStepupButton");
  const settingsPasskeyList = document.getElementById("settingsPasskeyList");
  const settingsPasskeyStatus = document.getElementById("settingsPasskeyStatus");
  const settingsPasskeyHeading = document.getElementById("settingsPasskeyHeading");
  const forms = {
    login: document.getElementById("loginForm"),
    signup: document.getElementById("signupForm"),
    reset: document.getElementById("resetForm"),
    resetConfirm: document.getElementById("resetConfirmForm"),
  };

  let csrfCookieName = "phishdetect_user_csrf";
  let signupEnabled = false;
  let selectedFile = null;
  let selectedBillingInterval = "monthly";
  let lastPlansPayload = null;
  let featureCatalog = new Map();
  const planOrder = ["free", "starter", "pro", "business"];
  const phishPlanCopy = {
    free: {
      best_for: "Personal testing and light manual checks",
      summary: "Try manual phishing checks without connecting a mailbox or using paid APIs.",
    },
    starter: {
      best_for: "Individuals and small teams",
      summary: "Manual scans with URL reputation, domain context, and stored history.",
    },
    pro: {
      best_for: "Teams that monitor shared inboxes",
      summary: "Mailbox monitoring plus LLM, attachment, and browser-backed analysis.",
    },
    business: {
      best_for: "Security teams and agencies",
      summary: "Higher scan limits, more mailboxes, team controls, and audit history.",
    },
  };
  const phishFeatureCopy = {
    agent_prompt_injection: {
      name: "AI instruction safety",
      description: "Flags hidden or direct instructions that try to control AI tools.",
    },
    payment_rules: {
      name: "Business email compromise signals",
      description: "Urgency, impersonation, and social-engineering wording checks.",
    },
    sender_profiling: {
      description: "Baseline sender patterns and flag unusual sender behavior.",
    },
    llm_intent: {
      name: "LLM social-engineering reasoning",
      description: "LLM-backed phishing, BEC, and intent analysis.",
    },
    rmm_lure: {
      name: "Remote access lure detection",
      description: "Flags fake document/update flows that try to make users install support tools.",
    },
    url_detonation: {
      name: "Browser link check",
      description: "Opens extracted links in a controlled browser check when available on your plan.",
    },
    attachment_sandbox: {
      name: "Attachment safety check",
      description: "Checks suspicious attachments when this capability is configured and included.",
    },
  };
  const mailboxProviderDefaults = {
    gmail: {
      host: "imap.gmail.com",
      port: "993",
      password: "Google app password",
      title: "Gmail usually needs IMAP enabled and a Google app password.",
    },
    outlook: {
      host: "outlook.office365.com",
      port: "993",
      password: "OAuth or admin-approved mailbox password",
      title: "Microsoft accounts often require OAuth or admin approval. Manual upload is the fallback.",
    },
    yahoo: {
      host: "imap.mail.yahoo.com",
      port: "993",
      password: "Yahoo app password",
      title: "Yahoo Mail usually needs an app password from Account Security.",
    },
    icloud: {
      host: "imap.mail.me.com",
      port: "993",
      password: "Apple app-specific password",
      title: "iCloud Mail needs two-factor authentication and an app-specific password.",
    },
    zoho: {
      host: "imap.zoho.com",
      port: "993",
      password: "Zoho app-specific password",
      title: "Zoho Mail needs IMAP enabled. Use an app-specific password when 2FA is enabled.",
    },
    fastmail: {
      host: "imap.fastmail.com",
      port: "993",
      password: "Fastmail app password",
      title: "Fastmail uses app passwords for third-party mail clients.",
    },
    proton: {
      host: "Bridge host shown by Proton",
      port: "1143",
      password: "Proton Bridge password",
      title: "Use the host, port, username, and password shown in Proton Mail Bridge.",
      autofillHost: false,
      autofillPort: false,
    },
    aol: {
      host: "imap.aol.com",
      port: "993",
      password: "AOL app password",
      title: "AOL Mail may need an app password. Use export.imap.aol.com if the main host fails.",
    },
    imap: {
      host: "imap.example.com",
      port: "993",
      password: "Provider app password",
      title: "Use the IMAP host from your email provider or IT admin.",
      autofillHost: false,
    },
  };

  const pageCopy = {
    analyze: {
      title: "Email risk scanner",
      sub: "Upload an .eml file to analyze phishing indicators, malicious URLs, sender signals, and attachments.",
    },
    dashboard: {
      title: "Workspace dashboard",
      sub: "Review private scan history and aggregate risk signals for this signed-in workspace.",
    },
    monitor: {
      title: "Mailbox monitor",
      sub: "Connect user-owned mailboxes for account-scoped monitoring and future automated scanning.",
    },
    settings: {
      title: "Settings",
      sub: "Manage account, plan, mailbox, privacy, and platform-managed API coverage.",
    },
  };

  const firstRunStateKey = "phishanalyze_first_run_state";
  const reportBrandName = "PhishAnalyze";

  const samplePhishEmail = [
    "From: Security Team <security-alert@example-login.net>",
    "Reply-To: helpdesk@example-login.net",
    "To: Alex Example <alex@example.com>",
    "Subject: Urgent password reset required",
    "Date: Tue, 05 May 2026 09:24:00 +1000",
    "Message-ID: <sample-phish-001@example-login.net>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "",
    "Your account will be suspended today unless you verify it immediately.",
    "Open https://example-login.net/verify and enter your email password to keep access.",
    "",
    "If you did not request this, ignore normal support channels and use the link above.",
  ].join("\r\n");

  function cookieValue(name) {
    const parts = document.cookie.split(";").map((item) => item.trim());
    const match = parts.find((item) => item.startsWith(`${name}=`));
    return match ? decodeURIComponent(match.split("=").slice(1).join("=")) : "";
  }

  function notice(element, message) {
    if (!element) return;
    element.textContent = message;
    element.hidden = !message;
  }

  function showNotice(element, message) {
    notice(element, message || "");
  }

  function hideNotice(element) {
    notice(element, "");
  }

  function showUpgradeNotice(element, message) {
    if (!element) return;
    element.innerHTML = `
      <span>${escapeHtml(message || "Upgrade to unlock this feature.")}</span>
      <button class="notice-action" type="button" data-upgrade-trigger>View plans</button>
    `;
    element.hidden = false;
  }

  async function apiJson(path, options) {
    const response = await fetch(path, {
      credentials: "same-origin",
      referrerPolicy: "same-origin",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": cookieValue(csrfCookieName),
        ...(options && options.headers ? options.headers : {}),
      },
      ...options,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      let message = payload.detail || payload.reason || (payload.locked && payload.locked.reason) || `Request failed with ${response.status}`;
      if (message && typeof message === "object") {
        message = message.message || message.reason || JSON.stringify(message);
      }
      const error = new Error(message);
      error.status = response.status;
      error.payload = payload;
      if (payload.locked) {
        error.locked = payload.locked;
      }
      throw error;
    }
    return payload;
  }

  async function apiForm(path, formData) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      referrerPolicy: "same-origin",
      headers: {
        "x-csrf-token": cookieValue(csrfCookieName),
      },
      body: formData,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      let message = payload.detail || payload.reason || (payload.locked && payload.locked.reason) || `Request failed with ${response.status}`;
      if (message && typeof message === "object") {
        message = message.message || message.reason || JSON.stringify(message);
      }
      const error = new Error(message);
      error.status = response.status;
      error.payload = payload;
      if (payload.locked) {
        error.locked = payload.locked;
      }
      throw error;
    }
    return payload;
  }

  function base64urlToBuffer(value) {
    const base64 = String(value).replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const binary = window.atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer || []);
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function credentialToJson(credential) {
    const response = credential.response || {};
    return {
      id: credential.id,
      type: credential.type,
      rawId: bufferToBase64url(credential.rawId),
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      response: {
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        attestationObject: response.attestationObject ? bufferToBase64url(response.attestationObject) : undefined,
        authenticatorData: response.authenticatorData ? bufferToBase64url(response.authenticatorData) : undefined,
        signature: response.signature ? bufferToBase64url(response.signature) : undefined,
        userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : undefined,
        transports: typeof response.getTransports === "function" ? response.getTransports() : undefined,
      },
      clientExtensionResults: typeof credential.getClientExtensionResults === "function"
        ? credential.getClientExtensionResults()
        : {},
    };
  }

  function prepareCredentialCreationOptions(options) {
    const publicKey = { ...options };
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);
    publicKey.user = { ...publicKey.user, id: base64urlToBuffer(publicKey.user.id) };
    publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map((item) => ({
      ...item,
      id: base64urlToBuffer(item.id),
    }));
    return publicKey;
  }

  function prepareCredentialRequestOptions(options) {
    const publicKey = { ...options };
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);
    publicKey.allowCredentials = (publicKey.allowCredentials || []).map((item) => ({
      ...item,
      id: base64urlToBuffer(item.id),
    }));
    return publicKey;
  }

  function webAuthnSupported() {
    return Boolean(window.PublicKeyCredential && navigator.credentials);
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function label(value) {
    return String(value || "")
      .replace(/[_-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase()
      .replace(/\b\w/g, (char) => char.toUpperCase());
  }

  function mailboxStatusLabel(status) {
    const normalized = String(status || "pending").toLowerCase();
    if (normalized === "active") return "Ready";
    if (normalized === "error") return "Reconnect needed";
    if (normalized === "pending") return "Reconnect to verify";
    return label(normalized);
  }

  function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  function mailboxWorkflowLabel(workflow) {
    const status = String(workflow && workflow.status ? workflow.status : "").toLowerCase();
    if (status === "ready") return "Ready to scan unread mail.";
    if (status === "credential_error") return "Reconnect required before scanning.";
    if (status === "needs_verification") return "Reconnect once to verify IMAP access.";
    return "No verified mailbox connected.";
  }

  function percent(value) {
    const score = Math.max(0, Math.min(Number(value || 0), 1));
    return `${(score * 100).toFixed(score >= 0.1 ? 1 : 2)}%`;
  }

  function formatBytes(value) {
    const bytes = Number(value || 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }

  function setPrintAvailable(available) {
    if (printResultButton) {
      printResultButton.hidden = !available;
    }
    if (downloadResultButton) {
      downloadResultButton.hidden = !available;
    }
  }

  function sampleEmailFile() {
    return new File([samplePhishEmail], "sample-suspicious-email.eml", {
      type: "message/rfc822",
      lastModified: Date.now(),
    });
  }

  function storedFirstRunState() {
    try {
      return JSON.parse(localStorage.getItem(firstRunStateKey) || "{}") || {};
    } catch (error) {
      console.debug("Ignoring invalid first-run state", error);
      return {};
    }
  }

  function saveFirstRunState(update) {
    const next = { ...storedFirstRunState(), ...update };
    localStorage.setItem(firstRunStateKey, JSON.stringify(next));
    updateFirstRunChecklist(next);
  }

  function updateFirstRunChecklist(state = {}) {
    if (!firstRunPanel) return;
    firstRunPanel.querySelectorAll("[data-first-run-step]").forEach((item) => {
      const key = item.getAttribute("data-first-run-step");
      item.classList.toggle("complete", Boolean(state[key]));
    });
  }

  function downloadReportFrom(element, filenamePrefix) {
    if (!element) return;
    const title = `${reportBrandName} report`;
    const reportHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;line-height:1.5;color:#111827;margin:32px;max-width:920px}
h1{font-size:26px;margin:0 0 16px}
section,article{border:1px solid #d1d5db;border-radius:8px;padding:14px;margin:12px 0}
span{color:#4b5563;font-size:12px;font-weight:700;text-transform:uppercase}
strong{display:block;margin-top:6px;font-size:18px}
</style>
</head>
<body>
<h1>${escapeHtml(title)}</h1>
${element.innerHTML}
</body>
</html>`;
    const blob = new Blob([reportHtml], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.html`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function planRank(slug) {
    const rank = planOrder.indexOf(String(slug || "").toLowerCase());
    return rank >= 0 ? rank : 0;
  }

  function highestPlanSlug() {
    return planOrder[planOrder.length - 1];
  }

  function formatMoney(value) {
    const amount = Number(value || 0);
    if (!Number.isFinite(amount)) return "0";
    return amount % 1 === 0
      ? amount.toLocaleString("en-AU", { maximumFractionDigits: 0 })
      : amount.toLocaleString("en-AU", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function formatCount(value, singular) {
    const count = Number(value || 0);
    const suffix = count === 1 ? singular : singular === "mailbox" ? "mailboxes" : `${singular}s`;
    return `${count.toLocaleString()} ${suffix}`;
  }

  function planCopy(plan, key) {
    return (phishPlanCopy[plan.slug] && phishPlanCopy[plan.slug][key]) || plan[key] || "";
  }

  function featureCopy(feature) {
    const override = phishFeatureCopy[feature.slug] || {};
    return {
      ...feature,
      name: override.name || feature.name,
      description: override.description || feature.description,
    };
  }

  function billingIntervalLabel() {
    return selectedBillingInterval === "yearly" ? "/ month, billed yearly" : "/ month";
  }

  function accountBillingIntervalLabel(account) {
    if (!account || account.plan_slug === "free" || !account.stripe_subscription_id) {
      return "Free plan";
    }
    return account.billing_interval === "yearly" ? "Annual plan" : "Monthly plan";
  }

  function formatAccountDate(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    return date.toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  }

  function billingRenewalCopy(account) {
    if (!account || account.plan_slug === "free") {
      return "No card on file. Upgrade creates billing.";
    }
    if (!account.stripe_customer_id) {
      return "Plan is set locally. Billing portal appears after first Stripe checkout.";
    }
    const renewal = formatAccountDate(account.current_period_end);
    if (account.billing_interval === "yearly") {
      return renewal
        ? `Annual plan. Manage billing in Stripe. Monthly changes should be scheduled for ${renewal}, after the prepaid annual period ends.`
        : "Annual plan. Manage billing in Stripe and schedule monthly changes at the next renewal.";
    }
    return renewal
      ? `Monthly plan. Next renewal: ${renewal}.`
      : "Monthly plan. Manage payment methods and subscription changes in Stripe.";
  }

  function billingErrorMessage(error) {
    const message = String(error && error.message ? error.message : error || "");
    if (/stripe|billing|checkout|portal|502|503/i.test(message)) {
      return "Billing is not available right now. The server needs a valid Stripe secret key before checkout can start.";
    }
    return message || "Billing is not available right now.";
  }

  function syncMailboxProviderFields() {
    if (!mailboxProviderSelect || !mailboxHostInput || !mailboxPortInput || !mailboxPasswordInput) return;
    const provider = mailboxProviderSelect.value || "imap";
    const defaults = mailboxProviderDefaults[provider] || mailboxProviderDefaults.imap;
    const knownHosts = Object.values(mailboxProviderDefaults).map((item) => item.host);
    if (!mailboxHostInput.value || knownHosts.includes(mailboxHostInput.value)) {
      mailboxHostInput.value = defaults.autofillHost === false ? "" : defaults.host;
    }
    const knownPorts = Object.values(mailboxProviderDefaults).map((item) => item.port);
    if (!mailboxPortInput.value || knownPorts.includes(mailboxPortInput.value)) {
      mailboxPortInput.value = defaults.autofillPort === false ? "" : defaults.port;
    }
    mailboxHostInput.placeholder = defaults.host;
    mailboxPortInput.placeholder = defaults.port;
    mailboxPasswordInput.placeholder = defaults.password;
    mailboxProviderSelect.title = defaults.title;
  }

  function openPricingPanel(message) {
    if (!pricingPanel) return;
    pricingPanel.hidden = false;
    if (message) {
      showUpgradeNotice(billingNotice, message);
    }
    if (!lastPlansPayload) {
      loadPlans().catch((error) => showNotice(billingNotice, error.message));
    }
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    pricingPanel.scrollIntoView({ behavior: prefersReducedMotion ? "auto" : "smooth", block: "start" });
  }

  function closePricingPanel() {
    if (pricingPanel) pricingPanel.hidden = true;
  }

  function decisionText(value) {
    const text = String(value || "").toUpperCase();
    if (text === "CLEAN") return "Clean";
    if (text === "SUSPICIOUS") return "Suspicious";
    if (text === "LIKELY_PHISHING") return "Likely phishing";
    if (text === "CONFIRMED_PHISHING") return "Confirmed phishing";
    return "Review evidence";
  }

  function decisionClass(value, verdict) {
    const text = String(value || verdict || "").toUpperCase();
    if (text === "SAFE" || text === "CLEAN") return "safe";
    if (text === "CONFIRMED_PHISHING") return "block";
    if (text === "VERIFY" || text === "SUSPICIOUS" || text === "LIKELY_PHISHING") return "verify";
    return "neutral";
  }

  function signalText(value) {
    const text = String(value || "").toUpperCase();
    if (text === "SAFE") return "No strong business email compromise signal";
    if (text === "VERIFY") return "Potential social-engineering signal";
    if (/PAY/.test(text) && /NOT/.test(text)) return "High-risk impersonation or redirection signal";
    return label(value || "No specific signal");
  }

  function updateNav() {
    document.querySelectorAll("[data-nav]").forEach((link) => {
      link.classList.toggle("active", link.dataset.nav === page);
    });
    const copy = pageCopy[page] || pageCopy.analyze;
    document.getElementById("pageHeading").textContent = copy.title;
    document.getElementById("pageSubheading").textContent = copy.sub;
    document.querySelectorAll("[data-panel]").forEach((panel) => {
      panel.hidden = panel.dataset.panel !== page;
    });
  }

  function authMode(mode) {
    if (mode === "signup" && !signupEnabled) {
      mode = "login";
      notice(authNotice, "Account creation is invite-only on this deployment.");
    }
    const copy = {
      login: ["Sign in to PhishAnalyze", "Use your workspace account to continue."],
      signup: ["Create your workspace", "Start with free manual email scans."],
      reset: ["Reset your password", "Enter your email and we will send a reset link if the account exists."],
      resetConfirm: ["Choose a new password", "Set a new password to return to your workspace."],
    }[mode];
    authTitle.textContent = copy[0];
    authSubtext.textContent = copy[1];
    Object.entries(forms).forEach(([key, form]) => {
      form.hidden = key !== mode;
    });
  }

  function updateAccount(account) {
    document.getElementById("workspaceLabel").textContent = account.org_name || "Workspace";
    document.getElementById("planName").textContent = account.plan_name || "Free";
    setText("planCadenceText", accountBillingIntervalLabel(account));
    document.getElementById("userEmail").textContent = account.email || "-";
    document.getElementById("usageText").textContent = `${account.monthly_scan_used || 0} / ${account.monthly_scan_quota || 0}`;
    const quota = Number(account.monthly_scan_quota || 0);
    const used = Number(account.monthly_scan_used || 0);
    const pct = quota > 0 ? Math.min((used / quota) * 100, 100) : 0;
    document.getElementById("usageBar").style.width = `${pct}%`;
    const upgradeButton = document.getElementById("upgradeButton");
    const portalButton = document.getElementById("portalButton");
    const billingHelp = document.getElementById("billingHelp");
    const isHighestPlan = account.plan_slug === highestPlanSlug();
    const hasStripeCustomer = Boolean(account.stripe_customer_id);
    upgradeButton.textContent = isHighestPlan ? "Plan details" : "Upgrade";
    upgradeButton.setAttribute("aria-label", isHighestPlan ? "View plan coverage" : "View upgrade options");
    portalButton.disabled = !hasStripeCustomer;
    portalButton.textContent = hasStripeCustomer ? "Manage billing" : "Billing portal locked";
    billingHelp.textContent = hasStripeCustomer
      ? billingRenewalCopy(account)
      : isHighestPlan
        ? "You are already on the highest plan. Billing portal appears after first checkout."
        : "Use Upgrade when you need more scans or paid checks.";
    updateFirstRunChecklist({
      ...storedFirstRunState(),
      upgrade: account.plan_slug && account.plan_slug !== "free",
    });
    renderSettingsAccount(account);
  }

  function renderSettingsAccount(account) {
    if (!account) return;
    const quota = Number(account.monthly_scan_quota || 0);
    const used = Number(account.monthly_scan_used || 0);
    const pct = quota > 0 ? Math.min((used / quota) * 100, 100) : 0;
    const role = label(account.role || "viewer");
    const workspace = account.org_name || "Workspace";
    const plan = account.plan_name || "Free";
    setText("settingsWorkspaceName", workspace);
    setText("settingsWorkspaceDetail", workspace);
    setText("settingsAccountEmail", account.email || "Signed-in account");
    setText("settingsAccountRole", `Role: ${role}`);
    setText("settingsRoleDetail", role);
    setText("settingsPlanName", plan);
    setText("settingsUsageText", `${used} / ${quota}`);
    const settingsUsageBar = document.getElementById("settingsUsageBar");
    if (settingsUsageBar) settingsUsageBar.style.width = `${pct}%`;
    const billingStatus = billingRenewalCopy(account);
    setText("settingsBillingStatus", accountBillingIntervalLabel(account));
    setText("settingsBillingCadenceNote", billingStatus);
    if (settingsPortalButton) {
      settingsPortalButton.disabled = !account.stripe_customer_id;
      settingsPortalButton.textContent = account.stripe_customer_id ? "Manage billing" : "Billing portal locked";
    }
  }

  function renderPasskeyPolicy(payload) {
    const policy = (payload && payload.policy) || {};
    const passkeys = (payload && payload.passkeys) || [];
    if (settingsPasskeyHeading) {
      settingsPasskeyHeading.textContent = policy.enforcement === "enforce"
        ? "Passkey step-up enforced"
        : "Passkey step-up monitoring";
    }
    if (settingsPasskeyStatus) {
      const support = webAuthnSupported() && policy.webauthn_available;
      const stepup = policy.fresh_step_up ? "Fresh step-up active." : "Fresh step-up not active.";
      settingsPasskeyStatus.textContent = support
        ? `${passkeys.length} passkey${passkeys.length === 1 ? "" : "s"} registered. ${stepup}`
        : "This browser or server cannot complete WebAuthn passkey setup.";
    }
    if (passkeyRegisterButton) {
      passkeyRegisterButton.disabled = !webAuthnSupported() || policy.webauthn_available === false;
    }
    if (passkeyStepupButton) {
      passkeyStepupButton.disabled = !webAuthnSupported() || !passkeys.length || policy.webauthn_available === false;
    }
    if (settingsPasskeyList) {
      settingsPasskeyList.innerHTML = passkeys.length
        ? passkeys.map((item) => `
          <article>
            <strong>${escapeHtml(item.credential_id.slice(0, 12))}</strong>
            <span>Added ${escapeHtml(item.created_at || "recently")}</span>
          </article>
        `).join("")
        : "<span>No passkey registered.</span>";
    }
  }

  async function loadSecurityPolicy() {
    if (!settingsPasskeyStatus && !settingsPasskeyList) return;
    try {
      const payload = await apiJson("/api/saas/security/policy");
      renderPasskeyPolicy(payload);
      hideNotice(passkeyNotice);
    } catch (error) {
      console.warn("Passkey policy could not be loaded", error);
      if (settingsPasskeyStatus) {
        settingsPasskeyStatus.textContent = "Passkey policy could not be loaded.";
      }
      showNotice(passkeyNotice, error.message);
    }
  }

  async function registerPasskey() {
    if (!webAuthnSupported()) {
      showNotice(passkeyNotice, "This browser does not support passkeys.");
      return;
    }
    passkeyRegisterButton.disabled = true;
    showNotice(passkeyNotice, "Waiting for browser passkey registration.");
    try {
      const payload = await apiJson("/api/saas/security/passkeys/register/options", {
        method: "POST",
        body: "{}",
      });
      const credential = await navigator.credentials.create({
        publicKey: prepareCredentialCreationOptions(payload.options),
      });
      await apiJson("/api/saas/security/passkeys/register/verify", {
        method: "POST",
        body: JSON.stringify({
          challenge: payload.challenge,
          credential: credentialToJson(credential),
        }),
      });
      showNotice(passkeyNotice, "Passkey registered. Fresh step-up is active.");
      await loadSecurityPolicy();
    } catch (error) {
      console.warn("Passkey registration failed", error);
      showNotice(passkeyNotice, error.message);
    } finally {
      passkeyRegisterButton.disabled = false;
    }
  }

  async function verifyPasskeyStepup() {
    if (!webAuthnSupported()) {
      showNotice(passkeyNotice, "This browser does not support passkeys.");
      return;
    }
    passkeyStepupButton.disabled = true;
    showNotice(passkeyNotice, "Waiting for browser passkey verification.");
    try {
      const payload = await apiJson("/api/saas/security/passkeys/authenticate/options", {
        method: "POST",
        body: "{}",
      });
      const credential = await navigator.credentials.get({
        publicKey: prepareCredentialRequestOptions(payload.options),
      });
      await apiJson("/api/saas/security/passkeys/authenticate/verify", {
        method: "POST",
        body: JSON.stringify({
          challenge: payload.challenge,
          credential: credentialToJson(credential),
        }),
      });
      showNotice(passkeyNotice, "Passkey verified. Privileged actions are unlocked briefly.");
      await loadSecurityPolicy();
    } catch (error) {
      console.warn("Passkey step-up verification failed", error);
      showNotice(passkeyNotice, error.message);
    } finally {
      passkeyStepupButton.disabled = false;
    }
  }

  async function loadSession() {
    const session = await apiJson("/api/saas/session");
    csrfCookieName = session.csrf_cookie || csrfCookieName;
    signupEnabled = Boolean(session.public_signup_enabled);
    if (!session.authenticated) {
      workspaceView.hidden = true;
      authView.hidden = false;
      authMode(new URLSearchParams(window.location.search).get("reset_token") ? "resetConfirm" : "login");
      const token = new URLSearchParams(window.location.search).get("reset_token");
      if (token) document.getElementById("resetToken").value = token;
      return;
    }
    authView.hidden = true;
    workspaceView.hidden = false;
    updateAccount(session.account);
    renderEmptyResult();
    hideNotice(billingNotice);
    await Promise.all([
      loadPlans(),
      loadHistory(),
      loadCases(),
      loadSimulationSummary(),
      loadMailboxes(),
      loadSecurityPolicy(),
      loadTeam().catch(() => {
        if (settingsTeamList) settingsTeamList.innerHTML = "<span>Team settings could not be loaded.</span>";
      }),
    ]);
  }

  async function loadPlans() {
    const payload = await apiJson("/api/saas/plans");
    lastPlansPayload = payload;
    featureCatalog = new Map((payload.features || []).map((feature) => [feature.slug, feature]));
    if (payload.account) updateAccount(payload.account);
    renderPricing(payload);
    renderFeatureAccess(payload);
  }

  function renderPricing(payload) {
    if (!planGrid) return;
    const currentPlan = payload.current_plan || (payload.account && payload.account.plan_slug) || "free";
    const currentRank = planRank(currentPlan);
    const maxPlanRank = Math.max(...(payload.plans || []).map((plan) => planRank(plan.slug)));
    const isHighestPlan = currentRank >= maxPlanRank;
    const pricingTitle = document.getElementById("pricingTitle");
    const pricingDescription = document.getElementById("pricingDescription");
    if (pricingTitle && pricingDescription) {
      pricingTitle.textContent = isHighestPlan ? "Plan coverage" : "Upgrade options";
      pricingDescription.textContent = isHighestPlan
        ? "You are already on the highest plan. The lower tiers are shown for comparison."
        : "Open this when you need more scans, mailbox monitoring, or external reputation checks.";
    }
    planGrid.innerHTML = "";
    (payload.plans || []).forEach((plan) => {
      const targetRank = planRank(plan.slug);
      const isCurrent = plan.slug === currentPlan;
      const isCovered = targetRank < currentRank;
      const canUpgrade = targetRank > currentRank;
      const isFree = plan.slug === "free";
      const priceValue = selectedBillingInterval === "yearly"
        ? Number(plan.yearly_monthly_price_aud || plan.monthly_price_aud || 0)
        : Number(plan.monthly_price_aud || 0);
      const price = priceValue > 0 ? `A$${formatMoney(priceValue)}` : "A$0";
      const yearlyTotal = Number(plan.yearly_price_aud || priceValue * 12);
      const billingNote = isFree
        ? "No card needed"
        : selectedBillingInterval === "yearly"
          ? `Billed A$${formatMoney(yearlyTotal)} yearly`
          : "Billed monthly";
      const savings = Number(plan.yearly_savings_percent || 0);
      const savingsBadge = selectedBillingInterval === "yearly" && savings > 0
        ? `<span class="plan-badge save">Save ${escapeHtml(String(savings))}%</span>`
        : "";
      const buttonText = isCurrent
        ? "Current plan"
        : isCovered || isFree
          ? "Included"
          : `Upgrade to ${plan.name}`;
      const card = document.createElement("article");
      card.className = `plan-card ${isCurrent ? "current" : ""} ${isCovered ? "covered" : ""}`;
      card.innerHTML = `
        <div class="plan-card-head">
          <div>
            <h3>${escapeHtml(plan.name)}</h3>
            <p class="plan-audience">${escapeHtml(planCopy(plan, "best_for"))}</p>
          </div>
          <div class="plan-card-badges">
            ${savingsBadge}
            ${isCovered ? '<span class="plan-badge included">Included</span>' : ""}
            ${isCurrent ? '<span class="plan-badge">Current</span>' : ""}
          </div>
        </div>
        <div class="plan-price">
          <span>${escapeHtml(price)}</span>
          ${isFree ? "" : `<small>${escapeHtml(billingIntervalLabel())}</small>`}
          <em>${escapeHtml(billingNote)}</em>
        </div>
        <div class="plan-limits">
          <span>${escapeHtml(formatCount(plan.scan_quota, "scan"))} / month</span>
          <span>${escapeHtml(formatCount(plan.mailbox_quota, "mailbox"))}</span>
        </div>
        <div class="plan-card-action">
          <p class="plan-summary">${escapeHtml(planCopy(plan, "summary"))}</p>
          <button type="button" data-plan="${escapeHtml(plan.slug)}" ${canUpgrade ? "" : "disabled"}>
            ${escapeHtml(buttonText)}
          </button>
        </div>
      `;
      planGrid.appendChild(card);
    });
  }

  function renderFeatureAccess(payload) {
    if (!featureGrid) return;
    const plans = new Map((payload.plans || []).map((plan) => [plan.slug, plan]));
    const currentPlan = payload.current_plan || (payload.account && payload.account.plan_slug) || "free";
    const currentRank = planRank(currentPlan);
    featureGrid.innerHTML = planOrder.map((planSlug) => {
      const plan = plans.get(planSlug) || { name: label(planSlug) };
      const features = (payload.features || []).filter((feature) => feature.minimum_plan === planSlug);
      if (!features.length) return "";
      const groupRank = planRank(planSlug);
      const available = currentRank >= groupRank;
      const status = available ? "Included now" : `${plan.name} unlocks`;
      const heading = planSlug === "free" ? "Core checks" : `${plan.name} checks`;
      const rows = features.map((rawFeature) => {
        const feature = featureCopy(rawFeature);
        return `
          <li>
            <strong>${escapeHtml(feature.name)}</strong>
            <span>${escapeHtml(feature.description)}</span>
          </li>
        `;
      }).join("");
      return `
        <article class="feature-card ${available ? "available" : "locked"}">
          <span class="feature-status">${escapeHtml(status)}</span>
          <h3>${escapeHtml(heading)}</h3>
          <ul>${rows}</ul>
        </article>
      `;
    }).join("");
  }

  function renderEmptyResult() {
    setPrintAvailable(false);
    resultTitle.textContent = "No scan selected";
    resultNote.textContent = "Choose a file to start a fresh analysis.";
    resultBody.innerHTML = `
      <section class="empty-result">
        <strong>Ready for a new email</strong>
        <p>Changing files or clearing the form removes the previous preview, so the next result is unambiguous.</p>
      </section>
    `;
  }

  function renderSelectedFile(file) {
    setPrintAvailable(false);
    resultTitle.textContent = "Ready to analyze";
    resultNote.textContent = "The next result will be tied to this selected file.";
    resultBody.innerHTML = `
      <section class="empty-result">
        <span class="result-kicker">Selected file</span>
        <strong>${escapeHtml(file.name)}</strong>
        <p>${escapeHtml(formatBytes(file.size))} selected.</p>
      </section>
    `;
  }

  function renderLoading(file) {
    setPrintAvailable(false);
    resultTitle.textContent = "Analyzing email";
    resultNote.textContent = "Running available checks for this workspace plan.";
    resultBody.innerHTML = `
      <section class="loading-result" aria-live="polite">
        <span class="spinner" aria-hidden="true"></span>
        <div>
          <strong>${escapeHtml(file.name)}</strong>
          <p>Working through the scan. The result will replace this loading state.</p>
          <ul class="loading-steps">
            <li>Parsing email</li>
            <li>Checking links</li>
            <li>Reviewing sender</li>
            <li>Preparing evidence</li>
          </ul>
        </div>
      </section>
    `;
  }

  function analyzerStatus(result) {
    const status = String((result && result.status) || "").toLowerCase();
    const statusCopy = {
      success: ["Completed", "done"],
      cached: ["Reused cached result", "cached"],
      failed: ["Could not run", "error"],
      timeout: ["Could not run", "error"],
      skipped: ["Not needed for this email", "quiet"],
      feature_locked: ["Not included in your plan", "locked"],
      not_configured: ["No API key configured", "quiet"],
      quota_exceeded: ["Monthly scan limit reached", "locked"],
    };
    if (statusCopy[status]) return statusCopy[status];
    const details = (result && result.details) || {};
    const errors = result && result.errors ? result.errors : [];
    if (details.message === "feature_locked") return ["Not included in your plan", "locked"];
    if ((Array.isArray(errors) && errors.length) || details.error || details.status === "error") return ["Needs attention", "error"];
    return ["Completed", "done"];
  }

  function analyzerRawStatus(result) {
    const item = result || {};
    const details = item.details || {};
    const status = String(item.status || "").toLowerCase();
    if (status) return status;
    if (details.message === "feature_locked") return "feature_locked";
    if (details.status === "error" || details.error) return "failed";
    return "success";
  }

  function analyzerRisk(result) {
    const item = result || {};
    const value = item.risk_contribution != null ? item.risk_contribution : item.risk_score;
    return Number.isFinite(Number(value)) ? Number(value) : 0;
  }

  function analyzerSummary(name, result) {
    const item = result || {};
    const details = (result && result.details) || {};
    const rawStatus = analyzerRawStatus(item);
    if (rawStatus === "feature_locked" || details.message === "feature_locked") {
      const feature = featureCatalog.get(details.feature_slug || name) || {};
      return `${feature.description || "This paid check was not run on this plan."} Required plan: ${details.required_plan_name || feature.required_plan_name || "a higher plan"}.`;
    }
    if (rawStatus === "quota_exceeded") {
      return "This check was not run because the monthly scan limit has been reached.";
    }
    if (rawStatus === "not_configured") {
      return "This external check needs a provider key on the server before it can run.";
    }
    if (rawStatus === "timeout") {
      return "This check took too long and was left out of the final score. Other evidence is still shown.";
    }
    if (rawStatus === "failed") {
      return truncate(item.failure_reason || details.reason || details.error || "This check did not return a usable result. Try again or contact support.", 170);
    }
    if (rawStatus === "skipped") {
      return truncate(item.failure_reason || details.reason || "This check was not needed for this email or was skipped by the pipeline.", 170);
    }
    const evidence = Array.isArray(result && result.evidence) ? result.evidence : [];
    if (evidence.length) {
      const text = evidence
        .map((item) => item && (item.text || item.value || item))
        .filter(Boolean)
        .slice(0, 2)
        .join(" ");
      if (text) return truncate(text, 170);
    }
    if (result && result.failure_reason) {
      return truncate(result.failure_reason, 170);
    }
    if (details.decision) {
      return `BEC signal: ${signalText(details.decision)}.`;
    }
    if (details.summary) return details.summary;
    if (details.reason) return details.reason;
    return "This check returned a result for this scan.";
  }

  function summarizeAnalyzerStatuses(analyzers) {
    const counts = {
      completed: 0,
      cached: 0,
      locked: 0,
      attention: 0,
    };
    analyzers.forEach(([, result]) => {
      const status = analyzerRawStatus(result);
      if (status === "cached") counts.cached += 1;
      else if (status === "feature_locked" || status === "quota_exceeded") counts.locked += 1;
      else if (status === "failed" || status === "timeout" || status === "not_configured") counts.attention += 1;
      else counts.completed += 1;
    });
    return counts;
  }

  function evidenceReasons(analyzers, fallback) {
    const reasons = [];
    analyzers.forEach(([name, result]) => {
      const status = analyzerRawStatus(result);
      if (status !== "success" && status !== "cached") return;
      const evidence = Array.isArray(result && result.evidence) ? result.evidence : [];
      const evidenceText = evidence
        .map((item) => item && (item.text || item.value || item))
        .filter(Boolean)
        .slice(0, 1)
        .join(" ");
      const summary = evidenceText || ((result && result.details && (result.details.summary || result.details.reason)) || "");
      if (summary) {
        reasons.push(`${analyzerLabel(name)}: ${truncate(summary, 100)}`);
      }
    });
    if (!reasons.length && fallback) {
      reasons.push(fallback);
    }
    return reasons.slice(0, 3);
  }

  function plainActionSteps(nextSteps) {
    const steps = Array.isArray(nextSteps) && nextSteps.length
      ? nextSteps.slice(0, 3)
      : ["Do not open links or attachments until you trust the sender.", "Confirm the sender through a separate trusted channel."];
    return steps;
  }

  function truncate(value, maxLength) {
    const text = String(value || "").replace(/\s+/g, " ").trim();
    if (text.length <= maxLength) return text;
    return `${text.slice(0, Math.max(maxLength - 1, 0)).trim()}...`;
  }

  function analyzerLabel(name) {
    const labels = {
      agent_prompt_injection: "AI instruction safety",
      attachment_analysis: "Attachment analysis",
      attachment_sandbox: "Attachment safety check",
      brand_impersonation: "Brand impersonation",
      domain_intelligence: "Domain intelligence",
      header_analysis: "Header authentication",
      nlp_intent: "Intent analysis",
      payment_fraud: "Business email compromise signals",
      payment_relevance: "Payment relevance",
      rmm_lure: "Remote access lure detection",
      sender_profiling: "Sender profiling",
      url_detonation: "Browser link check",
      url_reputation: "URL reputation",
    };
    const feature = featureCatalog.get(name);
    return (feature && feature.name) || labels[name] || label(name);
  }

  function renderLockedChecks(locks) {
    if (!Array.isArray(locks) || !locks.length) {
      return `
        <section class="locked-checks clear">
          <h3>All checks on your plan completed</h3>
          <p>No paid external check was skipped for this scan.</p>
        </section>
      `;
    }
    const cards = locks.map((lock) => {
      const details = (lock && lock.details) || {};
      const slug = details.feature_slug || "";
      const feature = featureCatalog.has(slug) ? featureCopy(featureCatalog.get(slug)) : {};
      const requiredPlan = details.required_plan_name || feature.required_plan_name || "Upgrade";
      return `
        <article class="locked-check-card">
          <div>
            <strong>${escapeHtml(feature.name || analyzerLabel(slug || "locked_check"))}</strong>
            <p>${escapeHtml(feature.description || "This check is available on a higher plan.")}</p>
          </div>
          <span>${escapeHtml(requiredPlan)}</span>
        </article>
      `;
    }).join("");
    return `
      <section class="locked-checks">
        <div class="locked-check-heading">
          <div>
            <h3>Not included in your plan</h3>
            <p>These paid checks were not run on the current plan.</p>
          </div>
          <button class="secondary-button" type="button" data-upgrade-trigger>Upgrade</button>
        </div>
        <div class="locked-check-list">${cards}</div>
      </section>
    `;
  }

  function renderResult(payload) {
    const productVerdict = payload.product_verdicts && payload.product_verdicts.phishanalyze
      ? payload.product_verdicts.phishanalyze
      : null;
    const decision = (productVerdict && productVerdict.verdict) || payload.verdict || "REVIEW";
    const source = payload.upload_filename || payload.email_id || "uploaded email";
    const analyzers = Object.entries(payload.analyzer_results || {});
    const statusCounts = summarizeAnalyzerStatuses(analyzers);
    setPrintAvailable(true);
    resultTitle.textContent = "Latest analysis";
    resultNote.textContent = `Fresh result for ${source}.`;
    const rows = analyzers.map(([name, result]) => {
      const status = analyzerStatus(result);
      return `
        <div class="evidence-row">
          <strong>${escapeHtml((result && result.display_name) || analyzerLabel(name))}</strong>
          <span class="status-pill ${escapeHtml(status[1])}">${escapeHtml(status[0])}</span>
          <span>${escapeHtml(analyzerSummary(name, result))}</span>
          <span>${escapeHtml(percent(analyzerRisk(result)))} risk</span>
        </div>
      `;
    }).join("");
    const nextSteps = productVerdict && Array.isArray(productVerdict.next_steps)
      ? productVerdict.next_steps
      : ["Review the evidence before opening links, attachments, or replying."];
    const why = evidenceReasons(analyzers, productVerdict && productVerdict.summary);
    const actions = plainActionSteps(nextSteps);
    resultBody.innerHTML = `
      <section class="result-source-strip" aria-label="Analyzed file">
        <div>
          <span>Analyzed file</span>
          <strong>${escapeHtml(source)}</strong>
        </div>
      </section>
      <section class="plain-answer-grid" aria-label="Plain English result summary">
        <article>
          <span>What did we find?</span>
          <strong>${escapeHtml((productVerdict && productVerdict.label) || decisionText(decision))}</strong>
          <p>${escapeHtml((productVerdict && productVerdict.summary) || "We reviewed the email and prepared the evidence below.")}</p>
        </article>
        <article>
          <span>Why?</span>
          <ul>${why.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        </article>
        <article>
          <span>What should I do now?</span>
          <ul>${actions.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>
        </article>
      </section>
      <section class="result-summary ${escapeHtml(decisionClass(payload.verdict))}">
        <div>
          <span class="result-kicker">Phishing verdict</span>
          <strong>${escapeHtml((productVerdict && productVerdict.label) || decisionText(decision))}</strong>
          <p>${escapeHtml((productVerdict && productVerdict.summary) || "Review the evidence below before opening links, attachments, or replying.")}</p>
        </div>
        <div class="score-box">
          <span class="result-kicker">Risk score</span>
          <strong>${escapeHtml(percent(payload.overall_score))}</strong>
        </div>
      </section>
      <section class="result-status-overview" aria-label="Check status summary">
        <article><span>Completed</span><strong>${escapeHtml(String(statusCounts.completed))}</strong></article>
        <article><span>Reused</span><strong>${escapeHtml(String(statusCounts.cached))}</strong></article>
        <article><span>Not included</span><strong>${escapeHtml(String(statusCounts.locked))}</strong></article>
        <article><span>Needs review</span><strong>${escapeHtml(String(statusCounts.attention))}</strong></article>
      </section>
      <section class="evidence-table" aria-label="Checks and evidence">
        <div class="evidence-row header">
          <span>Check</span>
          <span>Status</span>
          <span>Evidence</span>
          <span>Score</span>
        </div>
        ${rows || '<div class="evidence-row"><span>No check evidence returned.</span></div>'}
      </section>
      <section class="locked-checks clear">
        <h3>Next steps</h3>
        <ul>${nextSteps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>
      </section>
      ${renderLockedChecks(payload.feature_locks || [])}
    `;
    if (payload.account) updateAccount(payload.account);
  }

  function renderErrorResult(error) {
    setPrintAvailable(false);
    const message = error && error.message ? error.message : "The scan could not finish.";
    resultTitle.textContent = "Scan could not finish";
    resultNote.textContent = "No old result is shown here, so you do not confuse it with this attempt.";
    resultBody.innerHTML = `
      <section class="result-error" aria-live="polite">
        <strong>${escapeHtml(message)}</strong>
        <p>Try these next steps:</p>
        <ul>
          <li>Upload the original saved .eml file, not a screenshot or forwarded text.</li>
          <li>Try the sample email button to confirm the scanner is working.</li>
          <li>If the message mentions billing or scan limits, open the plan options.</li>
        </ul>
      </section>
    `;
  }

  function setFile(file) {
    if (!file) return;
    if (!/\.eml$/i.test(file.name || "")) {
      notice(scanNotice, "Use an .eml file for this scan.");
      return;
    }
    selectedFile = file;
    dropTitle.textContent = file.name;
    dropHint.textContent = `${formatBytes(file.size)} selected`;
    dropZone.classList.add("has-file");
    analyzeButton.disabled = false;
    clearButton.hidden = false;
    notice(scanNotice, "");
    renderSelectedFile(file);
  }

  function clearFile() {
    selectedFile = null;
    emailFile.value = "";
    dropTitle.textContent = "Drop your .eml file here, or click to browse";
    dropHint.textContent = "Supports .eml files";
    dropZone.classList.remove("has-file", "drag-over");
    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analyze email";
    clearButton.hidden = true;
    notice(scanNotice, "");
    renderEmptyResult();
  }

  async function loadHistory() {
    const payload = await apiJson("/api/saas/scans?limit=50");
    if (payload.account) updateAccount(payload.account);
    const results = payload.results || [];
    if (results.length) {
      saveFirstRunState({ upload: true, review: true });
    } else {
      updateFirstRunChecklist(storedFirstRunState());
    }
    renderStats(results);
    historyList.innerHTML = "";
    notice(historyNotice, "");
    if (!results.length) {
      historyList.innerHTML = '<article class="history-row"><div><strong>No scans yet</strong><span>Analyze an email to populate this workspace dashboard.</span></div></article>';
      return;
    }
    results.forEach((item) => {
      const subject = item.result && item.result.iocs && item.result.iocs.headers
        ? item.result.iocs.headers.subject || item.email_id
        : item.email_id;
      const verdict = String(item.verdict || "").toLowerCase();
      const row = document.createElement("article");
      row.className = "history-row";
      row.innerHTML = `
        <div>
          <strong>${escapeHtml(subject)}</strong>
          <span>${escapeHtml(item.created_at)} &middot; ${escapeHtml(item.payment_decision || "not payment-specific")}</span>
        </div>
        <div class="row-actions">
          <span class="badge ${escapeHtml(verdict)}">${escapeHtml(label(item.verdict))}</span>
          <button class="secondary-button" type="button" data-create-case="${escapeHtml(item.id)}">Case</button>
          <button class="secondary-button" type="button" data-delete-scan="${escapeHtml(item.id)}">Delete</button>
        </div>
      `;
      historyList.appendChild(row);
    });
  }

  function renderStats(results) {
    const counts = {
      total: results.length,
      clean: 0,
      suspicious: 0,
      likely: 0,
      confirmed: 0,
    };
    results.forEach((item) => {
      const verdict = String(item.verdict || "").toUpperCase();
      if (verdict === "CLEAN") counts.clean += 1;
      else if (verdict === "LIKELY_PHISHING") counts.likely += 1;
      else if (verdict === "CONFIRMED_PHISHING") counts.confirmed += 1;
      else counts.suspicious += 1;
    });
    const cards = [
      ["Total analyzed", counts.total],
      ["Clean", counts.clean],
      ["Suspicious", counts.suspicious],
      ["Likely phishing", counts.likely],
    ];
    statsRow.innerHTML = cards.map(([name, value]) => `
      <article class="stat-card">
        <span>${escapeHtml(name)}</span>
        <strong>${escapeHtml(value)}</strong>
      </article>
    `).join("");
  }

  async function loadCases() {
    if (!caseList) return;
    const payload = await apiJson("/api/saas/cases?limit=25");
    const cases = payload.cases || [];
    caseList.innerHTML = "";
    hideNotice(casesNotice);
    if (!cases.length) {
      caseList.innerHTML = '<article class="history-row"><div><strong>No cases yet</strong><span>Create a case from a scan when response tracking is needed.</span></div></article>';
      return;
    }
    cases.forEach((item) => {
      const row = document.createElement("article");
      row.className = "history-row case-row";
      const escalated = item.escalated_at ? "Escalated" : "Not escalated";
      row.innerHTML = `
        <div>
          <strong>${escapeHtml(item.title || item.email_id || "Incident case")}</strong>
          <span>${escapeHtml(label(item.severity))} severity &middot; ${escapeHtml(item.owner_email || "Unassigned")} &middot; ${escapeHtml(escalated)}</span>
        </div>
        <div class="row-actions">
          <span class="status-pill ${escapeHtml(item.status || "open")}">${escapeHtml(label(item.status || "open"))}</span>
          ${caseActionButtons(item)}
        </div>
      `;
      caseList.appendChild(row);
    });
  }

  function caseActionButtons(item) {
    const status = String(item.status || "open").toLowerCase();
    const id = escapeHtml(item.id);
    const transitions = {
      open: [["triaged", "Triaged"], ["investigating", "Investigate"], ["closed", "Close"]],
      triaged: [["investigating", "Investigate"], ["contained", "Contain"], ["closed", "Close"]],
      investigating: [["contained", "Contain"], ["closed", "Close"]],
      contained: [["closed", "Close"], ["investigating", "Reopen"]],
      closed: [["investigating", "Reopen"]],
    }[status] || [];
    const buttons = transitions.slice(0, 2).map(([next, text]) => (
      `<button class="secondary-button" type="button" data-case-id="${id}" data-case-status="${escapeHtml(next)}">${escapeHtml(text)}</button>`
    ));
    if (!item.escalated_at && status !== "closed") {
      buttons.push(`<button class="secondary-button" type="button" data-case-id="${id}" data-case-escalate="true">Escalate</button>`);
    }
    return buttons.join("");
  }

  async function loadSimulationSummary() {
    if (!simulationStatsRow) return;
    try {
      const payload = await apiJson("/api/saas/simulations/summary?days=90");
      renderSimulationSummary(payload.summary || {});
    } catch (error) {
      console.debug("Simulation summary could not be loaded", error);
      simulationStatsRow.innerHTML = "";
    }
  }

  function renderSimulationSummary(summary) {
    if (!simulationStatsRow) return;
    const score = summary.risk_score == null ? "-" : `${summary.risk_score}/100`;
    const cards = [
      ["Simulation sample", `${summary.total || 0} / ${summary.target_sample_size || 10}`],
      ["Simulation risk", score],
      ["Report rate", percent(summary.report_rate || 0)],
      ["Click rate", percent(summary.click_rate || 0)],
    ];
    simulationStatsRow.innerHTML = cards.map(([name, value]) => `
      <article class="stat-card">
        <span>${escapeHtml(name)}</span>
        <strong>${escapeHtml(value)}</strong>
      </article>
    `).join("");
  }

  async function loadMailboxes() {
    const payload = await apiJson("/api/saas/mailboxes");
    if (payload.account) updateAccount(payload.account);
    const mailboxes = payload.mailboxes || [];
    if (mailboxes.length) {
      saveFirstRunState({ mailbox: true });
    } else {
      updateFirstRunChecklist(storedFirstRunState());
    }
    const quota = payload.quota || { used: 0, limit: 0 };
    const entitlement = payload.entitlement || {};
    const locked = !entitlement.available;
    renderSettingsMailboxes(payload);
    mailboxQuota.textContent = `${quota.used} / ${quota.limit} mailboxes`;
    mailboxButton.textContent = locked ? `${entitlement.required_plan_name || "Pro"} required` : "Connect mailbox";
    mailboxForm.querySelectorAll("input, select, button[type='submit']").forEach((control) => {
      control.disabled = locked;
    });
    mailboxStatus.textContent = locked
      ? `${entitlement.reason || "Mailbox monitoring is locked on this plan."} Use Upgrade to review plans.`
      : "Mailbox connections are stored per workspace.";
    mailboxList.innerHTML = "";
    if (!mailboxes.length) {
      mailboxList.innerHTML = '<article class="mailbox-row"><div><strong>No connected mailbox</strong><span>Connect an inbox when monitoring is available on your plan.</span></div></article>';
      return;
    }
    mailboxes.forEach((item) => {
      const row = document.createElement("article");
      row.className = "mailbox-row";
      row.innerHTML = `
        <div>
          <strong>${escapeHtml(item.external_account_id || "Mailbox")}</strong>
          <span>${escapeHtml(label(item.provider))} &middot; ${escapeHtml(item.credential_saved ? "credential encrypted" : "credential missing")}</span>
        </div>
        <div class="row-actions">
          <span class="status-pill ${escapeHtml(item.status || "locked")}">${escapeHtml(mailboxStatusLabel(item.status))}</span>
          <button class="secondary-button" type="button" data-scan-mailbox="${escapeHtml(item.id)}">Scan now</button>
          <button class="secondary-button" type="button" data-delete-mailbox="${escapeHtml(item.id)}">Delete</button>
        </div>
      `;
      mailboxList.appendChild(row);
    });
  }

  function renderSettingsMailboxes(payload) {
    if (!payload) return;
    const mailboxes = payload.mailboxes || [];
    const quota = payload.quota || { used: mailboxes.length, limit: 0 };
    const workflow = payload.workflow || {};
    setText("settingsMailboxCount", `${quota.used || 0} / ${quota.limit || 0}`);
    setText("settingsMailboxStatus", mailboxWorkflowLabel(workflow));
    setText("settingsMailboxMessage", workflow.message || "Connect an inbox when monitoring is available on your plan.");
    setText(
      "settingsMailboxHeading",
      mailboxes.length
        ? `${mailboxes.length} connected mailbox${mailboxes.length === 1 ? "" : "es"}`
        : "Mailbox monitoring"
    );
  }

  async function loadTeam() {
    if (!settingsTeamList) return;
    const payload = await apiJson("/api/saas/team/members");
    if (payload.account) updateAccount(payload.account);
    const members = payload.members || [];
    if (settingsTeamSummary) {
      settingsTeamSummary.textContent = `${members.length} workspace member${members.length === 1 ? "" : "s"}`;
    }
    if (!members.length) {
      settingsTeamList.innerHTML = "<span>No team members found.</span>";
      return;
    }
    settingsTeamList.innerHTML = members.map((member) => `
      <article>
        <strong>${escapeHtml(member.email || "Member")}</strong>
        <span>${escapeHtml(label(member.role || "viewer"))}</span>
      </article>
    `).join("");
  }

  document.querySelectorAll("[data-auth-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      notice(authNotice, "");
      authMode(button.dataset.authMode || "login");
    });
  });

  forms.login.addEventListener("submit", async (event) => {
    event.preventDefault();
    notice(authNotice, "");
    try {
      const form = new FormData(event.currentTarget);
      await apiJson("/api/saas/auth/login", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      await loadSession();
    } catch (error) {
      console.warn("Login failed", error);
      notice(authNotice, error.message);
    }
  });

  forms.signup.addEventListener("submit", async (event) => {
    event.preventDefault();
    notice(authNotice, "");
    try {
      const form = new FormData(event.currentTarget);
      await apiJson("/api/saas/auth/signup", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      await loadSession();
    } catch (error) {
      console.warn("Signup failed", error);
      notice(authNotice, error.message);
    }
  });

  forms.reset.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const form = new FormData(event.currentTarget);
      const payload = await apiJson("/api/saas/auth/password-reset/request", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      notice(authNotice, payload.message);
    } catch (error) {
      console.warn("Password reset request failed", error);
      notice(authNotice, error.message);
    }
  });

  forms.resetConfirm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const form = new FormData(event.currentTarget);
      await apiJson("/api/saas/auth/password-reset/confirm", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      window.history.replaceState({}, "", window.location.pathname);
      await loadSession();
    } catch (error) {
      console.warn("Password reset confirmation failed", error);
      notice(authNotice, error.message);
    }
  });

  document.getElementById("logoutButton").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    hideNotice(billingNotice);
    try {
      await apiJson("/api/saas/auth/logout", { method: "POST", body: "{}" });
      window.location.href = "/analyze";
    } catch (error) {
      console.warn("Logout failed", error);
      button.disabled = false;
      notice(historyNotice, error.message || "Logout failed. Refresh and try again.");
    }
  });

  document.getElementById("upgradeButton").addEventListener("click", () => {
    hideNotice(billingNotice);
    openPricingPanel();
  });

  document.getElementById("closePricingButton").addEventListener("click", () => {
    closePricingPanel();
    hideNotice(billingNotice);
  });

  document.getElementById("portalButton").addEventListener("click", async () => {
    const portalButton = document.getElementById("portalButton");
    if (portalButton.disabled) return;
    hideNotice(billingNotice);
    try {
      const payload = await apiJson("/api/saas/billing/portal", {
        method: "POST",
        body: "{}",
      });
      if (!payload.portal_url) {
        throw new Error("Stripe did not return a billing portal URL.");
      }
      window.location.href = payload.portal_url;
    } catch (error) {
      console.warn("Billing portal request failed", error);
      showNotice(billingNotice, billingErrorMessage(error));
    }
  });

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-upgrade-trigger]");
    if (!trigger) return;
    event.preventDefault();
    openPricingPanel();
  });

  if (settingsPortalButton) {
    settingsPortalButton.addEventListener("click", () => {
      document.getElementById("portalButton").click();
    });
  }

  if (passkeyRegisterButton) {
    passkeyRegisterButton.addEventListener("click", registerPasskey);
  }

  if (passkeyStepupButton) {
    passkeyStepupButton.addEventListener("click", verifyPasskeyStepup);
  }

  billingCycle.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-billing-interval]");
    if (!button) return;
    selectedBillingInterval = button.getAttribute("data-billing-interval") || "monthly";
    billingCycle.querySelectorAll("button[data-billing-interval]").forEach((item) => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", active ? "true" : "false");
    });
    if (lastPlansPayload) {
      renderPricing(lastPlansPayload);
    }
  });

  planGrid.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-plan]");
    if (!button || button.disabled) return;
    hideNotice(billingNotice);
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Opening Checkout";
    try {
      const payload = await apiJson("/api/saas/billing/checkout", {
        method: "POST",
        body: JSON.stringify({
          plan: button.getAttribute("data-plan"),
          billing_interval: selectedBillingInterval,
        }),
      });
      if (!payload.checkout_url) {
        throw new Error("Stripe did not return a Checkout URL.");
      }
      window.location.href = payload.checkout_url;
    } catch (error) {
      console.warn("Checkout request failed", error);
      showNotice(billingNotice, billingErrorMessage(error));
      button.disabled = false;
      button.textContent = originalText;
    }
  });

  dropZone.addEventListener("click", () => emailFile.click());
  dropZone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      emailFile.click();
    }
  });
  emailFile.addEventListener("change", (event) => setFile(event.target.files[0]));
  dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropZone.classList.add("drag-over");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
  dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.classList.remove("drag-over");
    setFile(event.dataTransfer.files[0]);
  });
  clearButton.addEventListener("click", clearFile);
  if (sampleEmailButton) {
    sampleEmailButton.addEventListener("click", () => {
      setFile(sampleEmailFile());
      notice(scanNotice, "Sample email loaded. Click Analyze email to see a full report.");
    });
  }
  if (printResultButton) {
    printResultButton.addEventListener("click", () => window.print());
  }
  if (downloadResultButton) {
    downloadResultButton.addEventListener("click", () => downloadReportFrom(resultBody, "phishanalyze-report"));
  }

  document.getElementById("scanForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selectedFile) return;
    analyzeButton.disabled = true;
    clearButton.disabled = true;
    analyzeButton.textContent = "Analyzing";
    renderLoading(selectedFile);
    notice(scanNotice, "");
    try {
      const form = new FormData();
      form.append("file", selectedFile);
      const payload = await apiForm("/api/saas/analyze/upload", form);
      renderResult(payload);
      saveFirstRunState({ upload: true, review: true });
      await loadHistory();
    } catch (error) {
      console.warn("Manual email analysis failed", error);
      if (error.status === 402) {
        showUpgradeNotice(scanNotice, `${error.message} Upgrade to keep scanning.`);
        openPricingPanel();
      } else {
        notice(scanNotice, error.message);
      }
      renderErrorResult(error);
    } finally {
      analyzeButton.disabled = false;
      clearButton.disabled = false;
      analyzeButton.textContent = "Analyze email";
    }
  });

  document.getElementById("refreshHistoryButton").addEventListener("click", () => {
    loadHistory().catch((error) => notice(historyNotice, error.message));
  });

  if (refreshCasesButton) {
    refreshCasesButton.addEventListener("click", () => {
      loadCases().catch((error) => notice(casesNotice, error.message));
    });
  }

  if (mailboxProviderSelect) {
    mailboxProviderSelect.addEventListener("change", syncMailboxProviderFields);
    syncMailboxProviderFields();
  }

  historyList.addEventListener("click", async (event) => {
    const caseButton = event.target.closest("[data-create-case]");
    if (caseButton) {
      const resultId = caseButton.dataset.createCase;
      caseButton.disabled = true;
      caseButton.textContent = "Opening";
      hideNotice(casesNotice);
      try {
        await apiJson("/api/saas/cases", {
          method: "POST",
          body: JSON.stringify({ scan_result_id: resultId }),
        });
        await loadCases();
        notice(casesNotice, "Case opened.");
      } catch (error) {
        console.warn("Case creation failed", error);
        caseButton.disabled = false;
        caseButton.textContent = "Case";
        notice(casesNotice, error.message);
      }
      return;
    }

    const button = event.target.closest("[data-delete-scan]");
    if (!button) return;
    const resultId = button.dataset.deleteScan;
    button.disabled = true;
    button.textContent = "Deleting";
    try {
      await apiJson(`/api/saas/scans/${encodeURIComponent(resultId)}`, {
        method: "DELETE",
        body: "{}",
      });
      saveFirstRunState({ delete: true });
      await loadHistory();
      await loadCases();
    } catch (error) {
      console.warn("Scan delete failed", error);
      button.disabled = false;
      button.textContent = "Delete";
      notice(historyNotice, error.message);
    }
  });

  if (caseList) {
    caseList.addEventListener("click", async (event) => {
      const statusButton = event.target.closest("[data-case-status]");
      const escalateButton = event.target.closest("[data-case-escalate]");
      const button = statusButton || escalateButton;
      if (!button) return;
      const caseId = button.dataset.caseId;
      button.disabled = true;
      const originalText = button.textContent;
      button.textContent = "Saving";
      try {
        const payload = statusButton
          ? { status: statusButton.dataset.caseStatus }
          : { escalate: true, escalation_reason: "Manual escalation" };
        await apiJson(`/api/saas/cases/${encodeURIComponent(caseId)}`, {
          method: "PATCH",
          body: JSON.stringify(payload),
        });
        await loadCases();
      } catch (error) {
        console.warn("Case update failed", error);
        button.disabled = false;
        button.textContent = originalText;
        notice(casesNotice, error.message);
      }
    });
  }

  mailboxForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    mailboxButton.disabled = true;
    mailboxButton.textContent = "Testing";
    let mailboxStateReloaded = false;
    notice(mailboxNotice, "");
    try {
      const payload = await apiJson("/api/saas/mailboxes", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      event.currentTarget.reset();
      syncMailboxProviderFields();
      await loadMailboxes();
      mailboxStateReloaded = true;
      notice(mailboxNotice, payload.message || "Mailbox saved.");
    } catch (error) {
      console.warn("Mailbox save failed", error);
      if (error.status === 402) {
        showUpgradeNotice(mailboxNotice, `${error.message} Upgrade to connect mailbox monitoring.`);
        openPricingPanel();
      } else {
        notice(mailboxNotice, error.message);
      }
      await loadMailboxes().then(() => { mailboxStateReloaded = true; }).catch((reloadError) => {
        console.warn("Mailbox refresh after save failure failed", reloadError);
      });
    } finally {
      if (!mailboxStateReloaded) {
        mailboxButton.disabled = false;
        mailboxButton.textContent = "Connect mailbox";
      }
    }
  });

  mailboxList.addEventListener("click", async (event) => {
    const scanButton = event.target.closest("[data-scan-mailbox]");
    if (scanButton) {
      const mailboxId = scanButton.dataset.scanMailbox;
      scanButton.disabled = true;
      scanButton.textContent = "Scanning";
      try {
        const payload = await apiJson(`/api/saas/mailboxes/${encodeURIComponent(mailboxId)}/scan-now`, {
          method: "POST",
          body: JSON.stringify({ max_results: 5 }),
        });
        await loadMailboxes();
        await loadHistory();
        const count = Number(payload.analyzed || 0);
        const skipped = Number(payload.skipped_non_payment || payload.skipped || 0);
        const parts = [];
        if (count) parts.push(`scanned ${count} payment-related email${count === 1 ? "" : "s"}`);
        if (skipped) parts.push(`skipped ${skipped} non-payment email${skipped === 1 ? "" : "s"}`);
        const message = parts.join(" and ");
        notice(mailboxNotice, message ? `${message.charAt(0).toUpperCase()}${message.slice(1)}.` : "No new unread emails found.");
      } catch (error) {
        console.warn("Mailbox scan failed", error);
        scanButton.disabled = false;
        scanButton.textContent = "Scan now";
        if (error.status === 402) {
          showUpgradeNotice(mailboxNotice, `${error.message} Upgrade to scan connected mailboxes.`);
          openPricingPanel();
        } else {
          notice(mailboxNotice, error.message);
        }
      }
      return;
    }

    const button = event.target.closest("[data-delete-mailbox]");
    if (!button) return;
    const mailboxId = button.dataset.deleteMailbox;
    button.disabled = true;
    button.textContent = "Deleting";
    try {
      await apiJson(`/api/saas/mailboxes/${encodeURIComponent(mailboxId)}`, {
        method: "DELETE",
        body: "{}",
      });
      await loadMailboxes();
      notice(mailboxNotice, "Mailbox deleted.");
    } catch (error) {
      console.warn("Mailbox delete failed", error);
      button.disabled = false;
      button.textContent = "Delete";
      notice(mailboxNotice, error.message);
    }
  });

  updateNav();
  loadSession().catch((error) => {
    console.warn("Initial session load failed", error);
    authView.hidden = false;
    workspaceView.hidden = true;
    notice(authNotice, error.message);
  });
})();
