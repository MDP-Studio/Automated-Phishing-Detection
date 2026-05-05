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
  const clearButton = document.getElementById("clearButton");
  const historyList = document.getElementById("historyList");
  const statsRow = document.getElementById("statsRow");
  const mailboxForm = document.getElementById("mailboxForm");
  const mailboxButton = document.getElementById("mailboxButton");
  const mailboxList = document.getElementById("mailboxList");
  const mailboxStatus = document.getElementById("mailboxStatus");
  const mailboxQuota = document.getElementById("mailboxQuota");
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
    payment_rules: {
      name: "BEC and payment-language signals",
      description: "Business email compromise, urgency, and executive-transfer wording checks.",
    },
    sender_profiling: {
      description: "Baseline sender patterns and flag unusual sender behavior.",
    },
    llm_intent: {
      name: "LLM social-engineering reasoning",
      description: "LLM-backed phishing, BEC, and intent analysis.",
    },
  };

  const pageCopy = {
    analyze: {
      title: "Email risk analyzer",
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
  };

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
      const message = payload.detail || payload.reason || (payload.locked && payload.locked.reason) || `Request failed with ${response.status}`;
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
      const message = payload.detail || payload.reason || (payload.locked && payload.locked.reason) || `Request failed with ${response.status}`;
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

  function billingErrorMessage(error) {
    const message = String(error && error.message ? error.message : error || "");
    if (/stripe|billing|checkout|portal|502|503/i.test(message)) {
      return "Billing is not available right now. The server needs a valid Stripe secret key before checkout can start.";
    }
    return message || "Billing is not available right now.";
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
    if (text === "SAFE") return "Safe to continue";
    if (text === "VERIFY") return "Verify before payment";
    if (text === "DO_NOT_PAY") return "Do not pay";
    return "Review evidence";
  }

  function decisionClass(value, verdict) {
    const text = String(value || verdict || "").toUpperCase();
    if (text === "SAFE" || text === "CLEAN") return "safe";
    if (text === "DO_NOT_PAY" || text === "CONFIRMED_PHISHING") return "block";
    if (text === "VERIFY" || text === "SUSPICIOUS" || text === "LIKELY_PHISHING") return "verify";
    return "neutral";
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
      ? "Manage payment methods and subscription changes in Stripe."
      : isHighestPlan
        ? "You are already on the highest plan. Billing portal appears after first checkout."
        : "Use Upgrade when you need more scans or paid checks.";
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
    await Promise.all([loadPlans(), loadHistory(), loadMailboxes()]);
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
        : "Open this when you need more scans, mailbox monitoring, or paid API-backed checks.";
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
    resultTitle.textContent = "Analyzing email";
    resultNote.textContent = "Running available checks for this workspace plan.";
    resultBody.innerHTML = `
      <section class="loading-result" aria-live="polite">
        <span class="spinner" aria-hidden="true"></span>
        <div>
          <strong>${escapeHtml(file.name)}</strong>
          <p>Analyzing this email now. Results will replace this loading state.</p>
        </div>
      </section>
    `;
  }

  function analyzerStatus(result) {
    const details = (result && result.details) || {};
    const errors = result && result.errors ? result.errors : [];
    if (details.message === "feature_locked") return ["Locked", "locked"];
    if ((Array.isArray(errors) && errors.length) || details.error || details.status === "error") return ["Needs attention", "error"];
    return ["Completed", "done"];
  }

  function analyzerSummary(name, result) {
    const details = (result && result.details) || {};
    if (details.message === "feature_locked") {
      const feature = featureCatalog.get(details.feature_slug || name) || {};
      return `${feature.description || "This analyzer did not run."} Required plan: ${details.required_plan_name || feature.required_plan_name || "a higher plan"}.`;
    }
    if (details.decision) {
      return `Payment decision: ${decisionText(details.decision)}.`;
    }
    if (details.summary) return details.summary;
    if (details.reason) return details.reason;
    return "Analyzer returned a result for this scan.";
  }

  function analyzerLabel(name) {
    const labels = {
      attachment_analysis: "Attachment analysis",
      attachment_sandbox: "Attachment sandbox",
      brand_impersonation: "Brand impersonation",
      domain_intelligence: "Domain intelligence",
      header_analysis: "Header authentication",
      nlp_intent: "Intent analysis",
      payment_fraud: "Payment scam rules",
      sender_profiling: "Sender profiling",
      url_detonation: "Browser URL detonation",
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
          <p>No paid API-backed analyzer was skipped for this scan.</p>
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
            <p>${escapeHtml(feature.description || "This analyzer is available on a higher plan.")}</p>
          </div>
          <span>${escapeHtml(requiredPlan)}</span>
        </article>
      `;
    }).join("");
    return `
      <section class="locked-checks">
        <div class="locked-check-heading">
          <div>
            <h3>Skipped until upgrade</h3>
            <p>These paid checks were not run on the current plan.</p>
          </div>
          <button class="secondary-button" type="button" data-upgrade-trigger>Upgrade</button>
        </div>
        <div class="locked-check-list">${cards}</div>
      </section>
    `;
  }

  function renderResult(payload) {
    const payment = payload.payment_protection || {};
    const decision = payment.decision || payload.verdict || "REVIEW";
    const source = payload.upload_filename || payload.email_id || "uploaded email";
    resultTitle.textContent = "Latest analysis";
    resultNote.textContent = `Fresh result for ${source}.`;
    const analyzers = Object.entries(payload.analyzer_results || {});
    const rows = analyzers.map(([name, result]) => {
      const status = analyzerStatus(result);
      return `
        <div class="evidence-row">
          <strong>${escapeHtml(analyzerLabel(name))}</strong>
          <span class="status-pill ${escapeHtml(status[1])}">${escapeHtml(status[0])}</span>
          <span>${escapeHtml(analyzerSummary(name, result))}</span>
          <span>${escapeHtml(percent(result && result.risk_score))} risk</span>
        </div>
      `;
    }).join("");
    resultBody.innerHTML = `
      <section class="result-summary ${escapeHtml(decisionClass(payment.decision, payload.verdict))}">
        <div>
          <span class="result-kicker">Decision</span>
          <strong>${escapeHtml(decisionText(payment.decision || payload.verdict))}</strong>
          <p>Pipeline verdict: ${escapeHtml(label(payload.verdict || "Unknown"))}</p>
        </div>
        <div class="score-box">
          <span class="result-kicker">Risk score</span>
          <strong>${escapeHtml(percent(payload.overall_score))}</strong>
        </div>
      </section>
      <section class="evidence-table" aria-label="Analyzer evidence">
        <div class="evidence-row header">
          <span>Analyzer</span>
          <span>Status</span>
          <span>Evidence</span>
          <span>Score</span>
        </div>
        ${rows || '<div class="evidence-row"><span>No analyzer evidence returned.</span></div>'}
      </section>
      ${renderLockedChecks(payload.feature_locks || [])}
    `;
    if (payload.account) updateAccount(payload.account);
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

  async function loadMailboxes() {
    const payload = await apiJson("/api/saas/mailboxes");
    if (payload.account) updateAccount(payload.account);
    const mailboxes = payload.mailboxes || [];
    const quota = payload.quota || { used: 0, limit: 0 };
    const entitlement = payload.entitlement || {};
    const locked = !entitlement.available;
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
          <span class="status-pill ${escapeHtml(item.status || "locked")}">${escapeHtml(label(item.status || "pending"))}</span>
          <button class="secondary-button" type="button" data-delete-mailbox="${escapeHtml(item.id)}">Delete</button>
        </div>
      `;
      mailboxList.appendChild(row);
    });
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
      showNotice(billingNotice, billingErrorMessage(error));
    }
  });

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-upgrade-trigger]");
    if (!trigger) return;
    event.preventDefault();
    openPricingPanel();
  });

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
      await loadHistory();
    } catch (error) {
      if (error.status === 402) {
        showUpgradeNotice(scanNotice, `${error.message} Upgrade to keep scanning.`);
        openPricingPanel();
      } else {
        notice(scanNotice, error.message);
      }
      resultTitle.textContent = "Analysis failed";
      resultNote.textContent = "The previous result stays cleared. Try again after fixing the issue.";
      resultBody.innerHTML = `<section class="empty-result"><strong>${escapeHtml(error.message)}</strong></section>`;
    } finally {
      analyzeButton.disabled = false;
      clearButton.disabled = false;
      analyzeButton.textContent = "Analyze email";
    }
  });

  document.getElementById("refreshHistoryButton").addEventListener("click", () => {
    loadHistory().catch((error) => notice(historyNotice, error.message));
  });

  historyList.addEventListener("click", async (event) => {
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
      await loadHistory();
    } catch (error) {
      button.disabled = false;
      button.textContent = "Delete";
      notice(historyNotice, error.message);
    }
  });

  mailboxForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    mailboxButton.disabled = true;
    mailboxButton.textContent = "Saving";
    let mailboxStateReloaded = false;
    notice(mailboxNotice, "");
    try {
      const payload = await apiJson("/api/saas/mailboxes", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      event.currentTarget.reset();
      await loadMailboxes();
      mailboxStateReloaded = true;
      notice(mailboxNotice, payload.message || "Mailbox saved.");
    } catch (error) {
      if (error.status === 402) {
        showUpgradeNotice(mailboxNotice, `${error.message} Upgrade to connect mailbox monitoring.`);
        openPricingPanel();
      } else {
        notice(mailboxNotice, error.message);
      }
      await loadMailboxes().then(() => { mailboxStateReloaded = true; }).catch(() => {});
    } finally {
      if (!mailboxStateReloaded) {
        mailboxButton.disabled = false;
        mailboxButton.textContent = "Connect mailbox";
      }
    }
  });

  mailboxList.addEventListener("click", async (event) => {
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
      button.disabled = false;
      button.textContent = "Delete";
      notice(mailboxNotice, error.message);
    }
  });

  updateNav();
  loadSession().catch((error) => {
    authView.hidden = false;
    workspaceView.hidden = true;
    notice(authNotice, error.message);
  });
})();
