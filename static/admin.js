(function () {
  const metricGrid = document.getElementById("metricGrid");
  const planList = document.getElementById("planList");
  const verdictList = document.getElementById("verdictList");
  const mailboxList = document.getElementById("mailboxList");
  const lockList = document.getElementById("lockList");
  const analyzerStatusList = document.getElementById("analyzerStatusList");
  const costTierList = document.getElementById("costTierList");
  const analyzerFailureList = document.getElementById("analyzerFailureList");
  const cachedCheckList = document.getElementById("cachedCheckList");
  const ctiTransportList = document.getElementById("ctiTransportList");
  const paymentAssuranceList = document.getElementById("paymentAssuranceList");
  const auditList = document.getElementById("auditList");
  const adminNotice = document.getElementById("adminNotice");
  const buildLabel = document.getElementById("buildLabel");
  const refreshButton = document.getElementById("refreshButton");

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

  function notice(message) {
    adminNotice.textContent = message || "";
    adminNotice.hidden = !message;
  }

  function renderRows(element, rows, empty) {
    if (!rows || !rows.length) {
      element.innerHTML = `<div class="row"><strong>${escapeHtml(empty)}</strong><span>0</span></div>`;
      return;
    }
    element.innerHTML = rows.map((row) => `
      <div class="row">
        <strong>${escapeHtml(label(row.name))}</strong>
        <span>${escapeHtml(Number(row.count || 0).toLocaleString())}</span>
      </div>
    `).join("");
  }

  function renderKeyRows(element, rows, empty) {
    if (!rows || !rows.length) {
      element.innerHTML = `<div class="row"><strong>${escapeHtml(empty)}</strong><span>empty</span></div>`;
      return;
    }
    element.innerHTML = rows.map(([name, value]) => `
      <div class="row">
        <strong>${escapeHtml(name)}</strong>
        <span>${escapeHtml(value)}</span>
      </div>
    `).join("");
  }

  function renderMetrics(payload) {
    const totals = payload.totals || {};
    const owner = payload.owner_console || {};
    const metrics = [
      ["Organizations", totals.organizations || 0],
      ["Users", totals.users || 0],
      ["Workspace scans", totals.scans || 0],
      ["User mailboxes", totals.mailboxes || 0],
      ["Owner monitor", owner.monitor_running ? "Running" : "Stopped"],
      ["Owner mailboxes", owner.configured_mailbox_accounts || 0],
      ["Active owner accounts", owner.active_mailbox_accounts || 0],
      ["Runtime uploads", owner.recent_runtime_results || 0],
    ];
    metricGrid.innerHTML = metrics.map(([name, value]) => `
      <article class="metric-card">
        <span>${escapeHtml(name)}</span>
        <strong>${escapeHtml(value)}</strong>
      </article>
    `).join("");
  }

  function renderAudit(rows) {
    if (!rows || !rows.length) {
      auditList.innerHTML = '<div class="audit-row"><strong>No audit activity yet</strong><span>empty</span></div>';
      return;
    }
    auditList.innerHTML = rows.map((row) => `
      <div class="audit-row">
        <div>
          <strong>${escapeHtml(label(row.action))}</strong>
          <span>${escapeHtml(row.target_type)} &middot; org ${escapeHtml(row.org_ref)}</span>
        </div>
        <span>${escapeHtml(row.created_at)}</span>
      </div>
    `).join("");
  }

  async function load() {
    refreshButton.disabled = true;
    refreshButton.textContent = "Refreshing";
    notice("");
    try {
      const response = await fetch("/admin/api/overview", {
        credentials: "same-origin",
        referrerPolicy: "same-origin",
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || `Request failed with ${response.status}`);
      }
      renderMetrics(payload);
      renderRows(planList, payload.plans, "No plan data");
      renderRows(verdictList, payload.verdicts, "No scan data");
      renderRows(mailboxList, [
        ...(payload.mailboxes_by_status || []).map((row) => ({ name: `status ${row.name}`, count: row.count })),
        ...(payload.mailboxes_by_provider || []).map((row) => ({ name: `provider ${row.name}`, count: row.count })),
      ], "No mailbox data");
      renderRows(lockList, payload.feature_locks, "No feature locks");
      const analyzers = payload.analyzers || {};
      renderRows(analyzerStatusList, analyzers.statuses, "No analyzer status data");
      renderRows(costTierList, analyzers.cost_tiers, "No cost tier data");
      renderRows(analyzerFailureList, [
        ...(analyzers.failures || []).map((row) => ({ name: `failed ${row.name}`, count: row.count })),
        ...(analyzers.not_configured || []).map((row) => ({ name: `not configured ${row.name}`, count: row.count })),
      ], "No analyzer failures");
      renderRows(cachedCheckList, analyzers.cached, "No cached checks");
      const cti = payload.cti_transport || {};
      const taxii = cti.taxii || {};
      const sigma = cti.sigma_conversion || {};
      renderKeyRows(ctiTransportList, [
        ["TAXII", `${label(taxii.status || "never_run")} · ${taxii.configured ? "configured" : "not configured"}`],
        ["TAXII objects", Number(taxii.object_count || 0).toLocaleString()],
        ["Sigma converter", `${label(sigma.status || "never_run")} · ${sigma.rules_converted || 0}/${sigma.rules_checked || 0}`],
        ["Sigma failures", Number(sigma.failure_count || 0).toLocaleString()],
      ], "No CTI transport data");
      const assurance = payload.payment_assurance || {};
      renderKeyRows(paymentAssuranceList, [
        ["Status", label(assurance.status || "never_run")],
        ["Ready", assurance.ready ? "Yes" : "No"],
        [
          "Real redacted",
          `${Number(assurance.pii_free_real_redacted_total || 0).toLocaleString()}/${Number(assurance.review_target || 0).toLocaleString()}`,
        ],
        ["Recommendations", Number(assurance.recommendation_count || 0).toLocaleString()],
      ], "No payment assurance data");
      renderAudit(payload.recent_audit);
      buildLabel.textContent = `Build ${payload.system && payload.system.build_sha ? payload.system.build_sha : "unknown"}`;
    } catch (error) { console.debug("Suppressed exception in static/admin.js", error);
      notice(error.message);
    } finally {
      refreshButton.disabled = false;
      refreshButton.textContent = "Refresh";
    }
  }

  refreshButton.addEventListener("click", load);
  load();
})();
