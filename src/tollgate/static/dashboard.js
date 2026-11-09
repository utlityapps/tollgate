/* Tollgate dashboard. Plain JavaScript + AG Grid Community.
 *
 * Everything that came from a listing, a merchant or an agent is attacker-controlled text.
 * It is only ever written with textContent / createElement, never innerHTML.
 */
(() => {
  "use strict";

  const state = {
    token: sessionStorage.getItem("tollgate.admin") || "",
    health: null,
    decisions: [],
    selectedId: null,
    outcome: "ALL", // the outcome chip in the decision-log toolbar: ALL, APPROVE, ESCALATE or DENY
    tab: "decisions",
    redteamRan: false,
    redteamRunning: false,
  };
  let decisionsApi = null;
  let mandatesApi = null;
  let redteamApi = null;

  const $ = (selector, root = document) => root.querySelector(selector);

  function el(tag, props = {}, ...kids) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = String(value);
      else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, String(value));
    }
    for (const kid of kids) if (kid !== null && kid !== undefined) node.append(kid);
    return node;
  }

  const chip = (text, kind) => el("span", { class: `chip ${kind}`, text });
  const humanize = (s) => String(s ?? "").replaceAll("_", " ");

  function fmtMoney(value, currency = "USD") {
    const n = Number(value);
    if (!Number.isFinite(n)) return String(value ?? "");
    try {
      return n.toLocaleString(undefined, { style: "currency", currency });
    } catch (_) {
      return `${n.toFixed(2)} ${currency}`;
    }
  }
  const fmtTime = (iso) => (iso ? new Date(iso).toLocaleTimeString(undefined, { hourCycle: "h23" }) : "");
  const fmtDateTime = (iso) => (iso ? new Date(iso).toLocaleString() : "");
  const fmtShortDateTime = (iso) =>
    iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short", hourCycle: "h23" }) : "";

  function safeUrl(url) {
    try {
      const u = new URL(url, window.location.origin);
      return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
    } catch (_) {
      return null;
    }
  }

  function banner(message) {
    const node = $("#banner");
    node.textContent = message || "";
    node.hidden = !message;
  }

  async function api(path, options = {}) {
    const headers = { Authorization: `Bearer ${state.token}` };
    let body;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    const response = await fetch(path, { method: options.method || "GET", headers, body });
    if (response.status === 401) {
      banner("Admin token rejected. Paste the admin token and press Connect.");
      throw new Error("unauthorized");
    }
    let data = {};
    try {
      data = await response.json();
    } catch (_) {
      /* empty body */
    }
    if (!response.ok) {
      const detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail ?? response.statusText);
      throw new Error(detail);
    }
    return data;
  }

  // ---- header ------------------------------------------------------------------------
  function renderPills() {
    const box = $("#pills");
    box.replaceChildren();
    const h = state.health;
    if (!h) return;
    const payments = h.payments === "mock" ? ["MOCK PAYMENTS (no keys set)", "warn"]
      : h.payments === "paypal-sandbox" ? ["PAYPAL SANDBOX", "good"] : ["PAYPAL LIVE", "bad"];
    box.append(el("span", { class: `pill ${payments[1]}`, text: payments[0] }));
    box.append(el("span", { class: "pill", text: `judge: ${h.judge}` }));
    box.append(el("span", { class: "pill", text: `layers: ${(h.layers || []).join(" + ") || "quotes + limits"}` }));
    if (h.demo_secrets) box.append(el("span", { class: "pill bad", text: "DEMO SECRETS: change before sharing" }));
  }

  // ---- decisions ---------------------------------------------------------------------
  function itemsSummary(items) {
    return (items || []).map((i) => `${i.quantity}× ${i.name}`).join(", ");
  }

  function riskBar(value) {
    const pct = Math.round(Math.min(1, Math.max(0, Number(value) || 0)) * 100);
    const level = pct >= 80 ? "hi" : pct >= 35 ? "mid" : "lo";
    return el("div", { class: "risk", title: `risk ${pct}%` },
      el("span", { class: `bar ${level}`, style: `width:${pct}%` }), el("em", { text: String(pct) }));
  }

  const numCompare = (a, b) => Number(a) - Number(b);

  // On a phone only Outcome, Status and Total fit; tap a row for everything else.
  const narrow = window.matchMedia("(max-width: 720px)");
  const WIDE_ONLY = ["created_at", "merchant_name", "items", "risk", "why"];
  function applyColumnLayout() {
    if (decisionsApi) decisionsApi.setColumnsVisible(WIDE_ONLY, !narrow.matches);
  }

  // A CSV opened in a spreadsheet runs any cell that starts with = + - @ (or a tab or CR) as a formula.
  // Merchant and item names are attacker-controlled, so such cells are exported as text.
  const csvCell = (value) => (/^[=+\-@\t\r]/.test(String(value ?? "")) ? `'${value}` : String(value ?? ""));

  // Everything the quick filter can match: the reasons in full and every finding code that fired.
  const searchText = (d) => [...(d.reasons || []), ...(d.findings || []).map((f) => f.code)].join(" ");

  function updateGridCount() {
    if (!decisionsApi) return; // AG Grid can report a model update while createGrid is still running
    const total = state.decisions.length;
    const shown = decisionsApi.getDisplayedRowCount();
    $("#gridCount").textContent = shown === total ? `${total} request${total === 1 ? "" : "s"}` : `${shown} of ${total} shown`;
    // This AG Grid only shows its no-rows overlay when there is no data at all, so a filter that hides
    // every row gets it from here.
    if (total > 0 && shown === 0) decisionsApi.showNoRowsOverlay();
    else if (shown > 0) decisionsApi.hideOverlay();
  }

  function createDecisionsGrid() {
    decisionsApi = agGrid.createGrid($("#decisionsGrid"), {
      columnDefs: [
        { headerName: "Time", field: "created_at", width: 86, valueFormatter: (p) => fmtTime(p.value), sort: "desc", filter: false },
        { headerName: "Outcome", field: "outcome", width: 104, filter: false, enableCellChangeFlash: true,
          cellRenderer: (p) => chip(p.value, String(p.value).toLowerCase()) },
        { headerName: "Status", field: "status", flex: 0.7, minWidth: 112, enableCellChangeFlash: true,
          cellRenderer: (p) => chip(humanize(p.value), "status") },
        { headerName: "Merchant", field: "merchant_name", flex: 1, minWidth: 112 }, // room for the label and the filter icon
        { colId: "items", headerName: "Items", valueGetter: (p) => itemsSummary(p.data.items), flex: 1.2, minWidth: 90 },
        { headerName: "Total", field: "total", width: 88, type: "rightAligned", comparator: numCompare, enableCellChangeFlash: true,
          filter: "agNumberColumnFilter", filterValueGetter: (p) => Number(p.data.total),
          valueFormatter: (p) => fmtMoney(p.value, p.data && p.data.currency) },
        { headerName: "Risk", field: "risk", width: 84, cellRenderer: (p) => riskBar(p.value), comparator: numCompare,
          filter: "agNumberColumnFilter", filterValueGetter: (p) => Math.round(Number(p.data.risk) * 100) }, // the 0 to 100 shown, not 0 to 1
        { colId: "why", headerName: "Why", valueGetter: (p) => (p.data.reasons || [])[0] || "No concerns", flex: 1.6, minWidth: 110,
          getQuickFilterText: (p) => searchText(p.data) },
        { colId: "id", headerName: "Decision ID", field: "id", hide: true }, // only in the CSV export
      ],
      defaultColDef: { sortable: true, resizable: true, filter: true },
      getRowId: (p) => String(p.data.id),
      rowData: [],
      rowHeight: 38,
      suppressCellFocus: true,
      animateRows: false,
      includeHiddenColumnsInQuickFilter: true, // on a phone Merchant, Items and Why are hidden but still searchable
      isExternalFilterPresent: () => state.outcome !== "ALL",
      doesExternalFilterPass: (node) => !!node.data && node.data.outcome === state.outcome,
      onModelUpdated: updateGridCount,
      rowClassRules: { "row-selected": (p) => !!p.data && p.data.id === state.selectedId },
      onRowClicked: (event) => {
        state.selectedId = event.data.id;
        decisionsApi.redrawRows();
        renderDetail(event.data);
      },
      noRowsOverlayComponent: NoDecisionsOverlay,
    });
  }

  // Shown when the grid has nothing to draw: either no requests yet, or a filter that matches none.
  class NoDecisionsOverlay {
    init() {
      this.gui = state.decisions.length
        ? el("span", { text: "No decisions match this filter." })
        : el("span", {}, "No purchase requests yet. Run ", el("b", { text: "tollgate demo" }), " in a terminal.");
    }
    getGui() {
      return this.gui;
    }
  }

  function exportCsv() {
    const stamp = new Date().toISOString().replace(/\.\d+Z$/, "Z").replace(/[-:]/g, "");
    decisionsApi.exportDataAsCsv({
      fileName: `tollgate-decisions-${stamp}.csv`, // the rows as filtered and sorted on screen
      allColumns: true,
      processCellCallback: (p) => csvCell(p.value),
    });
  }

  function wireDecisionToolbar() {
    $("#decisionSearch").addEventListener("input", (event) => {
      decisionsApi.setGridOption("quickFilterText", event.target.value);
    });
    const chips = [...document.querySelectorAll("#outcomeFilter button")];
    for (const button of chips) {
      button.addEventListener("click", () => {
        state.outcome = button.dataset.outcome;
        for (const other of chips) other.setAttribute("aria-pressed", String(other === button));
        decisionsApi.onFilterChanged(); // tells the grid to ask doesExternalFilterPass again
      });
    }
    $("#exportCsv").addEventListener("click", exportCsv);
  }

  // One block per finding: severity, code and who raised it on the first line, then the detail.
  function findingsList(findings) {
    if (!findings.length) return el("p", { class: "muted", text: "No findings." });
    return el("ul", { class: "findings" }, ...findings.map((f) => el("li", {},
      el("div", { class: "fhead" },
        chip(f.severity, `sev-${f.severity}`), el("code", { text: f.code }), el("span", { class: "muted", text: `by ${f.source}` })),
      el("div", { class: "fdetail", text: f.detail }),
      f.evidence ? el("code", { class: "evidence", text: f.evidence }) : null)));
  }

  async function review(decision, verb) {
    const note = verb === "approve" ? "approved in dashboard" : "declined in dashboard";
    try {
      await api(`/api/decisions/${encodeURIComponent(decision.id)}/${verb}`, { method: "POST", body: { reviewer: "dashboard", note } });
      banner("");
    } catch (error) {
      banner(`Could not ${verb}: ${error.message}`);
    }
    await refresh();
  }

  async function simulateBuyer(decision) {
    try {
      await fetch(`/mock/pay/${encodeURIComponent(decision.paypal_order_id)}/approve`, { method: "POST" });
      banner("");
    } catch (error) {
      banner(`Could not simulate the buyer: ${error.message}`);
    }
    await api(`/api/decisions/${encodeURIComponent(decision.id)}`).catch(() => null);
    await refresh();
  }

  async function refund(decision) {
    try {
      await api(`/api/decisions/${encodeURIComponent(decision.id)}/refund`, {
        method: "POST",
        body: { reviewer: "dashboard", note: "refunded in dashboard" },
      });
      banner("");
    } catch (error) {
      banner(`Could not refund: ${error.message}`);
    }
    await refresh();
  }

  // A refund moves money back, so the first tap arms the button and the second tap sends it.
  function refundButton(decision) {
    const label = "Refund this payment";
    const button = el("button", { class: "danger", text: label });
    let timer = null;
    button.addEventListener("click", () => {
      if (timer === null) {
        button.textContent = `Tap again to refund ${fmtMoney(decision.total, decision.currency)}`;
        timer = setTimeout(() => {
          timer = null;
          button.textContent = label;
        }, 4000);
        return;
      }
      clearTimeout(timer);
      timer = null;
      button.disabled = true;
      refund(decision);
    });
    return button;
  }

  function renderDetail(d) {
    const box = $("#detail");
    box.replaceChildren();
    if (!d) {
      box.append(el("p", { class: "muted", text: "Select a decision to see why Tollgate decided what it did." }));
      return;
    }
    box.append(el("h3", {}, chip(d.outcome, d.outcome.toLowerCase()), " ", chip(humanize(d.status), "status"), `  ${fmtMoney(d.total, d.currency)}`));
    box.append(el("dl", { class: "facts" },
      el("dt", { text: "Decision" }), el("dd", {}, el("code", { text: d.id })),
      el("dt", { text: "When" }), el("dd", { text: fmtDateTime(d.created_at) }),
      el("dt", { text: "Merchant" }), el("dd", { text: d.merchant_name || "none" }),
      el("dt", { text: "Items" }), el("dd", { text: itemsSummary(d.items) || "none (no valid quote)" }),
      el("dt", { text: "Risk" }), el("dd", { text: `${Math.round((d.risk || 0) * 100)} / 100` }),
      el("dt", { text: "Judge" }), el("dd", { text: `${d.judge_source}${d.judge_summary ? `: ${d.judge_summary}` : ""}` }),
      el("dt", { text: "Agent said" }), el("dd", { text: d.justification || "(nothing)" }),
      d.paypal_order_id ? el("dt", { text: "Order" }) : null,
      d.paypal_order_id ? el("dd", {}, el("code", { text: d.paypal_order_id })) : null,
      d.capture_id ? el("dt", { text: "Capture" }) : null,
      d.capture_id ? el("dd", {}, el("code", { text: d.capture_id })) : null,
      d.refund_id ? el("dt", { text: "Refund" }) : null,
      d.refund_id ? el("dd", {}, el("code", { text: d.refund_id })) : null));

    box.append(el("h4", { text: "Findings" }), findingsList(d.findings || []));
    box.append(el("h4", { text: "Timeline" }),
      el("ul", { class: "timeline" }, ...(d.events || []).map((e) =>
        el("li", {}, el("time", { text: fmtTime(e.at) }), el("b", { text: humanize(e.type) }), e.detail ? ` ${e.detail}` : ""))));

    const buttons = el("div", { class: "btnrow" });
    if (d.status === "pending_review") {
      buttons.append(el("button", { class: "primary", text: "Approve and create PayPal order", onclick: () => review(d, "approve") }));
      buttons.append(el("button", { class: "danger", text: "Deny", onclick: () => review(d, "deny") }));
    }
    const url = d.status === "order_created" ? safeUrl(d.approve_url) : null;
    if (url) {
      buttons.append(el("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, el("button", { text: "Open buyer approval page" })));
      if (state.health && state.health.payments === "mock") {
        buttons.append(el("button", { text: "Simulate buyer approval (mock)", onclick: () => simulateBuyer(d) }));
      }
    }
    if (d.status === "captured") buttons.append(refundButton(d));
    if (buttons.childNodes.length) box.append(buttons);
  }

  // ---- mandates ----------------------------------------------------------------------
  function createMandatesGrid() {
    mandatesApi = agGrid.createGrid($("#mandatesGrid"), {
      columnDefs: [
        { headerName: "ID", field: "id", width: 150, cellRenderer: (p) => el("code", { text: p.value }) },
        { headerName: "Owner", field: "owner", width: 100 },
        { headerName: "Task", field: "task", flex: 2, minWidth: 180 },
        { headerName: "Per order", field: "per_order_limit", width: 100, valueFormatter: (p) => fmtMoney(p.value) },
        { headerName: "Daily", field: "daily_limit", width: 92, valueFormatter: (p) => fmtMoney(p.value) },
        { headerName: "Auto below", field: "auto_approve_below", width: 108, valueFormatter: (p) => fmtMoney(p.value) },
        { headerName: "Merchants", valueGetter: (p) => (p.data.allowed_merchant_names || []).join(", "), flex: 1, minWidth: 140 },
        { headerName: "Expires", field: "expires_at", width: 140, valueFormatter: (p) => fmtShortDateTime(p.value) },
        { headerName: "State", field: "active", width: 92,
          cellRenderer: (p) => (p.value ? chip("active", "ok") : chip("revoked", "bad")) },
        { headerName: "", width: 96, sortable: false,
          cellRenderer: (p) => (p.data.active
            ? el("button", { text: "Revoke", class: "danger", onclick: async () => {
                try { await api(`/api/mandates/${encodeURIComponent(p.data.id)}/revoke`, { method: "POST" }); banner(""); }
                catch (error) { banner(`Could not revoke: ${error.message}`); }
                await loadMandates();
              } })
            : null) },
      ],
      defaultColDef: { sortable: true, resizable: true },
      getRowId: (p) => String(p.data.id),
      rowData: [],
      suppressCellFocus: true,
      animateRows: false,
      overlayNoRowsTemplate: "<span>No mandates yet. Create one above.</span>",
    });
  }

  async function loadMandates() {
    if (!mandatesApi || !state.token) return;
    try {
      mandatesApi.setGridOption("rowData", await api("/api/mandates"));
    } catch (_) { /* surfaced by api() */ }
  }

  const csv = (text) => String(text).split(",").map((s) => s.trim()).filter(Boolean);

  async function submitMandate(event) {
    event.preventDefault();
    const f = new FormData(event.target);
    const body = {
      owner: f.get("owner"),
      task: f.get("task"),
      per_order_limit: String(f.get("per_order_limit")),
      daily_limit: String(f.get("daily_limit")),
      auto_approve_below: String(f.get("auto_approve_below")),
      max_items_per_order: Number(f.get("max_items_per_order")),
      allowed_categories: csv(f.get("allowed_categories")),
      allowed_merchants: csv(f.get("allowed_merchants")),
      ttl_hours: Number(f.get("ttl_hours")),
    };
    const msg = $("#mandateMsg");
    try {
      const created = await api("/api/mandates", { method: "POST", body });
      msg.replaceChildren("Created ", el("code", { text: created.id }), ". Give this ID to your agent as TOLLGATE_MANDATE_ID.");
      banner("");
      await loadMandates();
    } catch (error) {
      msg.textContent = "";
      banner(`Could not create the mandate: ${error.message}`);
    }
  }

  // ---- red team ----------------------------------------------------------------------
  function outcomeCell(p) {
    return p.value ? chip(p.value, String(p.value).toLowerCase()) : null;
  }

  // ---- charts ------------------------------------------------------------------------
  // AG Charts Community (vendored, MIT). It draws on a canvas, so no text here is ever parsed as HTML.
  const INK = "#18202a";
  const MUTED = "#5a6572";
  const HAIRLINE = "#dde2e8";
  const CRITICAL = "#d03b3b"; // status colour: the series means "a bad outcome"
  const SERIES_1 = "#2a78d6"; // categorical slot 1: one nominal series gets one colour
  const FONT = 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  const LEVEL_SHORT = { baseline: "None", limits: "Limits", detectors: "Detectors", full: "Full" };
  const charts = new Map(); // container id -> { chart, key }

  const chartsReady = () => typeof agCharts !== "undefined" && !!agCharts.AgCharts;

  function chartFrame(title, subtitle) {
    return {
      background: { visible: false },
      padding: { top: 6, right: 14, bottom: 6, left: 4 },
      title: { text: title, textAlign: "left", color: INK, fontFamily: FONT, fontSize: 14, fontWeight: "bold" },
      subtitle: { text: subtitle, textAlign: "left", color: MUTED, fontFamily: FONT, fontSize: 12 },
      legend: { enabled: false }, // one series: the title already says what it is
    };
  }

  const categoryAxis = (position) => ({
    type: "category", position, paddingInner: 0.15, paddingOuter: 0.1, // bars have a fixed width, so the band is free for the label
    line: { enabled: true, strokeWidth: 1, stroke: "#c3cad3" },
    tick: { enabled: false },
    // Never wrap; a label too wide for a phone shrinks towards 9px, then is truncated, never clipped.
    label: { color: MUTED, fontFamily: FONT, fontSize: 12, wrapping: "never", truncate: true, minimumFontSize: 9 },
  });

  // Every column is labelled with its value, so the value axis (and its grid) would only repeat it.
  const valueAxis = (position, max) => ({
    type: "number", position, min: 0, ...(max ? { max } : {}),
    line: { enabled: false },
    tick: { enabled: false },
    gridLine: { enabled: false },
    label: { enabled: false },
  });

  const barSeries = (extra) => ({
    type: "bar", strokeWidth: 0, cornerRadius: 4,
    label: { enabled: true, placement: "outside-end", color: INK, fontFamily: FONT, fontSize: 12, fontWeight: "bold" },
    ...extra,
  });

  function drawChart(id, options, summary) {
    if (!chartsReady()) return;
    const node = $(`#${id}`);
    const key = JSON.stringify(options.data);
    const known = charts.get(id);
    if (known && known.key === key) return; // nothing changed, so do not restart the animation
    node.setAttribute("aria-label", summary);
    if (known) {
      known.chart.update({ ...options, container: node });
      known.key = key;
    } else {
      node.replaceChildren();
      charts.set(id, { chart: agCharts.AgCharts.create({ ...options, container: node }), key });
    }
  }

  function emptyChart(id, message) {
    const known = charts.get(id);
    if (known) {
      known.chart.destroy();
      charts.delete(id);
    }
    $(`#${id}`).replaceChildren(el("p", { class: "placeholder", text: message }));
  }

  function renderRedteamCharts(sc) {
    const attacks = sc.baseline.succeeded;
    const rows = [{ id: "baseline", succeeded: attacks, lost: Number(sc.baseline.usd_lost) }]
      .concat(sc.levels.map((l) => ({ id: l.id, succeeded: l.attacks.succeeded, lost: Number(l.usd_lost) })))
      .map((r) => ({ ...r, level: LEVEL_SHORT[r.id] || r.id }));
    drawChart("rtChartSucceeded", {
      ...chartFrame("Attacks that got through", `Out of ${attacks} attacks`),
      data: rows,
      series: [barSeries({
        xKey: "level", yKey: "succeeded", xName: "Defense level", yName: "Attacks that got through",
        fill: CRITICAL, width: 24, label: { ...barSeries({}).label, formatter: ({ value }) => String(value) },
      })],
      axes: { x: categoryAxis("bottom"), y: valueAxis("left", attacks + Math.ceil(attacks / 5)) },
    }, `Attacks that got through, out of ${attacks}: ${rows.map((r) => `${r.level} ${r.succeeded}`).join(", ")}.`);
    drawChart("rtChartLost", {
      ...chartFrame("Money lost", "Spent on attacker-chosen goods"),
      data: rows,
      series: [barSeries({
        xKey: "level", yKey: "lost", xName: "Defense level", yName: "Money lost (USD)",
        fill: CRITICAL, width: 24, label: { ...barSeries({}).label, formatter: ({ value }) => fmtMoney(value) },
      })],
      axes: { x: categoryAxis("bottom"), y: valueAxis("left") },
    }, `Money lost: ${rows.map((r) => `${r.level} ${fmtMoney(r.lost)}`).join(", ")}.`);
  }

  // Which finding codes flagged how many requests. Codes come from a fixed vocabulary, never from listing text.
  // A ranked list, not a canvas: the longest codes wrap instead of being clipped, and it reads fine on a phone.
  function renderFired(decisions) {
    const counts = new Map();
    for (const d of decisions) {
      for (const code of new Set((d.findings || []).map((f) => f.code))) counts.set(code, (counts.get(code) || 0) + 1);
    }
    const data = [...counts].map(([code, requests]) => ({ code, requests }))
      .sort((a, b) => b.requests - a.requests || a.code.localeCompare(b.code)).slice(0, 8);
    const list = $("#firedList");
    list.replaceChildren();
    if (!data.length) {
      list.append(el("li", { class: "empty muted", text: "No findings yet. Every flagged request will show up here." }));
      return;
    }
    for (const row of data) {
      const pct = Math.max(3, Math.round((row.requests / data[0].requests) * 100));
      list.append(el("li", {},
        el("code", { text: row.code }),
        el("span", { class: "track" }, el("span", { class: "fill", style: `width:${pct}%` }), el("b", { text: String(row.requests) }))));
    }
  }

  function createRedteamGrid() {
    redteamApi = agGrid.createGrid($("#redteamGrid"), {
      columnDefs: [
        { headerName: "Scenario", field: "title", flex: 2, minWidth: 260, tooltipField: "description" },
        { headerName: "Kind", field: "kind", width: 90, cellRenderer: (p) => chip(p.value, p.value === "attack" ? "bad" : "ok") },
        { headerName: "Caught by", field: "stopped_by", width: 110 },
        { headerName: "Expected", valueGetter: (p) => p.data.expect.join(" / "), width: 150 },
        { headerName: "Limits only", valueGetter: (p) => p.data.results.limits.outcome, width: 120, cellRenderer: outcomeCell },
        { headerName: "+ Detectors", valueGetter: (p) => p.data.results.detectors.outcome, width: 120, cellRenderer: outcomeCell },
        { headerName: "Full", valueGetter: (p) => p.data.results.full.outcome, width: 110, cellRenderer: outcomeCell },
        { headerName: "OK", valueGetter: (p) => (p.data.results.full.passed ? "pass" : "FAIL"), width: 90,
          cellRenderer: (p) => chip(p.value, p.value === "pass" ? "ok" : "bad") },
      ],
      defaultColDef: { sortable: true, resizable: true },
      getRowId: (p) => String(p.data.id),
      rowData: [],
      suppressCellFocus: true,
      tooltipShowDelay: 200,
      overlayNoRowsTemplate: "<span>Press <b>Run red team</b> to score every attack.</span>",
    });
  }

  function renderLevels(sc) {
    const table = $("#rtLevels");
    table.replaceChildren();
    const head = ["Defense level", "Attacks denied", "Held for a human", "Attacks that SUCCEEDED", "Benign handled", "$ lost"];
    table.append(el("thead", {}, el("tr", {}, ...head.map((h) => el("th", { text: h })))));
    const base = sc.baseline;
    const rows = [el("tr", { class: "base" }, el("td", { text: base.label }), el("td", { text: "0" }), el("td", { text: "0" }),
      el("td", { class: "bad", text: String(base.succeeded) }), el("td", { text: "n/a" }), el("td", { class: "bad", text: fmtMoney(base.usd_lost) }))];
    for (const level of sc.levels) {
      rows.push(el("tr", {}, el("td", { text: level.label }), el("td", { text: String(level.attacks.denied) }),
        el("td", { text: String(level.attacks.escalated) }),
        el("td", { class: level.attacks.succeeded ? "bad" : "", text: String(level.attacks.succeeded) }),
        el("td", { text: `${level.benign.ok} / ${level.benign.total}` }), el("td", { text: fmtMoney(level.usd_lost) })));
    }
    table.append(el("tbody", {}, ...rows));
  }

  async function runRedteam() {
    if (state.redteamRunning) return;
    state.redteamRunning = true;
    const button = $("#runRedteam");
    button.disabled = true;
    $("#rtHeadline").textContent = "Running...";
    try {
      const sc = await api("/api/redteam/run", { method: "POST" });
      $("#rtHeadline").textContent = sc.headline + (sc.passed ? "" : " (some scenarios missed expectations)");
      renderLevels(sc);
      renderRedteamCharts(sc);
      redteamApi.setGridOption("rowData", sc.scenarios);
      state.redteamRan = true;
      banner("");
    } catch (error) {
      $("#rtHeadline").textContent = "";
      banner(`Red team failed: ${error.message}`);
    } finally {
      state.redteamRunning = false;
      button.disabled = false;
    }
  }

  // ---- loop --------------------------------------------------------------------------
  function renderKpis(stats) {
    $("#kpiApproved").textContent = fmtMoney(stats.approved_usd);
    $("#kpiBlocked").textContent = fmtMoney(stats.blocked_usd);
    $("#kpiHeld").textContent = fmtMoney(stats.held_usd);
    $("#kpiHeldLabel").textContent = `Waiting for a human (${stats.pending_review})`;
    $("#kpiCount").textContent = String(stats.decisions);
  }

  async function refresh() {
    if (!state.token) return;
    try {
      const [rows, stats] = await Promise.all([api("/api/decisions?limit=300"), api("/api/stats")]);
      state.decisions = rows;
      decisionsApi.setGridOption("rowData", rows);
      renderFired(rows);
      renderKpis(stats);
      const selected = rows.find((r) => r.id === state.selectedId);
      if (selected) renderDetail(selected);
      if (!$("#banner").textContent.startsWith("Could not")) banner("");
    } catch (error) {
      if (error.message !== "unauthorized") banner(`Cannot reach Tollgate: ${error.message}`);
    }
  }

  function switchTab(name) {
    state.tab = name;
    for (const tab of document.querySelectorAll(".tab")) tab.classList.toggle("active", tab.dataset.tab === name);
    for (const id of ["decisions", "mandates", "redteam"]) $(`#tab-${id}`).hidden = id !== name;
    if (name === "mandates") loadMandates();
    if (name === "redteam" && !state.redteamRan && state.token) runRedteam();
  }

  async function start() {
    createDecisionsGrid();
    wireDecisionToolbar();
    createMandatesGrid();
    createRedteamGrid();
    applyColumnLayout();
    narrow.addEventListener("change", applyColumnLayout);
    renderDetail(null);
    emptyChart("rtChartSucceeded", "The chart appears when the red team has run.");
    emptyChart("rtChartLost", "The chart appears when the red team has run.");
    renderFired([]);
    for (const tab of document.querySelectorAll(".tab")) tab.addEventListener("click", () => switchTab(tab.dataset.tab));
    $("#mandateForm").addEventListener("submit", submitMandate);
    $("#runRedteam").addEventListener("click", runRedteam);
    $("#login").addEventListener("submit", (event) => {
      event.preventDefault();
      state.token = $("#token").value.trim();
      sessionStorage.setItem("tollgate.admin", state.token);
      banner("");
      refresh();
    });
    try {
      state.health = await (await fetch("/api/health")).json();
      renderPills();
      if (!state.token && state.health.admin_token_hint) {
        state.token = state.health.admin_token_hint;
        $("#token").placeholder = "demo: token filled";
      }
    } catch (_) {
      banner("Cannot reach the Tollgate API.");
    }
    if (!state.token) banner("Paste the admin token and press Connect.");
    await refresh();
    setInterval(refresh, 2500);
  }

  start();
})();
