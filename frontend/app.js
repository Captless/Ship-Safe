"use strict";

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const RING_CIRCUMFERENCE = 552.92;
const POLL_INTERVAL_MS = 700;
const MAX_POLL_ERRORS = 4;

const PHASE_TITLES = {
  uploading: "Uploading your project",
  preparing: "Preparing your project",
  discovering: "Discovering files",
  filtering: "Filtering files",
  scanning: "Checking your code",
  reviewing: "Reviewing findings",
  building_report: "Preparing your report",
  complete: "Scan complete",
  error: "Scan could not be completed",
};

const PHASE_MESSAGES = {
  discovering: "We're looking through your project structure.",
};

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const SEVERITY_TEXT = {
  critical: "Fix this first",
  high: "Important",
  medium: "Review this",
  low: "Good to know",
  informational: "Optional",
};
const SEVERITY_COLORS = {
  critical: "#f85149",
  high: "#f0883e",
  medium: "#fbbf24",
  low: "#38bdf8",
  informational: "#8b949e",
};
const GRADE_COLORS = {
  looking: "#2dd4bf",
  almost: "#38bdf8",
  review: "#fbbf24",
  dont: "#f0883e",
  risk: "#f85149",
};

const PRIORITY_ROWS = [
  { sev: "critical", label: "Fix before shipping", color: "#f85149" },
  { sev: "high", label: "Worth reviewing", color: "#f0883e" },
  { sev: "medium", label: "Worth reviewing", color: "#fbbf24" },
  { sev: "low", label: "Good to know", color: "#38bdf8" },
  { sev: "informational", label: "Good to know", color: "#8b949e" },
];

const PASSED_LABELS = [
  { prefix: "SECRET-", category: "secrets", label: "No obvious exposed secrets" },
  { prefix: "GIT-", category: "git", label: "No risky version-control files" },
  { prefix: "CONF-", category: "config", label: "No unsafe configuration defaults" },
  { prefix: "DB-", category: "database", label: "No database credential exposure" },
  { prefix: "AUTH-", category: "auth", label: "Authentication checks look present" },
  { prefix: "API-", category: "api", label: "API input validation looks present" },
  { prefix: "PAY-", category: "payments", label: "Payment handling looks reasonable" },
  { prefix: "CODE-", category: "code", label: "No dangerous code patterns detected" },
  { prefix: "DEPLOY-", category: "deploy", label: "No insecure deployment settings" },
  { prefix: "DEP-", category: "dependencies", label: "Dependencies look reasonable" },
];

const CONSOLIDATED_STEPS = [
  "Inspect the existing project first.",
  "Understand the existing architecture and conventions before making changes.",
  "Address each listed finding with the smallest appropriate change.",
  "Do not create duplicate files or duplicate existing modules.",
  "Preserve existing behavior unless a finding requires changing it.",
  "Avoid unrelated refactoring.",
  "Verify your changes by running the relevant tests.",
  "Summarize what you changed and why.",
];

const els = {
  ctaScan: document.getElementById("cta-scan"),
  viewLanding: document.getElementById("view-landing"),
  viewUpload: document.getElementById("view-upload"),
  viewProgress: document.getElementById("view-progress"),
  viewScanComplete: document.getElementById("view-scan-complete"),
  viewResults: document.getElementById("view-results"),
  dropzone: document.getElementById("upload-dropzone"),
  fileInput: document.getElementById("upload-input"),
  fileInfo: document.getElementById("upload-fileinfo"),
  uploadError: document.getElementById("upload-error"),
  uploadButton: document.getElementById("upload-button"),
  progressTitle: document.getElementById("progress-title"),
  progressMessage: document.getElementById("progress-message"),
  progressActivity: document.getElementById("progress-activity"),
  progressFileStats: document.getElementById("progress-file-stats"),
  progressError: document.getElementById("progress-error"),
  progressActions: document.getElementById("progress-actions"),
  progressRetry: document.getElementById("progress-retry"),
  completeTitle: document.getElementById("complete-title"),
  completeMessage: document.getElementById("complete-message"),
  completeScore: document.getElementById("complete-score"),
  completeGrade: document.getElementById("complete-grade"),
  completeSummary: document.getElementById("complete-summary"),
  completeStats: document.getElementById("complete-stats"),
  completeDuration: document.getElementById("complete-duration"),
  completeLive: document.getElementById("complete-live"),
  reviewReport: document.getElementById("review-report"),
  scanAgainComplete: document.getElementById("scan-again-complete"),
  resultsTitle: document.getElementById("results-title"),
  heroTitle: document.getElementById("hero-title"),
  scoreNumber: document.getElementById("results-score"),
  scoreGrade: document.getElementById("results-grade"),
  scoreRing: document.getElementById("results-score-ring"),
  summary: document.getElementById("results-summary"),
  findingsList: document.getElementById("findings-list"),
  prioritySection: document.getElementById("priority-section"),
  priorityList: document.getElementById("priority-list"),
  nextStepSection: document.getElementById("next-step-section"),
  nextStepText: document.getElementById("next-step-text"),
  fixWithAi: document.getElementById("fix-with-ai"),
  consolidatedSection: document.getElementById("consolidated-section"),
  consolidatedIntro: document.getElementById("consolidated-intro"),
  consolidatedToggle: document.getElementById("consolidated-toggle"),
  consolidatedCopy: document.getElementById("consolidated-copy"),
  consolidatedPrompt: document.getElementById("consolidated-prompt"),
  whatsGoodSection: document.getElementById("whats-good-section"),
  whatsGoodList: document.getElementById("whats-good-list"),
  scanInfoSection: document.getElementById("scan-info-section"),
  scanInfoText: document.getElementById("scan-info-text"),
  downloadReport: document.getElementById("download-report"),
  scanAgain: document.getElementById("scan-again"),
};

let selectedFile = null;
let currentScanId = null;
let currentResult = null;
let lastAnnouncedPhase = null;
let lastAnnouncedMessage = null;
let activityEntries = [];
let activityCurrent = null;

function showView(viewName) {
  [els.viewLanding, els.viewUpload, els.viewProgress, els.viewScanComplete, els.viewResults].forEach(function (v) {
    const show = v === viewName;
    v.hidden = !show;
    v.classList.toggle("active", show);
  });
  window.scrollTo({ top: 0, behavior: "auto" });
}

function setError(message) {
  els.uploadError.textContent = message;
  els.uploadError.hidden = !message;
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function formatDuration(ms) {
  if (typeof ms !== "number" || isNaN(ms)) return "n/a";
  if (ms < 1000) return ms + " ms";
  return (ms / 1000).toFixed(1) + " s";
}

function looksLikeSecret(evidence) {
  if (typeof evidence !== "string") return false;
  return /sk-[A-Za-z0-9]{20,}|-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----|(^|["'])(api[_-]?key|secret|password|token)(["']|:)/i.test(evidence);
}

function redactEvidence(evidence) {
  const str = String(evidence);
  if (!looksLikeSecret(str)) return null;
  if (str.length <= 24) return "<redacted>";
  return str.slice(0, 10) + "\u2026<redacted>\u2026" + str.slice(-8);
}

function makeEl(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = text;
  return el;
}

function severityGroupLabel(severity) {
  const label = severity === "informational" ? "Informational" : severity.charAt(0).toUpperCase() + severity.slice(1);
  return label + " (" + severity.toUpperCase() + ")";
}

let uidCounter = 0;
function nextUid() {
  uidCounter += 1;
  return "fi-" + uidCounter;
}

function buildFindingCard(group, index) {
  const b = group.beginner || {};
  const card = makeEl("article", "finding-card");
  card.setAttribute("aria-labelledby", "finding-title-" + index);
  card.style.setProperty("--severity-color", SEVERITY_COLORS[group.severity] || "#30363d");
  const uid = nextUid();

  const top = makeEl("div", "finding-top");
  top.appendChild(makeEl("span", "severity-badge", SEVERITY_TEXT[group.severity] || group.severity || "Note"));
  card.appendChild(top);

  const title = makeEl("h4", "finding-title", b.title || group.title || "Untitled finding");
  title.id = "finding-title-" + index;
  card.appendChild(title);

  if (b.summary) card.appendChild(makeEl("p", "finding-description", b.summary));

  if (b.why_it_matters) {
    const w = makeEl("p", "finding-why");
    w.appendChild(makeEl("strong", null, "Why it matters: "));
    w.appendChild(document.createTextNode(b.why_it_matters));
    card.appendChild(w);
  }
  if (b.recommended_action) {
    const r = makeEl("p", "recommendation");
    r.appendChild(makeEl("strong", null, "What to do: "));
    r.appendChild(document.createTextNode(b.recommended_action));
    card.appendChild(r);
  }

  const locations = Array.isArray(group.locations) ? group.locations : [];
  if (locations.length) {
    const foundWrap = makeEl("div", "finding-locations-block");
    foundWrap.appendChild(makeEl("p", "detail-heading", "Found in:"));
    const locs = makeEl("ul", "finding-locations");
    locations.forEach(function (loc) {
      locs.appendChild(makeEl("li", "finding-location", (loc.file || "?") + (loc.line ? ":" + loc.line : "")));
    });
    foundWrap.appendChild(locs);
    card.appendChild(foundWrap);
  }

  const toggle = makeEl("button", "explain-toggle", "Show advanced details");
  toggle.type = "button";
  toggle.setAttribute("aria-expanded", "false");
  toggle.setAttribute("aria-controls", uid + "-detail");

  const detail = makeEl("div", "finding-detail");
  detail.hidden = true;
  detail.id = uid + "-detail";

  const tech = group.technical || {};
  const techList = makeEl("dl", "tech-list");
  [
    ["Technical name", tech.name || group.title],
    ["Rule", tech.rule_id || group.rule_id],
    ["Severity", tech.severity || group.severity],
    ["Confidence", tech.confidence || group.confidence],
  ].forEach(function (row) {
    if (!row[1]) return;
    const dt = makeEl("dt", null, row[0]);
    const dd = makeEl("dd", null, String(row[1]));
    techList.appendChild(dt);
    techList.appendChild(dd);
  });
  if (locations.length && locations[0].evidence) {
    const dt = makeEl("dt", null, "Evidence");
    const dd = makeEl("dd", null);
    dd.appendChild(makeEl("code", "finding-evidence", locations[0].evidence));
    techList.appendChild(dt);
    techList.appendChild(dd);
  }
  if (group.description) {
    const dt = makeEl("dt", null, "Scanner note");
    const dd = makeEl("dd", null, group.description);
    techList.appendChild(dt);
    techList.appendChild(dd);
  }
  detail.appendChild(techList);

  if (group.ai_fix_prompt) {
    const fixWrap = makeEl("div", "fix-prompt");
    const promptEl = makeEl("pre", "fix-prompt-text", group.ai_fix_prompt);
    promptEl.hidden = true;
    promptEl.id = uid + "-prompt";
    const copyBtn = makeEl("button", "copy-btn", "Copy AI Fix Prompt");
    copyBtn.type = "button";
    copyBtn.hidden = true;
    copyBtn.setAttribute("aria-label", "Copy AI fix prompt for " + (b.title || group.title || "this finding"));
    copyBtn.addEventListener("click", function () {
      copyText(group.ai_fix_prompt, copyBtn);
    });
    const viewBtn = makeEl("button", "explain-toggle", "View AI Fix Prompt");
    viewBtn.type = "button";
    viewBtn.setAttribute("aria-expanded", "false");
    viewBtn.setAttribute("aria-controls", uid + "-prompt");
    viewBtn.addEventListener("click", function () {
      const willShow = promptEl.hidden;
      promptEl.hidden = !willShow;
      copyBtn.hidden = !willShow;
      viewBtn.textContent = willShow ? "Hide AI Fix Prompt" : "View AI Fix Prompt";
      viewBtn.setAttribute("aria-expanded", String(willShow));
    });
    fixWrap.appendChild(viewBtn);
    fixWrap.appendChild(copyBtn);
    fixWrap.appendChild(promptEl);
    detail.appendChild(fixWrap);
  }

  toggle.addEventListener("click", function () {
    const willShow = detail.hidden;
    detail.hidden = !willShow;
    toggle.textContent = willShow ? "Hide advanced details" : "Show advanced details";
    toggle.setAttribute("aria-expanded", String(willShow));
  });
  card.appendChild(toggle);
  card.appendChild(detail);

  return card;
}

function copyText(text, button) {
  const done = function () {
    const original = button.textContent;
    button.textContent = "Copied!";
    button.disabled = true;
    setTimeout(function () {
      button.textContent = original;
      button.disabled = false;
    }, 1600);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(function () {
      fallbackCopy(text, done);
    });
  } else {
    fallbackCopy(text, done);
  }
}

function fallbackCopy(text, onSuccess) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch (err) {
    console.error("Copy fallback failed:", err);
    ok = false;
  }
  document.body.removeChild(ta);
  if (ok) onSuccess();
}

function gradeForScore(score) {
  if (score >= 90) return { label: "LOOKING GOOD", color: GRADE_COLORS.looking };
  if (score >= 75) return { label: "ALMOST READY", color: GRADE_COLORS.almost };
  if (score >= 50) return { label: "REVIEW BEFORE SHIPPING", color: GRADE_COLORS.review };
  if (score >= 25) return { label: "DON'T SHIP YET", color: GRADE_COLORS.dont };
  return { label: "HIGH RISK \u2014 FIX BEFORE SHIPPING", color: GRADE_COLORS.risk };
}

function beginnerLabelForScore(score) {
  if (score >= 90) return "LOOKING GOOD";
  if (score >= 75) return "ALMOST READY";
  if (score >= 50) return "NEEDS ATTENTION";
  return "DON'T SHIP YET";
}

function heroTitleForScore(score) {
  if (score >= 90) return "IS LOOKING GOOD";
  if (score >= 75) return "IS ALMOST READY";
  if (score >= 50) return "NEEDS ATTENTION";
  return "DON'T SHIP YET";
}

function renderResults(result) {
  currentResult = result;
  const score = typeof result.score === "number" ? Math.max(0, Math.min(100, Math.round(result.score))) : null;
  const grade = score === null ? { label: "Unknown", color: "#8b949e" } : gradeForScore(score);

  els.heroTitle.textContent = score === null ? "SCAN RESULTS" : heroTitleForScore(score);

  els.scoreNumber.textContent = score === null ? "--" : String(score);
  els.scoreGrade.textContent = grade.label;
  els.scoreGrade.style.color = grade.color;

  const offset = score === null ? RING_CIRCUMFERENCE : RING_CIRCUMFERENCE * (1 - score / 100);
  els.scoreRing.style.stroke = grade.color;
  els.scoreRing.style.strokeDashoffset = String(RING_CIRCUMFERENCE);
  requestAnimationFrame(function () {
    els.scoreRing.style.strokeDashoffset = String(offset);
  });

  const groups = result.groups || [];
  const actionable = groups.filter(function (g) {
    return g.severity === "critical" || g.severity === "high" || g.severity === "medium";
  });
  if (actionable.length) {
    els.summary.textContent = actionable.length === 1
      ? "1 thing needs your attention before you ship."
      : actionable.length + " things need your attention before you ship.";
  } else {
    els.summary.textContent = "No critical or high-priority issues were detected. Before launching, perform your normal manual testing and review.";
  }

  renderPrioritySummary(groups);
  renderNextStep(groups);
  renderConsolidatedPrompt(groups);
  renderFindings(groups, result);
  renderWhatsAlreadyGood(result, groups);
  renderScanInfo(result);

  els.downloadReport.disabled = !currentScanId && !result.scan_id;
  showView(els.viewResults);
  els.resultsTitle.focus();
}

function renderScanComplete(result) {
  currentResult = result;
  const score = typeof result.score === "number" ? Math.max(0, Math.min(100, Math.round(result.score))) : null;
  const grade = score === null ? { label: "Unknown", color: "#8b949e" } : gradeForScore(score);

  const groups = result.groups || [];
  const actionable = groups.filter(function (g) {
    return g.severity === "critical" || g.severity === "high" || g.severity === "medium";
  });

  els.completeScore.textContent = score === null ? "--" : String(score);
  els.completeGrade.textContent = score === null ? "Pending" : beginnerLabelForScore(score);
  els.completeGrade.style.color = grade.color;

  if (actionable.length) {
    els.completeMessage.textContent = "Your project has been analyzed.";
    els.completeSummary.textContent = actionable.length === 1
      ? "1 thing needs your attention before you ship."
      : actionable.length + " things need your attention before you ship.";
  } else {
    els.completeMessage.textContent = "Your project looks good.";
    els.completeSummary.textContent = "No critical or high-priority issues were detected.";
  }

  const parts = [];
  if (typeof result.application_files === "number") parts.push(result.application_files + " application files checked");
  if (typeof result.ignored_files === "number") parts.push(result.ignored_files + " ignored/generated/vendor files");
  els.completeStats.hidden = !parts.length;
  if (parts.length) els.completeStats.textContent = parts.join(" \u00b7 ");

  const hasDuration = typeof result.duration_ms === "number";
  els.completeDuration.hidden = !hasDuration;
  if (hasDuration) els.completeDuration.textContent = "Scan took " + formatDuration(result.duration_ms);

  els.completeLive.textContent = score === null
    ? "Scan complete. Your results are ready."
    : "Scan complete. Your Ship Score is " + score + ".";

  showView(els.viewScanComplete);
  els.completeTitle.focus();
}

function sectionHeading(label) {
  const h = makeEl("h3", "section-heading", label);
  return h;
}

function collapsibleSection(heading, contentEl, collapsed) {
  const uid = "obs-" + nextUid();
  const wrap = makeEl("div", "obs-section");
  const btn = makeEl("button", "explain-toggle", heading);
  btn.type = "button";
  btn.setAttribute("aria-expanded", "false");
  btn.setAttribute("aria-controls", uid);
  const body = makeEl("div", "obs-body");
  body.id = uid;
  body.hidden = collapsed;
  btn.addEventListener("click", function () {
    const willShow = body.hidden;
    body.hidden = !willShow;
    btn.textContent = heading.replace("Show", willShow ? "Hide" : "Show");
    btn.setAttribute("aria-expanded", String(willShow));
  });
  contentEl.forEach(function (el) { body.appendChild(el); });
  wrap.appendChild(btn);
  wrap.appendChild(body);
  return wrap;
}

function renderFindings(groups, result) {
  els.findingsList.replaceChildren();
  if (!groups.length) {
    els.findingsList.appendChild(makeEl("p", "empty-note", "No issues detected \u2014 clean scan."));
    return;
  }

  const actionable = groups.filter(function (g) {
    return g.severity === "critical" || g.severity === "high" || g.severity === "medium";
  });
  const suggestions = groups.filter(function (g) {
    return !(g.severity === "critical" || g.severity === "high" || g.severity === "medium");
  });

  const fixFirst = actionable.filter(function (g) { return g.severity === "critical"; });
  const review = actionable.filter(function (g) { return g.severity !== "critical"; });

  if (fixFirst.length) {
    els.findingsList.appendChild(sectionHeading("FIX FIRST"));
    fixFirst.forEach(function (g, i) {
      els.findingsList.appendChild(buildFindingCard(g, "ff" + i));
    });
  }
  if (review.length) {
    els.findingsList.appendChild(sectionHeading("REVIEW"));
    review.forEach(function (g, i) {
      els.findingsList.appendChild(buildFindingCard(g, "rv" + i));
    });
  }

  if (suggestions.length) {
    els.findingsList.appendChild(sectionHeading("SUGGESTIONS"));
    const cards = suggestions.map(function (g, i) { return buildFindingCard(g, "sg" + i); });
    els.findingsList.appendChild(collapsibleSection(suggestions.length + " lower-priority suggestion" + (suggestions.length === 1 ? "" : "s") + " \u2014 Show suggestions", cards, true));
  }

  const scan = makeEl("details", "scan-details");
  const scanSummary = makeEl("summary", null, "Scan details");
  scan.appendChild(scanSummary);
  const scanList = makeEl("p", "scan-meta", "");
  const scanParts = [];
  if (typeof result.application_files === "number") scanParts.push(result.application_files + " application files checked");
  if (typeof result.ignored_files === "number") scanParts.push(result.ignored_files + " ignored/generated/vendor files");
  scanList.textContent = scanParts.join(" \u00b7 ") || "";
  scan.appendChild(scanList);
  els.findingsList.appendChild(scan);
}

function renderPrioritySummary(groups) {
  const counts = {};
  PRIORITY_ROWS.forEach(function (row) { counts[row.sev] = 0; });
  groups.forEach(function (g) {
    if (counts[g.severity] !== undefined) counts[g.severity] += 1;
  });
  els.priorityList.replaceChildren();
  const visible = PRIORITY_ROWS.filter(function (row) { return counts[row.sev] > 0; });
  els.prioritySection.hidden = !visible.length;
  visible.forEach(function (row) {
    const line = makeEl("div", "priority-row");
    const dot = makeEl("span", "priority-dot");
    dot.style.backgroundColor = row.color;
    line.appendChild(dot);
    line.appendChild(makeEl("span", "priority-count", String(counts[row.sev])));
    line.appendChild(makeEl("span", "priority-label", row.label));
    els.priorityList.appendChild(line);
  });
}

function renderNextStep(groups) {
  const hasCritical = groups.some(function (g) { return g.severity === "critical"; });
  const hasReview = groups.some(function (g) { return g.severity === "high" || g.severity === "medium"; });
  const hasMinor = groups.some(function (g) { return g.severity === "low" || g.severity === "informational"; });
  els.nextStepSection.hidden = false;
  els.fixWithAi.hidden = true;
  if (hasCritical) {
    els.nextStepText.textContent = "Fix the critical issues first. The remaining items can be reviewed afterward.";
    els.fixWithAi.hidden = false;
  } else if (hasReview) {
    els.nextStepText.textContent = "Review the highlighted issues and fix the ones that matter for your app before you ship.";
    els.fixWithAi.hidden = false;
  } else if (hasMinor) {
    els.nextStepText.textContent = "These are minor suggestions. Review them when you have time.";
  } else {
    els.nextStepText.textContent = "Continue with your normal testing and deployment review.";
  }
}

function buildConsolidatedPrompt(groups) {
  const actionable = groups.filter(function (g) {
    return g.severity === "critical" || g.severity === "high" || g.severity === "medium";
  });
  if (!actionable.length) return null;
  const parts = [];
  parts.push("Ship Safe found " + actionable.length + " issue" + (actionable.length === 1 ? "" : "s") + " worth fixing before you ship.");
  parts.push("");
  parts.push("Instructions:");
  parts.push(CONSOLIDATED_STEPS.join("\n"));
  actionable.forEach(function (g, i) {
    const b = g.beginner || {};
    const loc = (g.locations && g.locations.length)
      ? g.locations[0].file + (g.locations[0].line ? ":" + g.locations[0].line : "")
      : "unknown location";
    parts.push("");
    parts.push((i + 1) + ". " + String(g.severity || "").toUpperCase() + " — " + (b.title || g.title || "Finding"));
    parts.push("   Where: " + loc);
    parts.push("   What happened: " + (b.summary || g.description || ""));
    parts.push("   Why it matters: " + (b.why_it_matters || g.why_it_matters || ""));
    parts.push("   What to do: " + (b.recommended_action || g.recommendation || ""));
    if (g.ai_fix_prompt) parts.push("   Suggested fix: " + g.ai_fix_prompt);
  });
  return parts.join("\n").trim();
}

function renderConsolidatedPrompt(groups) {
  const prompt = buildConsolidatedPrompt(groups);
  els.consolidatedPrompt.hidden = true;
  els.consolidatedCopy.hidden = true;
  els.consolidatedToggle.textContent = "Show AI Fix Prompt";
  els.consolidatedToggle.setAttribute("aria-expanded", "false");
  if (!prompt) {
    els.consolidatedSection.hidden = true;
    return;
  }
  const actionable = groups.filter(function (g) {
    return g.severity === "critical" || g.severity === "high" || g.severity === "medium";
  });
  els.consolidatedSection.hidden = false;
  els.consolidatedIntro.textContent = "Ship Safe found " + actionable.length + " issue" + (actionable.length === 1 ? "" : "s") + " worth fixing before launch. We've combined the relevant findings into one prompt you can paste into your AI coding assistant.";
  els.consolidatedPrompt.textContent = prompt;
  els.consolidatedToggle.onclick = function () {
    const willShow = els.consolidatedPrompt.hidden;
    els.consolidatedPrompt.hidden = !willShow;
    els.consolidatedCopy.hidden = !willShow;
    els.consolidatedToggle.textContent = willShow ? "Hide AI Fix Prompt" : "Show AI Fix Prompt";
    els.consolidatedToggle.setAttribute("aria-expanded", String(willShow));
  };
  els.consolidatedCopy.onclick = function () {
    copyText(prompt, els.consolidatedCopy);
  };
}

function renderWhatsAlreadyGood(result, groups) {
  const groupCats = new Set(groups.map(function (g) { return g.category; }));
  const passed = result.passed || [];
  const rows = [];
  PASSED_LABELS.forEach(function (item) {
    const ran = passed.some(function (rid) { return typeof rid === "string" && rid.indexOf(item.prefix) === 0; });
    if (ran && !groupCats.has(item.category)) rows.push(item.label);
  });
  els.whatsGoodList.replaceChildren();
  els.whatsGoodSection.hidden = !rows.length;
  rows.forEach(function (label) {
    els.whatsGoodList.appendChild(makeEl("span", "passed-chip", label));
  });
}

function renderScanInfo(result) {
  const parts = [];
  if (typeof result.application_files === "number") parts.push(result.application_files.toLocaleString() + " files checked");
  if (typeof result.ignored_files === "number") parts.push(result.ignored_files.toLocaleString() + " ignored/generated/vendor files");
  if (result.summary && typeof result.summary.total_findings === "number") {
    parts.push(result.summary.total_findings + " finding" + (result.summary.total_findings === 1 ? "" : "s"));
  }
  if (typeof result.duration_ms === "number") parts.push(formatDuration(result.duration_ms) + " scan time");
  if (result.project_type && result.project_type !== "unknown") parts.push("Project type: " + result.project_type);
  if (Array.isArray(result.frameworks) && result.frameworks.length) parts.push("Frameworks: " + result.frameworks.join(", "));
  els.scanInfoText.textContent = parts.join(" · ");
  els.scanInfoSection.hidden = !parts.length;
}

function activitySection(entry, isCurrent) {
  const wrap = makeEl("div", "activity-section");
  if (isCurrent) wrap.classList.add("current");
  const p = entry.fields;
  const phase = entry.phase;
  const line = makeEl.bind(null, "div", "activity-line");

  if (phase === "uploading") {
    wrap.appendChild(line("> Uploading your project"));
    if (typeof p.current === "number" && typeof p.total === "number") {
      wrap.appendChild(line("  " + formatBytes(p.current) + " / " + formatBytes(p.total)));
    }
  } else if (phase === "preparing") {
    wrap.appendChild(line("> Preparing your project"));
  } else if (phase === "discovering") {
    wrap.appendChild(line("> Discovering files"));
    if (typeof p.files_discovered === "number") {
      wrap.appendChild(line("  " + p.files_discovered.toLocaleString() + " files found"));
    }
  } else if (phase === "filtering") {
    wrap.appendChild(line("> Filtering files"));
    if (typeof p.files_to_scan === "number") {
      wrap.appendChild(line("  " + p.files_to_scan.toLocaleString() + " files selected"));
    }
  } else if (phase === "scanning") {
    wrap.appendChild(line("> Checking your code"));
    const pct = progressPercent(p);
    if (pct !== null) {
      const filled = Math.round(pct / 5);
      const bar = "\u2588".repeat(filled) + "\u2591".repeat(20 - filled);
      wrap.appendChild(line("  [" + bar + "] " + pct + "%"));
      if (typeof p.current === "number" && typeof p.total === "number") {
        wrap.appendChild(line("  " + p.current.toLocaleString() + " / " + p.total.toLocaleString() + " files"));
      }
    }
    if (p.current_file) {
      const fileLine = line("  \u2514\u2500 " + p.current_file);
      fileLine.classList.add("activity-file");
      wrap.appendChild(fileLine);
    }
    if (typeof p.findings_found === "number" && p.findings_found > 0) {
      const findLine = line("  " + p.findings_found + " finding" + (p.findings_found === 1 ? "" : "s") + " found so far");
      findLine.classList.add("activity-findings");
      wrap.appendChild(findLine);
    }
  } else if (phase === "reviewing") {
    wrap.appendChild(line("> Reviewing findings"));
    if (typeof p.findings_found === "number") {
      wrap.appendChild(line("  " + p.findings_found + " finding" + (p.findings_found === 1 ? "" : "s")));
    }
  } else if (phase === "building_report") {
    wrap.appendChild(line("> Preparing your report"));
  } else if (phase === "complete") {
    const okLine = line("\u2713 Scan complete");
    okLine.classList.add("activity-ok");
    wrap.appendChild(okLine);
    const stats = [];
    if (typeof p.files_analyzed === "number") stats.push(p.files_analyzed + " files checked");
    if (typeof p.findings_found === "number") stats.push(p.findings_found + " finding" + (p.findings_found === 1 ? "" : "s"));
    if (stats.length) wrap.appendChild(line("  " + stats.join(" \u00b7 ")));
  } else if (phase === "error") {
    const errLine = line("\u2715 Scan failed");
    errLine.classList.add("activity-error");
    wrap.appendChild(errLine);
    if (p.error) wrap.appendChild(line("  " + p.error));
  }
  return wrap;
}

function renderActivity() {
  els.progressActivity.replaceChildren();
  activityEntries.forEach(function (entry) {
    els.progressActivity.appendChild(activitySection(entry, false));
  });
  if (activityCurrent) {
    els.progressActivity.appendChild(activitySection(activityCurrent, true));
  }
}

function pushActivity(p) {
  if (!activityCurrent || activityCurrent.phase !== p.phase) {
    if (activityCurrent) activityEntries.push(activityCurrent);
    activityCurrent = { phase: p.phase, fields: p };
  } else {
    activityCurrent.fields = p;
  }
  renderActivity();
}

function resetProgressUi() {
  lastAnnouncedPhase = null;
  lastAnnouncedMessage = null;
  activityEntries = [];
  activityCurrent = null;
  els.progressMessage.textContent = "We're looking for things that could cause problems after launch.";
  els.progressMessage.hidden = false;
  els.progressFileStats.hidden = true;
  els.progressError.hidden = true;
  els.progressActions.hidden = true;
  els.progressActivity.replaceChildren();
}

function progressPercent(p) {
  if (typeof p.total === "number" && p.total > 0 && typeof p.current === "number" && p.current >= 0) {
    return Math.min(100, Math.round((p.current / p.total) * 100));
  }
  return null;
}

function renderProgress(p) {
  const title = PHASE_TITLES[p.phase] || p.message || "Checking your app";
  if (title !== lastAnnouncedPhase) {
    els.progressTitle.textContent = title;
    lastAnnouncedPhase = title;
  }
  const phaseMessage = PHASE_MESSAGES[p.phase];
  if (phaseMessage && phaseMessage !== lastAnnouncedMessage) {
    els.progressMessage.textContent = phaseMessage;
    lastAnnouncedMessage = phaseMessage;
  }
  els.progressMessage.hidden = p.phase === "uploading";

  pushActivity(p);

  const stats = [];
  if (typeof p.files_to_scan === "number") stats.push(p.files_to_scan.toLocaleString() + " application files");
  if (typeof p.files_skipped === "number") stats.push(p.files_skipped.toLocaleString() + " files skipped");
  els.progressFileStats.hidden = !stats.length;
  if (stats.length) els.progressFileStats.textContent = stats.join(" \u00b7 ");
}

function renderError(message) {
  pushActivity({ phase: "error", error: message || "The scan could not be completed." });
  els.progressError.textContent = message || "The scan could not be completed.";
  els.progressError.hidden = false;
  els.progressActions.hidden = false;
}

function delay(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function fetchScanStatus(scanId) {
  const res = await fetch("/api/scans/" + encodeURIComponent(scanId));
  let body = null;
  try {
    body = await res.json();
  } catch (err) {
    throw new Error("Failed to read scan status (server returned invalid JSON).");
  }
  if (!res.ok) {
    const detail = body && body.detail ? (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)) : "Status request failed.";
    throw new Error(detail);
  }
  return body;
}

async function pollScan(scanId) {
  let transportErrors = 0;
  for (;;) {
    await delay(POLL_INTERVAL_MS);
    let data;
    try {
      data = await fetchScanStatus(scanId);
      transportErrors = 0;
    } catch (err) {
      transportErrors += 1;
      if (transportErrors >= MAX_POLL_ERRORS) {
        renderError("Lost connection to the scan. Check your network and try again.");
        return;
      }
      continue;
    }
    const status = data.status ? String(data.status).toLowerCase() : null;
    if (status === "complete" || status === "completed" || status === "done") {
      if (data.result) {
        currentResult = data.result;
        renderScanComplete(data.result);
      } else if (typeof data.score === "number") {
        currentResult = data;
        renderScanComplete(data);
      } else {
        renderError("Scan finished but no result payload was returned.");
      }
      return;
    }
    if (status === "error" || status === "failed") {
      renderError(data.error || data.message || "The scan failed.");
      return;
    }
    if (data.progress) renderProgress(data.progress);
  }
}

function uploadScan(file, onProgress, onDone, onError) {
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/scans");
  xhr.upload.addEventListener("progress", function (e) {
    if (e.lengthComputable && onProgress) onProgress(e.loaded, e.total);
  });
  xhr.addEventListener("load", function () {
    let body = null;
    try {
      body = JSON.parse(xhr.responseText);
    } catch (err) { /* ignore */ }
    if (xhr.status >= 200 && xhr.status < 300) {
      if (onDone) onDone(body);
      return;
    }
    const detail = body && body.detail ? (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)) : "Request failed with status " + xhr.status + ".";
    if (onError) onError(new Error(detail));
  });
  xhr.addEventListener("error", function () {
    if (onError) onError(new Error("Upload failed. Check your connection and try again."));
  });
  const formData = new FormData();
  formData.append("file", file);
  xhr.send(formData);
}

function runScan(file) {
  setError(null);
  showView(els.viewProgress);
  currentScanId = null;
  currentResult = null;
  resetProgressUi();
  renderProgress({ phase: "uploading", message: "Uploading your project", uploaded: true, total: file.size, current: 0 });
  uploadScan(file, function (loaded, total) {
    renderProgress({ phase: "uploading", message: "Uploading your project", uploaded: true, current: loaded, total: total });
  }, function (body) {
    if (body && body.scan_id) {
      currentScanId = body.scan_id;
      pollScan(body.scan_id);
    } else {
      renderError("The server returned an unexpected response.");
    }
  }, function (err) {
    console.error("Upload failed:", err);
    renderError(err.message || "Upload failed.");
  });
}

function validateFile(file) {
  if (!file) return "No file selected.";
  const isZip = /\.zip$/i.test(file.name) || file.type === "application/zip" || file.type === "application/x-zip-compressed";
  if (!isZip) return "Unsupported file type. Please upload a .zip archive.";
  if (file.size > MAX_FILE_SIZE) {
    return "File is too large. Maximum size is " + formatBytes(MAX_FILE_SIZE) + ".";
  }
  return null;
}

function selectFile(file) {
  const err = validateFile(file);
  setError(err);
  if (err) {
    selectedFile = null;
    els.fileInfo.hidden = true;
    els.uploadButton.disabled = true;
    return;
  }
  selectedFile = file;
  els.fileInfo.textContent = file.name + " \u00b7 " + formatBytes(file.size);
  els.fileInfo.hidden = false;
  els.uploadButton.disabled = false;
}

function openFileDialog() {
  els.fileInput.click();
}

function resetUpload() {
  selectedFile = null;
  currentScanId = null;
  currentResult = null;
  els.fileInput.value = "";
  els.fileInfo.hidden = true;
  els.uploadButton.disabled = true;
  setError(null);
}

function buildReportHtml(data) {
  const findingsHtml = (data.findings || []).map(function (f) {
    return "<article style=\"border:1px solid #30363d;border-radius:8px;padding:14px;margin:0 0 12px\">"
      + "<p style=\"margin:0 0 4px\"><strong style=\"text-transform:uppercase\">" + escapeHtml(f.severity || "unknown") + "</strong>"
      + (f.confidence !== undefined ? " &nbsp;<span style=\"color:#8b949e\">confidence " + escapeHtml(String(f.confidence)) + "%</span>" : "")
      + (f.rule_id ? " &nbsp;<code style=\"color:#8b949e\">" + escapeHtml(f.rule_id) + "</code>" : "") + "</p>"
      + "<h4 style=\"margin:0 0 4px\">" + escapeHtml(f.title || "Finding") + "</h4>"
      + (f.file ? "<p style=\"margin:0 0 6px;color:#38bdf8\">" + escapeHtml(f.file + (f.line ? ":" + f.line : "")) + "</p>" : "")
      + (f.description ? "<p style=\"margin:0 0 6px\">" + escapeHtml(f.description) + "</p>" : "")
      + (f.evidence ? "<pre style=\"background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-all\">" + escapeHtml(redactEvidence(f.evidence) || f.evidence) + "</pre>" : "")
      + (f.recommendation ? "<p style=\"margin:6px 0 0\"><strong>Recommendation:</strong> " + escapeHtml(f.recommendation) + "</p>" : "")
      + (f.ai_fix_prompt ? "<pre style=\"background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-all;margin:8px 0 0\"><strong>AI Fix Prompt:</strong>\n" + escapeHtml(f.ai_fix_prompt) + "</pre>" : "")
      + "</article>";
  }).join("");

  const passedHtml = (data.passed || []).map(function (item) {
    const name = typeof item === "string" ? item : item.name || item.title || item.rule_id || "Passed check";
    return "<span style=\"color:#3fb950;font-family:monospace\">\u2713 " + escapeHtml(name) + "</span>";
  }).join(" ");

  const summary = "Project type: " + escapeHtml(String(data.project_type || "unknown"))
    + " | Frameworks: " + escapeHtml((data.frameworks || []).join(", ") || "none")
    + " | Files scanned: " + escapeHtml(String(data.files_scanned || 0))
    + " | Duration: " + escapeHtml(formatDuration(data.duration_ms));

  const grade = gradeForScore(data.score);
  const gradeColor = grade.color;

  return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
    + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    + "<title>Ship Safe Report</title>\n</head>\n"
    + "<body style=\"background:#0d1117;color:#e6edf3;font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;max-width:820px;margin:0 auto;padding:32px 20px\">\n"
    + "<header><h1 style=\"font-family:monospace\">Ship Safe &mdash; Before You Ship</h1>\n"
    + "<p style=\"font-family:monospace;color:#8b949e\">Generated report for vibe-coded app pre-flight scan.</p></header>\n"
    + "<section style=\"background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;margin:20px 0\">\n"
    + "<div style=\"display:flex;align-items:baseline;gap:16px\"><span style=\"font-size:56px;font-family:monospace;font-weight:700;color:" + gradeColor + "\">" + escapeHtml(String(data.score)) + "</span>"
    + "<span style=\"font-family:monospace;text-transform:uppercase;color:#8b949e\">" + escapeHtml(grade.label) + "</span></div>\n"
    + "<p style=\"color:#8b949e\">" + summary + "</p></section>\n"
    + "<h2 style=\"font-family:monospace;text-transform:uppercase;font-size:14px;color:#8b949e;border-bottom:1px solid #30363d;padding-bottom:8px\">Findings</h2>\n"
    + (data.findings && data.findings.length ? findingsHtml : "<p>No findings &mdash; clean scan.</p>")
    + "<h2 style=\"font-family:monospace;text-transform:uppercase;font-size:14px;color:#8b949e;border-bottom:1px solid #30363d;padding-bottom:8px\">Passed Checks</h2>\n"
    + (data.passed && data.passed.length ? "<p>" + passedHtml + "</p>" : "<p>None recorded.</p>")
    + "</body>\n</html>";
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

async function downloadReport() {
  const id = currentScanId;
  if (!id) return;
  els.downloadReport.disabled = true;
  const original = els.downloadReport.textContent;
  els.downloadReport.textContent = "Preparing\u2026";
  try {
    const res = await fetch("/api/scans/" + encodeURIComponent(id) + "/report");
    if (!res.ok) {
      let msg = "Report request failed.";
      try {
        const body = await res.json();
        if (body && body.detail) msg = String(body.detail);
      } catch (err) { /* ignore */ }
      throw new Error(msg);
    }
    const contentType = res.headers.get("content-type") || "";
    let blob;
    if (/html/.test(contentType)) {
      blob = await res.blob();
    } else {
      const reportJson = await res.json();
      blob = new Blob([buildReportHtml(reportJson)], { type: "text/html;charset=utf-8" });
    }
    saveBlob(blob, "ship-safe-report-" + id + ".html");
  } catch (err) {
    console.error("Report download failed:", err);
    alert("Failed to download report: " + err.message);
  } finally {
    els.downloadReport.textContent = original;
    els.downloadReport.disabled = false;
  }
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function () {
    URL.revokeObjectURL(url);
  }, 2000);
}

els.ctaScan.addEventListener("click", function () {
  resetUpload();
  showView(els.viewUpload);
});

els.dropzone.addEventListener("click", openFileDialog);
els.dropzone.addEventListener("keydown", function (e) {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    openFileDialog();
  }
});

["dragenter", "dragover"].forEach(function (name) {
  els.dropzone.addEventListener(name, function (e) {
    e.preventDefault();
    els.dropzone.classList.add("drag-over");
  });
});

["dragleave", "drop"].forEach(function (name) {
  els.dropzone.addEventListener(name, function (e) {
    e.preventDefault();
    els.dropzone.classList.remove("drag-over");
  });
});

els.dropzone.addEventListener("drop", function (e) {
  const files = e.dataTransfer && e.dataTransfer.files;
  if (files && files.length) selectFile(files[0]);
});

els.fileInput.addEventListener("change", function () {
  if (els.fileInput.files && els.fileInput.files.length) {
    selectFile(els.fileInput.files[0]);
  }
});

els.uploadButton.addEventListener("click", function () {
  if (selectedFile) runScan(selectedFile);
});

els.scanAgain.addEventListener("click", function () {
  resetUpload();
  showView(els.viewUpload);
});

els.reviewReport.addEventListener("click", function () {
  if (currentResult) renderResults(currentResult);
});

els.scanAgainComplete.addEventListener("click", function () {
  resetUpload();
  showView(els.viewUpload);
});

els.progressRetry.addEventListener("click", function () {
  resetUpload();
  showView(els.viewUpload);
});

els.downloadReport.addEventListener("click", downloadReport);

els.fixWithAi.addEventListener("click", function () {
  els.consolidatedSection.hidden = false;
  els.consolidatedSection.scrollIntoView({ behavior: "smooth", block: "start" });
});

showView(els.viewLanding);
