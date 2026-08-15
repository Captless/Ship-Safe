# Ship Safe — Product Requirements Document (PRD)

> Status: Draft · Version: 1.0 · Date: 2026-08-15
> Source of truth: `plan.md`

---

## 1. Product Overview

### 1.1 Name

**Ship Safe**

### 1.2 Positioning

> "The pre-flight scanner for vibe-coded apps."

### 1.3 Core Promise

Help beginners and non-security-specialist developers identify common security, configuration, authentication, database, API, payment, and deployment-readiness problems in applications built with AI coding tools **before** they deploy them publicly.

### 1.4 Product One-Liner

> "I vibe-coded this app. What should I check before I ship it?"

---

## 2. Target Users

| Segment | Description |
|---------|-------------|
| Beginner vibe coders | New developers relying heavily on AI tools |
| Indie hackers | Solo builders shipping quickly |
| AI-assisted developers | Developers using AI daily in workflows |
| Claude Code users | AI pair-programming tool |
| Cursor users | AI IDE |
| OpenCode users | AI CLI agent |
| Lovable users | AI app builder |
| Bolt users | AI app builder |
| Replit users | Online IDE with AI |
| Small freelance developers | Client work, tight timelines |
| Solo SaaS builders | One-person startups |
| Non-security-specialist developers | Developers without formal security training |

---

## 3. Non-Goals

The product is **NOT** intended to replace:

- Professional penetration testing
- Formal security audits
- SAST platforms (SonarQube, Semgrep, Snyk, etc.)
- Security engineers

The product provides a **pragmatic pre-launch sanity check** specifically optimized for AI-built applications.

---

## 4. Core Product Experience

### 4.1 Primary V1 Flow

```
Landing page
→ Upload project ZIP
→ Static scan
→ Progress indicator
→ Results
    → Ship Score
    → Findings
    → Detailed explanation
    → Recommended remediation
    → Copyable AI fix prompt
    → Download/shareable report
```

### 4.2 Hard Constraints

- **MUST NOT** execute user-submitted application code.
- Uploaded projects must be treated as **hostile input**.
- V1 uses **static analysis only**.

---

## 5. The Seven Questions Every Finding Answers

The report must be understandable to a beginner. Every finding answers:

1. **What is wrong?**
2. **Where is it?**
3. **Why does it matter?**
4. **How serious is it?**
5. **How confident are we?**
6. **What should I do?**
7. **What can I ask my AI coding agent to do?**

Findings provide both a **technical explanation** and a **simplified (beginner) explanation** where useful.

---

## 6. Ship Score

### 6.1 Model

Transparent heuristic score. **Not** a formal security rating.

| Severity | Penalty |
|----------|---------|
| Critical | -20 |
| High | -12 |
| Medium | -6 |
| Low | -2 |
| Informational | 0 |

Normalized to **0–100**.

### 6.2 Score Interpretation

| Range | Interpretation |
|-------|----------------|
| 80–100 | "Good — perform a final review before shipping." |
| 60–79 | "Review recommended before shipping." |
| 40–59 | "Significant issues detected." |
| 0–39 | "Do not ship yet." |

### 6.3 Scoring Rules

The score accounts for:

- Severity
- Confidence
- Duplicate findings
- Potentially related findings

**Dozens of informational findings must NOT destroy the score.**

---

## 7. Report UX

### 7.1 Beginner-Friendly Explanations

Each finding must include:

- Technical explanation
- Simplified (beginner) explanation

**Example:**

> **Technical:** "Potential missing resource-level authorization check."
>
> **Beginner:** "Your app appears to check whether someone is logged in, but it may not verify whether that person is allowed to access the specific record they requested."

### 7.2 AI Fix Prompts

Generated prompts are safe, copyable, and instruct the coding agent to:

- inspect the relevant files
- explain the proposed fix
- modify only necessary files
- avoid unrelated refactoring
- preserve existing functionality
- add or update tests
- verify the fix
- summarize changes

**V1 constraint:** The scanner does **NOT** automatically modify the user's uploaded project. It is advisory only.

---

## 8. Frontend Requirements

### 8.1 Main Page

Must immediately communicate:

> **"Before You Ship"**
>
> "Scan your vibe-coded app before you deploy it."

Supported examples: Claude Code · Cursor · OpenCode · Lovable · Bolt · Replit

**Primary CTA:** "Scan My Project"

### 8.2 Upload UI Must Explain

- ZIP supported
- Static analysis (no execution)
- Source code is not executed
- Scan limitations

### 8.3 Results Page Priority

1. Ship Score
2. Critical findings
3. Warnings
4. Passed checks
5. Categories
6. Detailed findings

### 8.4 Design Guidelines

- Clean, modern, developer-focused
- Avoid excessive animations
- Avoid dashboard complexity
- Feels like a serious developer utility, not a generic AI SaaS template
- Mobile-friendly
- Graceful frontend errors

### 8.5 Accessibility

- Keyboard navigation
- Readable contrast
- Semantic HTML
- Responsive layout
- Clear focus states
- Useful error messages

---

## 9. Data Handling & Privacy

- Uploaded source code is **temporary**.
- Lifecycle: Upload → temporary isolated workspace → scan → generate findings → **delete uploaded source**.
- Do not persist source code unless explicitly required later.
- If scan history is introduced later: store metadata/results, not raw source, by default.
- Be explicit in the UI about data handling.
- **Never** make a privacy claim the implementation does not actually satisfy.
- Never log secrets.
- Never expose raw uploaded source code in error messages.

---

## 10. Monetization Design (Future)

### 10.1 V1 Constraint

**Do NOT implement billing in the initial MVP.**

### 10.2 Architecture Intent

| Tier | Features |
|------|----------|
| Free | Limited scans |
| Paid | Unlimited scans, full reports, scan history, advanced checks, AI explanations, downloadable reports |

### 10.3 Potential Future Models

- One-time lifetime license
- Pro subscription
- CLI license
- Team plans

**Do not build billing until the scanner is validated with real users.**

---

## 11. Definition of Done (MVP Complete)

The MVP is complete only when a user can:

1. Open the web application.
2. Understand what the product does.
3. Upload a valid project ZIP.
4. Receive safe scan processing.
5. See a progress state.
6. Receive structured findings.
7. See a Ship Score.
8. Understand critical findings.
9. See affected files/locations.
10. Read beginner-friendly explanations.
11. Copy an AI fix prompt.
12. Download or view a report.
13. Encounter graceful errors for invalid uploads.
14. Be protected against malicious ZIP extraction.
15. Have uploaded source cleaned up after scanning.
16. Run the application locally using documented commands.
17. Build and run the application through Docker.
18. Run the complete automated test suite successfully.

---

## 12. Success Criteria (Non-Functional)

- Clear error handling
- Structured logging
- No secrets in logs
- Input validation
- Upload size limits
- Scan timeout
- Safe temporary file handling
- Health endpoint
- Docker support
- Reproducible local setup
- Automated tests
- Clean README
- Environment variable configuration
- No hardcoded credentials
- Graceful frontend errors
- Mobile-friendly UI

---

## 13. Roadmap

| Version | Features |
|---------|----------|
| **V1 (current)** | Web upload → static scan → report |
| **V2** | CLI, GitHub repository scanning, scan history, accounts |
| **V3** | VS Code extension, CI/CD integration, pull request scanning, deployment checks |
| **V4** | Framework-specific advanced rules, AI-assisted explanations, automatic fix suggestions, team reports |

**Do not implement roadmap features prematurely.**

---

## 14. Related Documents

- [ARCHITECTURE.md](./ARCHITECTURE.md)
- [DETECTION-RULES.md](./DETECTION-RULES.md)
- [THREAT-MODEL.md](./THREAT-MODEL.md)
- [MVP-PLAN.md](./MVP-PLAN.md)
- [TEST-PLAN.md](./TEST-PLAN.md)
