You are the senior software architect and lead engineer responsible for building a production-ready MVP called "Before You Ship".

PRODUCT
=======

Name:
Ship Safe

Positioning:
"The pre-flight scanner for vibe-coded apps."

Core promise:
Help beginners and non-security-specialist developers identify common security, configuration, authentication, database, API, payment, and deployment-readiness problems in applications built with AI coding tools before they deploy them publicly.

Target users:
- Beginner vibe coders
- Indie hackers
- AI-assisted developers
- People using Claude Code
- Cursor users
- OpenCode users
- Lovable users
- Bolt users
- Replit users
- Small freelance developers
- Solo SaaS builders

The product is NOT intended to replace professional penetration testing, security audits, SAST platforms, or security engineers.

The product provides a pragmatic pre-launch sanity check specifically optimized for AI-built applications.

CORE PRODUCT EXPERIENCE
=======================

The primary V1 flow is:

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

The scanner MUST NOT execute user-submitted application code.

Uploaded projects must be treated as hostile input.

V1 must use static analysis only.

ARCHITECTURAL PRINCIPLE
=======================

The scanner engine must be independent from the web application.

The architecture must allow the same scanner engine to eventually power:

1. Web SaaS
2. CLI
3. VS Code extension
4. CI/CD integration

Do NOT tightly couple detection rules to HTTP routes or frontend code.

Recommended conceptual architecture:

before-you-ship/
    scanner/
        core/
        rules/
        analyzers/
        models/
        scoring/
        reporting/

    backend/
        api/
        services/
        workers/

    frontend/

    tests/

    docs/

The exact structure may be improved during planning if a better architecture is justified.

TECHNOLOGY
==========

Use:

Backend:
- Python 3
- FastAPI

Frontend:
- Vanilla HTML
- Vanilla CSS
- Vanilla JavaScript
- No frontend framework unless there is a compelling technical reason

Database:
- PostgreSQL-compatible architecture
- Supabase may be used later
- V1 should minimize database dependence

Infrastructure:
- Docker
- Docker Compose for local development
- GitHub
- Deployment should remain portable between free/low-cost hosting providers

Do not introduce unnecessary infrastructure.

Avoid microservices.

Avoid Redis unless a concrete requirement appears.

Avoid message queues unless a concrete requirement appears.

Avoid Kubernetes.

Avoid unnecessary dependencies.

FREE-FIRST CONSTRAINT
=====================

The entire MVP must be developable and testable without paid APIs.

The core scanner MUST NOT require an LLM.

AI functionality is optional and secondary.

The deterministic scanner must work without external AI APIs.

If AI explanation functionality is implemented, isolate it behind a provider interface so it can later support different providers.

Do not hardcode a specific paid AI provider into the scanner engine.

SCANNER DESIGN
==============

Create a rule-based static analysis engine.

Each rule should have a consistent structure containing conceptually:

- rule_id
- title
- category
- severity
- confidence
- description
- detection logic
- evidence
- explanation
- recommendation
- remediation guidance
- AI fix prompt template

Rules must produce structured findings.

Example conceptual finding:

{
    "rule_id": "SECRET-001",
    "severity": "critical",
    "confidence": "high",
    "category": "secrets",
    "title": "Potential hardcoded API credential",
    "file": "src/config/api.js",
    "line": 14,
    "evidence": "...",
    "description": "...",
    "why_it_matters": "...",
    "recommendation": "...",
    "ai_fix_prompt": "..."
}

Do not expose sensitive secret values in reports.

Evidence should be redacted where necessary.

INITIAL DETECTION CATEGORIES
============================

Build V1 around high-confidence, practical checks.

1. SECRETS

Potential detection for:
- API keys
- cloud credentials
- private keys
- database credentials
- access tokens
- AI provider keys
- Stripe secret keys
- suspicious credential patterns

Also inspect:
- .env files
- committed environment files
- configuration files
- frontend source
- Git metadata where available

Never print full secrets.

2. GIT

Check for:
- tracked .env files
- obvious secret files
- sensitive configuration committed to repository
- suspicious credential artifacts

Do not modify the uploaded project.

3. CONFIGURATION

Check for indicators such as:
- DEBUG=true
- development configuration
- localhost production references
- wildcard CORS
- development/test credentials
- verbose error configuration
- unsafe production defaults

4. DATABASE

Framework-aware where possible.

Initial focus:
- Supabase
- Firebase
- PostgreSQL-related patterns
- Prisma
- SQL query patterns

Potential checks:
- missing RLS indicators
- unsafe Supabase usage
- service-role keys exposed client-side
- suspicious database policies
- unsafe query construction

Do not claim that static analysis proves a database is secure or insecure.

Use language such as:
"Potential issue detected"
when appropriate.

5. AUTHENTICATION AND AUTHORIZATION

Look for:
- unprotected API routes
- missing obvious auth middleware
- suspicious resource access patterns
- client-controlled authorization state
- insecure token handling indicators

Do not claim that static analysis can completely verify authorization correctness.

Use confidence levels.

6. API SECURITY

Look for:
- unauthenticated sensitive endpoints
- dangerous admin endpoints
- unrestricted methods
- wildcard CORS
- missing obvious rate limiting indicators
- exposed debug endpoints
- client-side secrets

7. PAYMENTS

Initial focus:
- Stripe

Check for:
- secret key exposure
- suspicious webhook handling
- missing obvious signature verification
- client-controlled price
- client-controlled subscription state

8. DANGEROUS CODE PATTERNS

Look for obvious static indicators of:
- eval
- unsafe shell execution
- command injection patterns
- unsafe SQL string construction
- path traversal indicators
- unsafe file handling
- dangerous redirects
- obvious XSS patterns

Detection must favor high-confidence findings over aggressive false positives.

9. DEPENDENCIES

Where practical, identify:
- dependency manifests
- package managers
- suspicious/outdated dependency patterns

Do not claim current vulnerability status unless the vulnerability data is actually current.

Do not build a fake vulnerability database.

If a reliable local vulnerability database is not available, clearly label dependency checks as limited.

10. DEPLOYMENT READINESS

Check for indicators such as:
- production configuration
- environment variables
- localhost references
- debug configuration
- missing obvious error handling
- missing obvious health endpoint where applicable

SHIP SCORE
==========

Create a transparent heuristic score.

The score must NOT claim to be a formal security rating.

Suggested conceptual severity penalties:

Critical: -20
High: -12
Medium: -6
Low: -2
Informational: 0

Normalize to 0-100.

Suggested interpretation:

80-100:
"Good — perform a final review before shipping."

60-79:
"Review recommended before shipping."

40-59:
"Significant issues detected."

0-39:
"Do not ship yet."

The exact scoring model may be improved during implementation.

The score should account for:
- severity
- confidence
- duplicate findings
- potentially related findings

Do not allow dozens of informational findings to destroy the score.

REPORT UX
=========

The report must be understandable to a beginner.

Every finding should answer:

1. What is wrong?
2. Where is it?
3. Why does it matter?
4. How serious is it?
5. How confident are we?
6. What should I do?
7. What can I ask my AI coding agent to do?

Use beginner-friendly explanations.

Provide a technical explanation and a simplified explanation where useful.

Example:

Technical:
"Potential missing resource-level authorization check."

Beginner:
"Your app appears to check whether someone is logged in, but it may not verify whether that person is allowed to access the specific record they requested."

AI FIX PROMPTS
==============

Generate safe, copyable prompts.

Prompts MUST instruct the coding agent to:

- inspect the relevant files
- explain the proposed fix
- modify only necessary files
- avoid unrelated refactoring
- preserve existing functionality
- add or update tests
- verify the fix
- summarize changes

Do not automatically modify the user's uploaded project in V1.

The scanner is advisory.

SECURITY OF THE SCANNER ITSELF
==============================

This is a critical requirement.

Uploaded repositories are untrusted.

NEVER execute user application code.

NEVER:
- run npm install on uploaded projects
- run pip install from uploaded projects
- run arbitrary build scripts
- run project startup commands
- execute package lifecycle scripts
- import arbitrary user Python modules
- execute uploaded binaries

Static analysis only.

Implement safeguards for:
- ZIP path traversal
- ZIP bombs
- extremely large files
- excessive file count
- recursive archive attacks
- symlinks where applicable
- scan timeouts
- memory limits
- temporary file cleanup

Do not trust filenames or file extensions.

Do not log secrets.

Do not expose raw uploaded source code in error messages.

TEMPORARY FILE HANDLING
=======================

Uploaded source code should be treated as temporary.

The intended lifecycle:

Upload
→ temporary isolated workspace
→ scan
→ generate findings
→ delete uploaded source

Do not persist source code unless explicitly required later.

If persistent scan history is introduced later, store metadata/results rather than raw source by default.

Be explicit in the UI about data handling, but NEVER make a privacy claim that the implementation does not actually satisfy.

API DESIGN
==========

Keep the backend API simple.

Conceptual endpoints:

GET /health

POST /api/scans

GET /api/scans/{scan_id}

GET /api/scans/{scan_id}/report

Potential future endpoints:

POST /api/explain
POST /api/github/connect
POST /api/auth
POST /api/billing

Do not implement future endpoints until required.

SCAN PROCESSING
===============

The scanner should be capable of:

1. Accepting ZIP upload
2. Validating the upload
3. Extracting safely
4. Detecting project type/framework
5. Running relevant rules
6. Aggregating findings
7. Deduplicating findings
8. Calculating score
9. Producing structured JSON results
10. Rendering the report

For long-running scans, design the code so synchronous scanning can later be replaced with background processing.

Do not introduce a queue unless actually necessary for V1.

PROJECT DETECTION
=================

Detect common project types where practical:

- Node.js
- React
- Next.js
- Vue
- Vite
- Express
- Python
- FastAPI
- Flask
- Django
- PHP
- Laravel

Also detect:
- Supabase
- Firebase
- Prisma
- Stripe
- common AI SDKs/providers

Framework detection should influence which rules are executed.

Do not pretend to understand frameworks that cannot be reliably detected.

FALSE POSITIVE CONTROL
======================

False positives are a major product risk.

Prioritize:
- high confidence
- useful evidence
- actionable findings

Every rule should include tests for:
- true positive
- true negative
- edge case

Where confidence is uncertain, classify the result as a warning rather than critical.

TESTING
=======

Testing is mandatory.

Create:
- unit tests for rules
- scanner integration tests
- ZIP safety tests
- scoring tests
- API tests
- report rendering tests where practical

Build fixture projects containing intentionally vulnerable examples.

Also create clean fixture projects.

Tests must verify that:
- expected issues are detected
- clean projects do not generate excessive false positives
- secrets are redacted
- malicious ZIP paths cannot escape the workspace
- scanner does not execute uploaded code

QUALITY REQUIREMENTS
====================

Production-ready MVP requirements:

- clear error handling
- structured logging
- no secrets in logs
- input validation
- upload size limits
- scan timeout
- safe temporary file handling
- health endpoint
- Docker support
- reproducible local setup
- automated tests
- clean README
- environment variable configuration
- no hardcoded credentials
- graceful frontend errors
- mobile-friendly UI

FRONTEND
========

Create a clean, modern, developer-focused interface.

The main page should immediately communicate:

"Before You Ship"

"Scan your vibe-coded app before you deploy it."

Supported examples:
Claude Code · Cursor · OpenCode · Lovable · Bolt · Replit

Primary CTA:
"Scan My Project"

Upload UI should explain:
- ZIP supported
- static analysis
- source code is not executed
- scan limitations

Results page should prioritize:
1. Ship Score
2. Critical findings
3. Warnings
4. Passed checks
5. Categories
6. Detailed findings

Avoid excessive animations.

Avoid dashboard complexity.

The product should feel like a serious developer utility rather than a generic AI SaaS template.

ACCESSIBILITY
=============

Support:
- keyboard navigation
- readable contrast
- semantic HTML
- responsive layout
- clear focus states
- useful error messages

MONETIZATION
============

Do NOT implement billing in the initial MVP.

Design the architecture so monetization can later support:

Free:
- limited scans

Paid:
- unlimited scans
- full reports
- scan history
- advanced checks
- AI explanations
- downloadable reports

Potential future:
- one-time lifetime license
- Pro subscription
- CLI license
- team plans

Do not build billing until the scanner has been validated with real users.

CLI FUTURE
==========

The scanner engine must eventually support:

before-you-ship scan .

The CLI should use the exact same rule engine.

Do not build the CLI during the initial MVP unless it requires minimal effort and does not slow down the web product.

FUTURE ROADMAP
==============

Possible later features:

V2:
- CLI
- GitHub repository scanning
- scan history
- accounts

V3:
- VS Code extension
- CI/CD integration
- pull request scanning
- deployment checks

V4:
- framework-specific advanced rules
- AI-assisted explanations
- automatic fix suggestions
- team reports

Do not implement roadmap features prematurely.

DEVELOPMENT WORKFLOW
====================

You MUST follow this workflow:

PHASE 1 — PLAN

Before writing implementation code:
- inspect the repository
- inspect existing files
- identify constraints
- produce architecture
- identify dependencies
- define milestones
- define tests
- identify risks

Do not immediately start coding.

PHASE 2 — IMPLEMENT CORE

Build scanner models, rule registry, scanner engine, findings, scoring, and tests.

PHASE 3 — IMPLEMENT SECURITY

Implement safe ZIP extraction, limits, temporary workspaces, and input validation.

PHASE 4 — IMPLEMENT API

Create the minimal FastAPI API.

PHASE 5 — IMPLEMENT FRONTEND

Build upload → progress → results.

PHASE 6 — INTEGRATION TESTING

Test the complete scan flow.

PHASE 7 — HARDENING

Review:
- security
- false positives
- error handling
- performance
- cleanup
- logging

PHASE 8 — DEPLOYMENT

Prepare:
- Docker
- production environment configuration
- deployment documentation
- health checks

PHASE 9 — FINAL REVIEW

Verify the product can be deployed by following the README from a clean environment.

IMPORTANT AGENT RULES
=====================

1. Do not make large architectural changes without explaining why.

2. Do not install unnecessary dependencies.

3. Do not rewrite working code unnecessarily.

4. Do not implement future features before the MVP works.

5. Do not claim a security check is stronger than it actually is.

6. Never execute uploaded user code.

7. Never expose secrets in scan output.

8. Prefer deterministic checks over LLM guesses.

9. Prefer high-confidence findings over noisy detection.

10. Every new detection rule must have tests.

11. Keep the scanner engine framework-independent where possible.

12. Keep the web layer separate from scanner logic.

13. Keep the application deployable with Docker.

14. Maintain a clear README.

15. Update documentation when behavior changes.

16. Before modifying code, understand the existing implementation.

17. After implementing a feature, run the relevant tests.

18. Do not declare a feature complete if tests fail.

19. If requirements are ambiguous, choose the simplest implementation that preserves the architecture and document the assumption.

20. Do not overengineer.

DEFINITION OF DONE
==================

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

FINAL PRODUCT PRINCIPLE
=======================

Do not try to build the world's best security scanner.

Build the best simple pre-launch safety checker for people who built an application with AI.

The product should answer one question extremely well:

"I vibe-coded this app. What should I check before I ship it?"

Prioritize:
- clarity
- trust
- safety
- useful findings
- low false positives
- simple UX
- fast scanning
- beginner-friendly explanations
- maintainable architecture
- zero unnecessary complexity

BUILD THE SMALLEST REAL PRODUCT FIRST.