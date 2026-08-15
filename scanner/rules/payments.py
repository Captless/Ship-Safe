from scanner.rules.base import Rule, Severity, Confidence

_FIX_PROMPT = (
    "Inspect the flagged payment handler file(s). Explain the proposed fix. "
    "Modify only the necessary files, avoid unrelated refactoring, and preserve existing functionality. "
    "Use server-side pricing and verify webhook signatures exactly as Stripe requires. "
    "Add or update tests that prove the fix, verify the change, and summarize what was changed."
)


def _check_webhook(content: str, extra: str) -> list[tuple[int, str]]:
    has_webhook = "webhook" in content.lower() or "stripe.webhooks" in content
    if not has_webhook:
        return []
    lowered = content.lower()
    if "constructevent" in lowered or "signature" in lowered or "stripe-signature" in lowered or "verify" in lowered:
        return []
    return [(1, "webhook handler found without signature verification reference")]


RULES: list[Rule] = [
    Rule(
        rule_id="PAY-001",
        title="Stripe secret key exposed",
        category="payments",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Potential issue detected: a Stripe live secret key (sk_live_...) is present in the scanned file.",
        why_it_matters="A live Stripe secret key grants full access to your account: charges, refunds, and customer data. Anyone who sees it can spend your money.",
        recommendation="Revoke the key immediately in the Stripe dashboard, generate a new one, and store it server-side in an environment variable or secrets manager.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Keys prefixed sk_live_ are account-level secrets. They must never appear in client bundles, logs, or repositories.",
        beginner="The sk_live_ key is your Stripe password. If it leaks, someone else can charge your customers and take your money.",
        patterns=[r"\bsk_live_[A-Za-z0-9]{16,}\b"],
        frameworks={"stripe"},
    ),
    Rule(
        rule_id="PAY-002",
        title="Stripe webhook without signature verification",
        category="payments",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Potential issue detected: a webhook handler exists but contains no reference to signature verification.",
        why_it_matters="Without verifying the Stripe-Signature header, an attacker can forge webhook events to mark payments as paid and unlock paid features for free.",
        recommendation="Verify every webhook event with the signing secret using constructEvent, and reject events with invalid signatures.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Stripe signs webhook payloads with the endpoint's signing secret. constructEvent validates signature, payload, and timestamp before any business logic runs.",
        beginner="A fake 'payment received' message can unlock paid features. Signature checks prove the message really came from Stripe.",
        patterns=[],
        frameworks={"stripe"},
        match=_check_webhook,
    ),
    Rule(
        rule_id="PAY-003",
        title="Client-controlled price",
        category="payments",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Potential issue detected: an amount or price is being read from client-controlled input when charging a customer.",
        why_it_matters="If the client supplies the amount, an attacker can pay 0.01 for a $100 product. Prices must be decided by your server.",
        recommendation="Compute the amount server-side from your product catalog and the verified session. Never trust client-supplied amounts in charge logic.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Payment amounts derived from request bodies, params, or unverified event data are mutable by the caller. Server-side pricing closes the tampering vector.",
        beginner="If the app lets the customer type the price, they will type zero. The server must set the price.",
        patterns=[r"(?i)(amount|price|total|amount_total)\s*[:=]\s*(req\.(query|body|params)|event\.data|body\.price|req\.body)"],
        frameworks={"stripe"},
    ),
    Rule(
        rule_id="PAY-004",
        title="Client-controlled subscription state",
        category="payments",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Potential issue detected: subscription or plan state is being set from client-controlled values.",
        why_it_matters="Letting the client assert its own plan or premium status lets users grant themselves paid features without paying.",
        recommendation="Maintain subscription status server-side, derived from verified billing events or the provider API, and treat client claims as untrusted.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Plan entitlements must be resolved from the server's billing records, not from request or client-stored fields that the caller can edit.",
        beginner="If the app believes the client's word about being premium, everyone will say they are premium.",
        patterns=[r"(?i)(plan|subscription|billing|isPro|premium)\s*[:=]\s*(req\.|body\.|client|props\.|localStorage)"],
    ),
    Rule(
        rule_id="PAY-005",
        title="Publishable key used where secret expected",
        category="payments",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="Potential issue detected: a Stripe publishable key appears near operations that require the secret key.",
        why_it_matters="Publishable keys are public and cannot perform charges or access account data. Using one where a secret is required means the operation either fails or silently misconfigures.",
        recommendation="Use the secret key only in trusted server code, and keep publishable keys strictly in client-side initialization where they are safe.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="pk_live_/pk_test_ keys are public by design. Using them for charges, checkout creation, or other privileged calls indicates a key-role mix-up.",
        beginner="The pk key is like a public name badge; the sk key is the key to the cash drawer. Using the badge to open the drawer will not work.",
        patterns=[r"(?i)(pk_live_|pk_test_)[^\n]{0,60}(secret|charges|checkout)"],
        frameworks={"stripe"},
    ),
]
