import os

from scanner.models import FileSnapshot
from scanner.rules import all_rules
from scanner.redaction import mask_secret, redact_evidence


def rule_by_id(rid):
    for r in all_rules():
        if r.rule_id == rid:
            return r
    raise AssertionError(f"rule {rid} not registered")


def hits(rule, content, path="x.py"):
    if rule.files_include and not any(x in path for x in rule.files_include):
        return []
    if rule.files_exclude and any(x in path for x in rule.files_exclude):
        return []
    return rule.find_in(content)


def test_secret_001_detects_api_key():
    r = rule_by_id("SECRET-001")
    assert hits(r, 'const k = "api_key=1234567890abcdef1234567890ab";')


def test_secret_001_true_negative():
    r = rule_by_id("SECRET-001")
    assert hits(r, "const k = apiKeyFromEnv();") == []


def test_secret_004_openai_key():
    r = rule_by_id("SECRET-004")
    assert hits(r, "client = OpenAI(api_key='sk-proj-abcdefghijklmnopqrstuvwxyz123456')")


def test_secret_005_stripe_live():
    r = rule_by_id("SECRET-005")
    assert hits(r, "stripe.api_key = 'sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'")


def test_secret_007_aws():
    r = rule_by_id("SECRET-007")
    assert hits(r, "AKIAIOSFODNN7EXAMPLE")


def test_secret_002_private_key():
    r = rule_by_id("SECRET-002")
    assert hits(r, "-----BEGIN RSA PRIVATE KEY-----\nMIIE", path="keys/id_rsa.pem")


def test_secret_006_db_url():
    r = rule_by_id("SECRET-006")
    assert hits(r, "postgres://admin:password123@db.example.com:5432/app")


def test_git_001_env_committed():
    r = rule_by_id("GIT-001")
    assert hits(r, "DATABASE_URL=postgres://u:p@h/db", path=".env")


def test_conf_001_debug_true():
    r = rule_by_id("CONF-001")
    assert hits(r, "DEBUG = True")


def test_conf_002_wildcard_cors():
    r = rule_by_id("CONF-002")
    assert hits(r, "cors_origins = ['*']")


def test_api_006_secret_in_client_js():
    r = rule_by_id("API-006")
    assert hits(r, "const apikey = 'sk-live-abcdefghijklmnopqrstuvwxyz123456';", path="client.js")


def test_auth_002_client_controlled_admin():
    r = rule_by_id("AUTH-002")
    assert hits(r, "const isAdmin = props.isAdmin;")


def test_auth_001_route_without_auth():
    r = rule_by_id("AUTH-001")
    assert hits(r, 'app.get("/api/users", (req,res)=>res.json([]))', path="server.js") != []


def test_auth_001_route_with_auth_clean():
    r = rule_by_id("AUTH-001")
    content = 'app.get("/api/users", requireAuth, (req,res)=>res.json([]))'
    assert hits(r, content, path="server.js") == []


def test_pay_001_stripe_secret():
    r = rule_by_id("PAY-001")
    assert hits(r, "stripe.api_key = 'sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'")


def test_code_001_eval():
    r = rule_by_id("CODE-001")
    assert hits(r, "const out = eval(code);")


def test_code_002_shell_exec():
    r = rule_by_id("CODE-002")
    assert hits(r, "os.system('ping -c 1 ' + host)")


def test_code_008_xss():
    r = rule_by_id("CODE-008")
    assert hits(r, "el.innerHTML = userContent;")


def test_deploy_004_debug_enabled():
    r = rule_by_id("DEPLOY-004")
    assert hits(r, 'NODE_ENV="development"')


def test_redaction_masks_secrets():
    out = redact_evidence("sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
    assert "51AbCdEfGhIjKlMnOpQrStUvWxYz" not in out
    assert out != "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def test_redaction_masks_url_credentials():
    out = redact_evidence("postgres://admin:s3cr3t@db.example.com:5432/app")
    assert "s3cr3t" not in out
    assert "admin:****@" in out


def test_mask_secret_short():
    assert mask_secret("abc") == "<redacted>"
