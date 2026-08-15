from scanner.rules.base import Rule, Severity, Confidence

_FIX_PROMPT = (
    "Inspect the flagged file(s) and related database client setup. Explain the proposed fix. "
    "Modify only the necessary files, avoid unrelated refactoring, and preserve existing functionality. "
    "Move secrets to environment variables or a secrets manager, and never ship them in client code. "
    "Add or update tests that prove the fix, verify the change, and summarize what was changed."
)


def _check_rls(content: str, extra: str) -> list[tuple[int, str]]:
    if "createClient" not in content and "supabase-js" not in content and "from_supabase" not in content:
        return []
    lowered = content.lower()
    if ".rls" in lowered or "row level security" in lowered or "enablerowlevelsecurity" in lowered:
        return []
    return [(1, "supabase client found; no RLS indicators in file")]


def _check_prisma(content: str, extra: str) -> list[tuple[int, str]]:
    if "generator client" not in content and "datasource" not in content:
        return []
    if 'url = env("' in content or "url = env('" in content:
        return []
    return [(1, "datasource block uses a hardcoded connection string instead of env()")]


RULES: list[Rule] = [
    Rule(
        rule_id="DB-100",
        title="Database client or ORM referenced",
        category="database",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        description="A database client, ORM, or database technology is referenced in the code.",
        why_it_matters="Presence of database code makes the database security checks relevant to this project.",
        recommendation="",
        ai_fix_prompt="",
        is_presence_signal=True,
        evidence_signal="Database client, ORM, or database technology referenced",
        patterns=[r"(?i)\b(prisma|sequelize|mongoose|typeorm|sqlalchemy|psycopg|psycopg2|pymysql|mysql2|knex|drizzle|sqlite3|mongo|firebase|supabase|firestore|dynamodb|postgres|mysql|sqlite|mongodb)\b"],
    ),
    Rule(
        rule_id="DB-101",
        title="SQL statements found in code",
        category="database",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        description="SQL statements appear in the scanned files.",
        why_it_matters="Presence of SQL statements makes the database security checks relevant to this project.",
        recommendation="",
        ai_fix_prompt="",
        is_presence_signal=True,
        evidence_signal="SQL statements found in code",
        patterns=[r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|CREATE TABLE)\b"],
    ),
    Rule(
        rule_id="DB-001",
        title="Supabase service-role key in client code",
        category="database",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Potential issue detected: a Supabase service-role key (or similar secret) appears in client code.",
        why_it_matters="The service-role key bypasses Row Level Security entirely and grants full read/write access to the database. Leaked in client code, anyone can read, modify, or delete every row.",
        recommendation="Remove the service-role key from client code. Keep it server-side only, behind your API, and rotate the key immediately if it was ever exposed.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Supabase service_role keys use the JWT prefix eyJ and are meant for privileged server contexts. Their presence in a client bundle allows direct PostgREST calls that ignore RLS policies.",
        beginner="The service-role key is like a master key for your database. Putting it in the app that users can see lets anyone open every door.",
        patterns=[r"(?i)(service_role|serviceRole|supabase[_-]service)[^\n]{0,40}?(eyJ[A-Za-z0-9_\-\.]{10,}|sk_live_|sb_secret)"],
        frameworks={"supabase"},
    ),
    Rule(
        rule_id="DB-002",
        title="Supabase usage without RLS indicators",
        category="database",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Potential issue detected: Supabase client usage was found, but no Row Level Security configuration indicators are present in the file.",
        why_it_matters="Without Row Level Security, the Postgres API exposes every table to any anonymous client with the anon key. RLS is the primary access control layer for Supabase projects.",
        recommendation="Enable Row Level Security on all tables and define policies that scope queries to the authenticated user. Do not rely on client-side filtering alone.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Supabase clients issue SQL through PostgREST, which honours RLS policies. Absence of RLS setup in the client project suggests tables may be unprotected by default.",
        beginner="RLS is the fence around your data. Without it, anyone holding the public key can read or change everything in your tables.",
        patterns=[],
        files_include=["supabase", ".sql", ".js", ".ts", ".tsx"],
        frameworks={"supabase"},
        match=_check_rls,
    ),
    Rule(
        rule_id="DB-003",
        title="Firebase admin/private key in client code",
        category="database",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Potential issue detected: a Firebase admin/private key or service account credential string appears in client code.",
        why_it_matters="Firebase service account private keys grant full administrative access to Firestore, Realtime Database, and Storage, bypassing all security rules.",
        recommendation="Remove the key from client code, keep it on a server environment, and rotate the service account key if it has shipped to clients.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Firebase service account keys are long base64/URL-safe strings. Client bundles are readable by anyone, so a key there is equivalent to a public credential.",
        beginner="A Firebase private key is the password to your whole backend. Never put it where users can see it.",
        patterns=[r'(?i)(serviceAccount|private_key|firebase_admin|FIREBASE_SERVICE_ACCOUNT)[^\n]{0,60}?["\'][A-Za-z0-9+/=_\-]{30,}["\']'],
        frameworks={"firebase"},
    ),
    Rule(
        rule_id="DB-004",
        title="Unsafe SQL string concatenation",
        category="database",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Potential issue detected: SQL statements appear to be built via string concatenation or interpolation, which is a classic SQL injection vector.",
        why_it_matters="Concatenating user input into SQL lets attackers inject their own statements, steal data, or drop tables. Parameterized queries eliminate the risk.",
        recommendation="Replace string-built SQL with parameterized queries, prepared statements, or a query builder/ORM. Never interpolate user input into SQL text.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="SQL injection occurs when user-controlled input is embedded in the query string before execution. Parameters bind values separately so they are never parsed as SQL.",
        beginner="If you glue user text into a database command, an attacker can add their own commands. Parameterized queries keep input as plain data.",
        patterns=[r'(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b[^\n]*?(f["\']|\.format\s*\(|%\(|\$\{|["\']\s*\+|\+\s*["\'])'],
    ),
    Rule(
        rule_id="DB-005",
        title="DB connection string with hardcoded password",
        category="database",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Potential issue detected: a database connection string containing an embedded password is present.",
        why_it_matters="A connection string with a plaintext password grants anyone who sees the code or repository direct database access.",
        recommendation="Remove the password from the connection string, reference it via environment variables or a secrets manager, and rotate the exposed credential.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="The pattern matches the userinfo component of postgres/mysql/mongodb URIs, e.g. postgres://user:pass@host/db, which is never safe to hardcode.",
        beginner="This is like writing your database password in a note taped to your laptop. Anyone who sees it is in.",
        patterns=[r"(?i)(postgres(ql)?|mysql|mongodb(\+srv)?)://[^\s:@/]+:[^\s:@]+@"],
    ),
    Rule(
        rule_id="DB-006",
        title="Prisma datasource with hardcoded connection string",
        category="database",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="Potential issue detected: the Prisma datasource block uses a hardcoded URL instead of the env() reference.",
        why_it_matters="A hardcoded database URL embeds credentials in the schema and version history, exposing them to anyone with repository access.",
        recommendation="Reference the connection string via env(\"DATABASE_URL\") in the datasource block and provide the value through environment configuration only.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Prisma requires the datasource url; using env() keeps credentials out of source control and lets environments inject their own value at migration/generate time.",
        beginner="Hardcoding the database address here prints your database password into the code. Use an environment variable instead.",
        patterns=[r'(?is)datasource[^\n]*\{.*?url\s*=\s*"[^"]+"'],
        files_include=["schema.prisma", "prisma"],
        frameworks={"prisma"},
    ),
]
