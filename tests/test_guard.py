import pytest

from conscience.config import Settings
from conscience.guard.diff import synthesize_diff
from conscience.guard.engine import Guard, scan_diff
from conscience.models import Severity


def rules_hit(source: str, filename: str = "app.py") -> set[str]:
    findings, _ = scan_diff(synthesize_diff(filename, source))
    return {f.rule_id for f in findings}


@pytest.mark.parametrize(
    "source,expected",
    [
        ('key = "AKIAIOSFODNN7EXAMPLE"', "secret.aws-access-key"),
        ('password = "hunter2hunter2"', "secret.hardcoded-credential"),
        ("exec(user_supplied)", "code.python-eval-exec"),
        ('subprocess.run(cmd, shell=True)', "code.shell-injection"),
        ('cur.execute(f"SELECT * FROM users WHERE id = {uid}")', "code.sql-string-building"),
        ("data = pickle.loads(blob)", "code.unsafe-deserialization"),
        ("requests.get(url, verify=False)", "config.tls-verification-disabled"),
        ('jwt.decode(token, options={"verify_signature": False})', "code.jwt-verification-skipped"),
        ("app.run(debug=True)", "config.debug-enabled"),
    ],
)
def test_rule_fires(source, expected):
    assert expected in rules_hit(source)


@pytest.mark.parametrize(
    "source",
    [
        'api_key = os.environ["SERVICE_API_KEY"]',
        'password = "<your-password-here>"',
        'token = process.env.AUTH_TOKEN',
    ],
)
def test_env_lookups_and_placeholders_are_not_flagged(source):
    assert "secret.hardcoded-credential" not in rules_hit(source)


def test_comments_are_ignored():
    assert rules_hit("# password = \"hunter2hunter2\"") == set()


def test_extension_scoping():
    # innerHTML only matters in web files
    assert "code.xss-innerhtml" in rules_hit("el.innerHTML = name;", "page.js")
    assert "code.xss-innerhtml" not in rules_hit("el.innerHTML = name;", "notes.txt")


def test_new_dependency_is_flagged_as_info():
    diff = synthesize_diff("package.json", '    "left-pad": "^1.3.0",')
    findings, _ = scan_diff(diff)

    assert [f.rule_id for f in findings] == ["dep.new-dependency"]
    assert findings[0].package == "left-pad"
    assert findings[0].severity is Severity.INFO


def test_clean_diff_is_allowed():
    guard = Guard(Settings(offline=True))
    verdict = guard.review_file("app.py", "def add(a, b):\n    return a + b\n")

    assert verdict.decision == "allow"
    assert verdict.findings == []
    assert verdict.agent_feedback == ""


def test_dangerous_diff_is_blocked_with_feedback_for_the_agent():
    guard = Guard(Settings(offline=True))
    verdict = guard.review_file("app.py", 'os.system("rm " + user_path)\nexec(payload)\n')

    assert verdict.decision == "block"
    assert not verdict.ok
    assert "Do this instead" in verdict.agent_feedback
    # Worst finding first, so a truncated context keeps the important half.
    assert verdict.findings[0].finding.severity.rank >= verdict.findings[-1].finding.severity.rank


def test_info_only_change_warns_but_does_not_block():
    guard = Guard(Settings(offline=True))
    verdict = guard.review_file("requirements.txt", "requests==2.31.0\n")

    assert verdict.decision == "warn"
    assert verdict.ok
