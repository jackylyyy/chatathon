from conscience.guard.diff import parse_unified_diff, synthesize_diff

SAMPLE = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,3 +10,5 @@ def handler():
 context line
+added one
+added two
-removed line
 trailing context
"""


def test_added_lines_get_new_file_line_numbers():
    parsed = parse_unified_diff(SAMPLE)

    assert [a.text for a in parsed.added] == ["added one", "added two"]
    assert [a.line for a in parsed.added] == [11, 12]
    assert parsed.files == ["app.py"]
    assert parsed.removed_count == 1


def test_multiple_files_are_tracked_separately():
    diff = SAMPLE + """\
--- a/other.py
+++ b/other.py
@@ -1,0 +1,1 @@
+print("hi")
"""
    parsed = parse_unified_diff(diff)

    assert parsed.files == ["app.py", "other.py"]
    assert parsed.added[-1].file == "other.py"
    assert parsed.added[-1].line == 1


def test_new_file_diff_has_no_a_side():
    parsed = parse_unified_diff(synthesize_diff("new.py", "one\ntwo\n"))

    assert parsed.files == ["new.py"]
    assert [a.line for a in parsed.added] == [1, 2]


def test_non_diff_text_yields_nothing():
    assert parse_unified_diff("just some prose\nwith + a plus").added == []
