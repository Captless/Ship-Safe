from scanner.engine import scan_root


def test_scan_root_reports_progress_events(vuln_project):
    events = []

    def reporter(fields):
        events.append(dict(fields))

    result = scan_root("vuln", vuln_project, progress=reporter)
    phases = [e["phase"] for e in events]

    assert "filtering" in phases
    assert "scanning" in phases
    assert "building_report" in phases

    filtering = next(e for e in events if e["phase"] == "filtering")
    assert filtering["files_discovered"] == len(vuln_project)
    assert filtering["files_to_scan"] == result.application_files
    assert filtering["files_skipped"] == result.ignored_files

    scanning = [e for e in events if e["phase"] == "scanning"]
    assert scanning
    assert scanning[0]["current"] == 1
    assert scanning[0]["total"] == result.application_files
    assert all(e["current"] == e["files_analyzed"] for e in scanning)
    assert all(e["total"] == result.application_files for e in scanning)
    assert all(e["current_file"] for e in scanning)
    assert scanning[-1]["findings_found"] <= len(result.findings)

    final = events[-1]
    assert final["phase"] == "building_report"
    assert final["current"] == result.application_files
    assert final["total"] == result.application_files
    assert final["files_analyzed"] == result.application_files
    assert final["findings_found"] == len(result.findings)


def test_progress_callback_does_not_alter_results(vuln_project):
    events = []
    baseline = scan_root("vuln", vuln_project)
    with_cb = scan_root("vuln", vuln_project, progress=lambda fields: events.append(dict(fields)))

    assert events
    a = baseline.to_dict()
    b = with_cb.to_dict()
    a["duration_ms"] = 0
    b["duration_ms"] = 0
    assert a == b
    assert baseline.score == with_cb.score
    assert [f.rule_id for f in baseline.findings] == [f.rule_id for f in with_cb.findings]
