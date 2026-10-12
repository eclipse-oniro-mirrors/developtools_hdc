#!/usr/bin/env python3
"""Validate AR requirement/test/task/report pair-level traceability."""
 
import argparse
import re
import sys
from pathlib import Path
 
 
REQUIRED_FILES = (
    "todo.md",
    "clarification.md",
    "requirement-spec.md",
    "architecture.md",
    "test-cases.md",
    "feature-test-matrix.md",
    "tasks.md",
    "apply-report.md",
)
 
 
def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")
 
 
def parse_table(text: str, required_headers: tuple[str, ...]) -> list[dict[str, str]]:
    lines = text.splitlines()
    required = set(required_headers)
    for index, line in enumerate(lines):
        if not line.lstrip().startswith("|"):
            continue
        headers = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not required.issubset(headers):
            continue
        rows = []
        for row_line in lines[index + 2:]:
            if not row_line.lstrip().startswith("|"):
                break
            cells = [cell.strip() for cell in row_line.strip().strip("|").split("|")]
            if len(cells) != len(headers):
                continue
            rows.append(dict(zip(headers, cells)))
        return rows
    return []
 
 
def validate_matrix(feature_ids: set[str], test_ids: set[str], matrix_rows: list[dict[str, str]],
                    task_blocks: list[str], errors: list[str]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for row in matrix_rows:
        feature_id = row["Feature ID"]
        test_id = row["Test Case ID"]
        pair = (feature_id, test_id)
        if pair in pairs:
            errors.append(f"duplicate matrix pair: {feature_id}/{test_id}")
        pairs.add(pair)
        if feature_id not in feature_ids:
            errors.append(f"matrix references undefined feature: {feature_id}")
        if test_id not in test_ids:
            errors.append(f"matrix references undefined test: {test_id}")
        if not any(feature_id in block and test_id in block for block in task_blocks):
            errors.append(f"pair not co-located in a task: {feature_id}/{test_id}")
 
    for feature_id in sorted(feature_ids):
        if not any(pair[0] == feature_id for pair in pairs):
            errors.append(f"feature has no matrix test: {feature_id}")
    return pairs
 
 
def validate_report(pairs: set[tuple[str, str]], report_rows: list[dict[str, str]], errors: list[str]) -> None:
    report_results = {
        (row["Feature ID"], row["Test Case ID"]): row["Result"]
        for row in report_rows
    }
    for feature_id, test_id in sorted(pairs):
        result = report_results.get((feature_id, test_id))
        if result != "Pass":
            errors.append(f"pair has no Pass result: {feature_id}/{test_id} (actual={result!r})")
 
 
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-dir", required=True, type=Path)
    change_dir = parser.parse_args().change_dir.resolve()
    errors = [
        f"missing required artifact: {name}"
        for name in REQUIRED_FILES if not (change_dir / name).is_file()
    ]
    if errors:
        print("AR validation failed:\n- " + "\n- ".join(errors), file=sys.stderr)
        return 1
 
    feature_ids = set(re.findall(r"\bF-\d{3,}\b", read_text(change_dir / "requirement-spec.md")))
    test_ids = set(re.findall(r"\bTC-\d{3,}\b", read_text(change_dir / "test-cases.md")))
    matrix_rows = parse_table(read_text(change_dir / "feature-test-matrix.md"),
                              ("Feature ID", "Test Case ID"))
    report_rows = parse_table(read_text(change_dir / "apply-report.md"),
                              ("Feature ID", "Test Case ID", "Result"))
    task_blocks = re.findall(r"(?ms)^### TASK-\d+.*?(?=^### TASK-\d+|\Z)",
                             read_text(change_dir / "tasks.md"))
    if not feature_ids:
        errors.append("no F-xxx IDs found in requirement-spec.md")
    if not test_ids:
        errors.append("no TC-xxx IDs found in test-cases.md")
    if not matrix_rows:
        errors.append("coverage matrix table is missing or empty")
    pairs = validate_matrix(feature_ids, test_ids, matrix_rows, task_blocks, errors)
    validate_report(pairs, report_rows, errors)
 
    if errors:
        print("AR validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
 
    print(f"AR validation passed: {len(feature_ids)} features, {len(test_ids)} tests, {len(pairs)} pairs")
    return 0
 
 
if __name__ == "__main__":
    raise SystemExit(main())