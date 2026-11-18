"""Read-only CLI for captured runtime evidence; deployment is a separate action."""

import argparse
import hashlib
import json
from pathlib import Path

from .runtime_security import check, load_lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock")
    parser.add_argument("--facts")
    parser.add_argument("--profile", default="alma10-relay113-candidate")
    parser.add_argument("--output")
    parser.add_argument("--summary")
    parser.add_argument("--gate", action="store_true")
    parser.add_argument("--build-manifest")
    parser.add_argument("--runtime-rpm")
    parser.add_argument("--regression")
    args = parser.parse_args()
    lock = load_lock(args.lock)
    facts = json.loads(Path(args.facts).read_text()) if args.facts else None
    if facts is not None:
        facts["_file_sha256"] = hashlib.sha256(
            Path(args.facts).read_bytes()
        ).hexdigest()
    if args.build_manifest or args.runtime_rpm or args.regression:
        if not (args.facts and args.build_manifest and args.runtime_rpm):
            parser.error(
                "native evidence requires --facts, --build-manifest and --runtime-rpm"
            )
        from .runtime_bundle import verify

        facts["build_evidence"] = verify(
            lock["profiles"][args.profile],
            args.build_manifest,
            args.runtime_rpm,
            args.regression,
        )
    report = check(lock, args.profile, facts=facts)
    content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(content)
    else:
        print(content, end="")
    if args.summary:
        counts = report["security_counts"]
        summary = (
            f"### Runtime candidate: {report['profile']}\n\n"
            f"Security: {counts['fixed']} fixed, {counts['not-applicable']} not applicable, "
            f"{counts['affected']} affected, {counts['unknown']} unknown.\n\n"
            f"Deployable: {report['deployable']}. Unresolved contracts: {len(report['unresolved'])}.\n"
        )
        with Path(args.summary).open("a") as output:
            output.write(summary)
    return 1 if args.gate and not report["deployable"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
