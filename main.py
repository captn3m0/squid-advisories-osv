#!/usr/bin/env python3
"""
Generate/update OSV-format JSON advisories for Squid from
GitHub Security Advisories (squid-cache/squid).

For existing advisory files only the `id` field is updated;
all other content is left as-is to preserve manual edits.
New advisories are written in full.
"""

import json
import re
import subprocess
from pathlib import Path

ADVISORIES_DIR = Path("advisories")
ADVISORIES_DIR.mkdir(exist_ok=True)


def squid_id_to_filename(squid_id: str) -> str:
    """SQUID-2020:10 -> SQUID-2020-10"""
    return squid_id.replace(":", "-")


def extract_squid_id(summary: str) -> str | None:
    m = re.match(r"(SQUID-\d{4}:\d+)", summary)
    return m.group(1) if m else None


def make_references(squid_id: str, cves: list[str], ghsa_id: str | None, html_url: str | None) -> list[dict]:
    refs = []
    if html_url:
        refs.append({"type": "ADVISORY", "url": html_url})
    for cve in cves:
        refs.append({"type": "REPORT", "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"})
    if ghsa_id:
        refs.append({"type": "ADVISORY", "url": f"https://github.com/advisories/{ghsa_id}"})
    return refs


def parse_version_ranges(range_str: str, patched_str: str) -> list[dict]:
    if not range_str:
        return []

    # Build fix lookup by major version: "4" -> "4.13"
    fixes_by_major: dict[str, str] = {}
    if patched_str:
        for v in re.split(r",\s*", patched_str):
            v = v.strip()
            if v:
                fixes_by_major[v.split(".")[0]] = v

    # Version token: digits, dots, and STABLE/alpha suffixes
    VER = r"[\d][.\d]*(?:[A-Za-z]\w*)?"

    ranges = []
    for part in re.split(r",\s*", range_str):
        part = part.strip()
        if not part:
            continue

        # "< X.Y" or "<X.Y"  (no lower bound — all versions before fix)
        m = re.match(rf"^<\s*({VER})$", part)
        if m:
            ranges.append({"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": m.group(1)},
            ]})
            continue

        # ">= X, < Y" — split already consumed comma, so check combined
        # This form won't appear after splitting on "," above, but handle
        # ">= X.Y" alone just in case (unlikely from GitHub)
        m = re.match(rf"^>=\s*({VER})$", part)
        if m:
            intro = m.group(1)
            fix = fixes_by_major.get(intro.split(".")[0])
            events: list[dict] = [{"introduced": intro}]
            if fix:
                events.append({"fixed": fix})
            ranges.append({"type": "SEMVER", "events": events})
            continue

        # "X.Y - Z.W"  (dash range, versions may contain STABLE etc.)
        m = re.match(rf"^({VER})\s*-\s*({VER})$", part)
        if m:
            intro, last = m.group(1), m.group(2)
            fix = fixes_by_major.get(intro.split(".")[0])
            if fix:
                events = [{"introduced": intro}, {"fixed": fix}]
            else:
                events = [{"introduced": intro}, {"last_affected": last}]
            ranges.append({"type": "SEMVER", "events": events})
            continue

        # Fallback
        ranges.append({"type": "SEMVER", "events": [{"introduced": part}]})

    return ranges


def make_affected(ranges: list[dict], severity: list[dict] | None) -> list[dict]:
    entry: dict = {
        "package": {
            "ecosystem": "Other",
            "name": "squid",
            "purl": "pkg:generic/squid",
        }
    }
    if ranges:
        entry["ranges"] = ranges
    if severity:
        entry["severity"] = severity
    return [entry]


def gh_advisory_to_osv(adv: dict) -> dict | None:
    squid_id = extract_squid_id(adv.get("summary", ""))
    if not squid_id:
        print(f"  WARN: cannot extract SQUID ID from: {adv['summary']}")
        return None

    cves = [adv["cve_id"]] if adv.get("cve_id") else []
    ghsa_id = adv.get("ghsa_id")
    aliases = ([ghsa_id] if ghsa_id else []) + cves
    title = re.sub(r"^SQUID-\d+:\d+\s+", "", adv.get("summary", "")).strip()
    published = adv.get("published_at") or ""
    modified = adv.get("updated_at") or published
    details = (adv.get("description") or "").replace("\r\n", "\n").strip()

    severity: list[dict] = []
    cvss_v3 = (adv.get("cvss_severities") or {}).get("cvss_v3") or {}
    if cvss_v3.get("vector_string"):
        severity.append({"type": "CVSS_V3", "score": cvss_v3["vector_string"]})

    all_ranges: list[dict] = []
    for vuln in adv.get("vulnerabilities") or []:
        all_ranges.extend(parse_version_ranges(
            vuln.get("vulnerable_version_range") or "",
            vuln.get("patched_versions") or "",
        ))

    return {
        "schema_version": "1.0.0",
        "id": squid_id,
        "aliases": aliases,
        "summary": title,
        "details": details,
        "published": published,
        "modified": modified,
        "affected": make_affected(all_ranges, severity or None),
        "references": make_references(squid_id, cves, ghsa_id, adv.get("html_url")),
    }


def write_advisory(osv: dict) -> Path:
    fname = ADVISORIES_DIR / f"{squid_id_to_filename(osv['id'])}.json"
    with open(fname, "w") as f:
        json.dump(osv, f, indent=2)
        f.write("\n")
    return fname


def main():
    result = subprocess.run(
        ["gh", "api", "repos/squid-cache/squid/security-advisories", "--paginate"],
        capture_output=True, text=True, check=True,
    )
    gh_advisories = json.loads(result.stdout)
    print(f"Fetched {len(gh_advisories)} GitHub advisories")

    for adv in gh_advisories:
        osv = gh_advisory_to_osv(adv)
        if not osv:
            continue

        fname = ADVISORIES_DIR / f"{squid_id_to_filename(osv['id'])}.json"

        if fname.exists():
            existing = json.loads(fname.read_text())
            if existing.get("id") != osv["id"]:
                existing["id"] = osv["id"]
                fname.write_text(json.dumps(existing, indent=2) + "\n")
                print(f"  Updated id in {fname.name}")
            else:
                print(f"  Unchanged {fname.name}")
        else:
            write_advisory(osv)
            print(f"  Created {fname.name}")


if __name__ == "__main__":
    main()
