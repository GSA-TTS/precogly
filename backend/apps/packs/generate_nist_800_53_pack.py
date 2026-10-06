"""Generate the offline Precogly NIST SP 800-53 Rev. 5 pack from OSCAL."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml

EXPECTED_SHA256 = "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062"
SOURCE_COMMIT = "78650f02ad9321bb7b817846f8fbd4f2bcd620de"
SOURCE_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/"
    f"{SOURCE_COMMIT}/nist.gov/SP800-53/rev5/json/"
    "NIST_SP-800-53_rev5_catalog.json"
)


def canonical_control_id(oscal_id: str) -> str:
    """Convert OSCAL IDs such as ac-2.1 to the shared AC-2(1) identity."""
    match = re.fullmatch(r"([a-z]{2,3})-(\d+)(?:\.(\d+))?", oscal_id.lower())
    if not match:
        raise ValueError(f"unsupported NIST control id: {oscal_id}")
    family, number, enhancement = match.groups()
    base = f"{family.upper()}-{int(number)}"
    return f"{base}({int(enhancement)})" if enhancement else base


def statement_prose(parts: list[dict]) -> str:
    """Return ordered prose from only OSCAL statement parts."""
    lines = []

    def visit(part: dict) -> None:
        if prose := part.get("prose", "").strip():
            lines.append(prose)
        for child in part.get("parts", []):
            visit(child)

    for part in parts:
        if part.get("name") == "statement":
            visit(part)
    return "\n".join(lines)


def property_value(item: dict, name: str) -> str:
    """Return the first OSCAL property value matching a name."""
    return next(
        (
            prop.get("value", "")
            for prop in item.get("props", [])
            if prop.get("name") == name
        ),
        "",
    )


def withdrawn_description(item: dict) -> str:
    """Describe an official withdrawal using only OSCAL disposition links."""
    dispositions = [
        link
        for link in item.get("links", [])
        if link.get("rel") in {"incorporated-into", "moved-to"}
    ]
    if not dispositions:
        return "Withdrawn in NIST SP 800-53 Rev. 5."

    labels = {
        "incorporated-into": "incorporated into",
        "moved-to": "moved to",
    }
    references = []
    for link in dispositions:
        target = link["href"].removeprefix("#")
        control_match = re.match(r"[a-z]{2,3}-\d+(?:\.\d+)?", target.lower())
        display_target = (
            canonical_control_id(control_match.group()) if control_match else target
        )
        reference = f"{labels[link['rel']]} {display_target}"
        if reference not in references:
            references.append(reference)
    return "Withdrawn in NIST SP 800-53 Rev. 5; " + "; ".join(references) + "."


def build_pack(document: dict, source_sha256: str) -> dict:
    catalog = document["catalog"]
    metadata = catalog["metadata"]
    requirements = []

    for group in catalog.get("groups", []):
        for control in group.get("controls", []):
            controls = [(control, None)]
            controls.extend(
                (enhancement, control["id"])
                for enhancement in control.get("controls", [])
            )
            for item, parent_id in controls:
                status = property_value(item, "status")
                description = statement_prose(item.get("parts", []))
                if not description and status == "withdrawn":
                    description = withdrawn_description(item)
                requirement = {
                    "section_code": canonical_control_id(item["id"]),
                    "name": item.get("title", ""),
                    "description": description,
                    "requirement_type": "enhancement" if parent_id else "control",
                    "format_metadata": {
                        "oscal_id": item["id"],
                        "family": group.get("id", "").upper(),
                        "source": "NIST OSCAL",
                        "parameters": [param["id"] for param in item.get("params", [])],
                        "disposition_links": [
                            link
                            for link in item.get("links", [])
                            if link.get("rel") in {"incorporated-into", "moved-to"}
                        ],
                    },
                }
                if status:
                    requirement["status"] = status
                if parent_id:
                    requirement["parent"] = canonical_control_id(parent_id)
                requirements.append(requirement)

    requirements.sort(key=lambda item: item["section_code"])
    return {
        "pack": {
            "schema_version": 1,
            "slug": "nist-800-53-r5",
            "name": "NIST SP 800-53 Rev. 5",
            "version": metadata["version"],
            "pack_type": "compliance",
            "author": "National Institute of Standards and Technology",
            "description": (
                "Official NIST SP 800-53 Revision 5 controls generated from the "
                "pinned OSCAL catalog."
            ),
            "tags": ["compliance", "security", "privacy", "government"],
            "provenance": {
                "source": SOURCE_URL,
                "source_commit": SOURCE_COMMIT,
                "source_sha256": source_sha256,
                "catalog_uuid": catalog["uuid"],
                "catalog_version": metadata["version"],
                "oscal_version": metadata["oscal-version"],
                "license": "U.S. Government work; public domain",
            },
        },
        "frameworks": [
            {
                "slug": "nist-800-53-r5",
                "name": "NIST SP 800-53 Rev. 5",
                "version": metadata["version"],
                "issuer": "NIST",
                "description": metadata["title"],
                "requirements": requirements,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--allow-unpinned-source", action="store_true")
    args = parser.parse_args()

    content = args.catalog.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if digest != EXPECTED_SHA256 and not args.allow_unpinned_source:
        raise SystemExit(
            f"catalog digest {digest} does not match pinned digest {EXPECTED_SHA256}"
        )

    pack = build_pack(json.loads(content), digest)
    requirements = pack["frameworks"][0]["requirements"]
    empty_requirements = [
        requirement["section_code"]
        for requirement in requirements
        if not requirement["description"]
    ]
    if empty_requirements:
        raise SystemExit(
            "requirements have no statement or withdrawal description: "
            + ", ".join(empty_requirements)
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(pack, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
