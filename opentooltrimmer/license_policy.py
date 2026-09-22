from __future__ import annotations

import re
from pathlib import Path

from .models import Decision, LicenseFinding

DEFAULT_ALLOWLIST = ("MIT",)
ACQUISITION_VALIDATED_LICENSES = frozenset({"MIT"})


def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


MIT_BODY = _normalize("""
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
""")

MIT_ABBREVIATED_BODY = _normalize("""
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, subject to inclusion of this notice.
THE SOFTWARE IS PROVIDED "AS IS".
""")

MIT_TITLES = frozenset({"mit license", "the mit license (mit)"})


def _detect_spdx(text: str) -> tuple[str | None, str]:
    t = _normalize(text)

    if "gnu affero general public license" in t and "version 3" in t:
        return "AGPL-3.0", "GNU Affero GPL v3 text detected"
    if "gnu lesser general public license" in t and "version 3" in t:
        return "LGPL-3.0", "GNU LGPL v3 text detected"
    if "gnu general public license" in t and "version 3" in t:
        return "GPL-3.0", "GNU GPL v3 text detected"
    if "gnu general public license" in t and "version 2" in t:
        return "GPL-2.0", "GNU GPL v2 text detected"
    if "mozilla public license" in t and "version 2.0" in t:
        return "MPL-2.0", "Mozilla Public License 2.0 text detected"
    if "permission is hereby granted, free of charge" in t and "the software is provided \"as is\"" in t:
        permission_start = t.find("permission is hereby granted, free of charge")
        body = t[permission_start:]
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        permission_line = next(
            (
                index
                for index, line in enumerate(lines)
                if _normalize(line).startswith("permission is hereby granted, free of charge")
            ),
            -1,
        )
        prefix_lines = lines[:permission_line] if permission_line >= 0 else []
        valid_prefix = bool(prefix_lines) and _normalize(prefix_lines[0]) in MIT_TITLES
        if valid_prefix:
            valid_prefix = all(
                re.fullmatch(
                    r"copyright\s*(?:\(c\)|©)?\s*\d{4}(?:-\d{4})?\s+\S.*",
                    line,
                    flags=re.IGNORECASE,
                )
                is not None
                for line in prefix_lines[1:]
            )
        if valid_prefix and body in {MIT_BODY, MIT_ABBREVIATED_BODY}:
            return "MIT", "MIT license text detected"
        return None, "MIT-like text contained additional terms or modifications; reuse permission is ambiguous"

    return None, "license text was present but not recognized by the V0.1 detector"


def detect_license(repo: Path) -> LicenseFinding:
    candidates = []
    for pattern in ("LICENSE*", "LICENCE*", "COPYING*"):
        candidates.extend(repo.glob(pattern))

    files = sorted(
        {p for p in candidates if p.is_file()},
        key=lambda p: (len(p.name), p.name.lower()),
    )
    if not files:
        return LicenseFinding(None, None, "none", "no license file found")

    findings = []
    for path in files:
        relative = str(path.relative_to(repo))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return LicenseFinding(
                None,
                relative,
                "none",
                f"license file could not be read: {exc}",
            )
        spdx, reason = _detect_spdx(text)
        findings.append((relative, text, spdx, reason))

    if len(findings) > 1:
        normalized_documents = {_normalize(text) for _, text, _, _ in findings}
        if (
            len(normalized_documents) == 1
            and all(spdx == "MIT" for _, _, spdx, _ in findings)
        ):
            return LicenseFinding(
                spdx_id="MIT",
                path=findings[0][0],
                confidence="high",
                reason="equivalent validated MIT license documents detected",
            )

        evidence = ", ".join(
            f"{relative}={spdx or 'unknown'}"
            for relative, _, spdx, _ in findings
        )
        return LicenseFinding(
            spdx_id=None,
            path=", ".join(relative for relative, _, _, _ in findings),
            confidence="low",
            reason=f"multiple conventional license documents disagree or include unvalidated evidence: {evidence}",
        )

    relative, _, spdx, reason = findings[0]
    return LicenseFinding(
        spdx_id=spdx,
        path=relative,
        confidence="high" if spdx else "low",
        reason=reason,
    )


def decide_acquisition(
    finding: LicenseFinding,
    allowlist: tuple[str, ...] | list[str],
    dependency_complete: bool,
) -> tuple[Decision, str]:
    allowed = set(allowlist)

    if finding.spdx_id is None:
        return Decision.HOLD, "license permission is missing or ambiguous; OpenToolTrimmer does not infer acquisition authority"

    if finding.spdx_id not in allowed:
        return (
            Decision.POINT_ONLY,
            f"{finding.spdx_id} was recognized but is not allowed by the active acquisition policy; source may be referenced but not emitted",
        )

    if finding.spdx_id not in ACQUISITION_VALIDATED_LICENSES:
        return (
            Decision.HOLD,
            f"{finding.spdx_id} was recognized, but V0.1 does not have conservative complete-document validation for acquisition",
        )

    if not dependency_complete:
        return (
            Decision.HOLD,
            "license policy permits acquisition, but V0.1 cannot prove dependency closure for this slice",
        )

    return (
        Decision.ACQUIRE,
        f"{finding.spdx_id} is allowed by the active policy and V0.1 dependency closure is complete",
    )
