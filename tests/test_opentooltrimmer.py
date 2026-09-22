from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from opentooltrimmer.cli import build_parser, main
from opentooltrimmer.core import _verify_slice, dissect
from opentooltrimmer.models import Decision

FIXTURES = Path(__file__).parent / "fixtures"


def _write_byte_preservation_repo(repo: Path) -> tuple[bytes, bytes]:
    repo.mkdir()
    (repo / "LICENSE").write_bytes(
        (FIXTURES / "permissive_repo" / "LICENSE").read_bytes()
    )
    cleaner = (
        b"from helpers import clean_name\r\n"
        b"\r\n"
        b"def normalize_customer_name(value: str) -> str:\r\n"
        b"    \"\"\"Normalize a customer name.\"\"\"\r\n"
        b"    return clean_name(value)\r\n"
    )
    helper = (
        b"# -*- coding: latin-1 -*-\n"
        b"\n"
        b"def clean_name(value: str) -> str:\n"
        b"    \"\"\"Clean a caf\xe9 customer name.\"\"\"\n"
        b"    return value.strip().lower()\n"
    )
    (repo / "cleaner.py").write_bytes(cleaner)
    (repo / "helpers.py").write_bytes(helper)
    (repo / "notes.bin").write_bytes(b"repository bytes not emitted\x00\xff")
    return cleaner, helper


def _write_repo(repo: Path, files: dict[str, bytes]) -> None:
    repo.mkdir()
    for relative, content in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


class OpenToolTrimmerTests(unittest.TestCase):
    def test_cli_requires_invocation_correlation(self):
        with self.assertRaises(SystemExit) as raised:
            build_parser().parse_args([
                "--repo", "repo",
                "--need", "need",
                "--intended-use", "use",
            ])

        self.assertEqual(raised.exception.code, 2)

    def test_cli_passes_opaque_invocation_correlation_unchanged(self):
        correlation = "attempt_id=not-an-attempt|authority:NOT-A-TOKEN/{opaque}?x=1"
        native = SimpleNamespace(
            decision=Decision.HOLD,
            selected=None,
            decision_reason="bounded test result",
        )

        with patch("opentooltrimmer.cli.dissect", return_value=native) as mocked:
            result = main([
                "--repo", "repo",
                "--need", "need",
                "--intended-use", "use",
                "--invocation-correlation-id", correlation,
                "--output", "output",
            ])

        self.assertEqual(result, 0)
        self.assertEqual(
            mocked.call_args.kwargs["invocation_correlation_id"],
            correlation,
        )

    def test_core_echoes_independent_correlations_without_changing_results(self):
        cases = (
            ("first:{opaque}/value?x=1", FIXTURES / "permissive_repo", Decision.ACQUIRE, "MIT"),
            ("second|not-a-uuid", FIXTURES / "gpl_repo", Decision.POINT_ONLY, "GPL-3.0"),
            ("authority-token-looking:value", FIXTURES / "no_license_repo", Decision.HOLD, None),
        )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            emitted_without_receipt: dict[str, bytes] | None = None
            for index, (correlation, repo, expected_decision, expected_license) in enumerate(cases):
                output = root / str(index)
                receipt = dissect(
                    str(repo),
                    "sha256 file hashing",
                    "small internal utility",
                    output,
                    invocation_correlation_id=correlation,
                )
                serialized = json.loads((output / "receipt.json").read_text(encoding="utf-8"))

                self.assertEqual(receipt.invocation_correlation_id, correlation)
                self.assertEqual(serialized["invocation_correlation_id"], correlation)
                self.assertEqual(receipt.decision, expected_decision)
                self.assertEqual(receipt.license.spdx_id, expected_license)

                if expected_decision == Decision.ACQUIRE:
                    current = {
                        path.relative_to(output).as_posix(): path.read_bytes()
                        for path in output.rglob("*")
                        if path.is_file() and path.name != "receipt.json"
                    }
                    if emitted_without_receipt is None:
                        emitted_without_receipt = current

            second_output = root / "second-acquire"
            second = dissect(
                str(FIXTURES / "permissive_repo"),
                "sha256 file hashing",
                "small internal utility",
                second_output,
                invocation_correlation_id="independent-J",
            )
            second_files = {
                path.relative_to(second_output).as_posix(): path.read_bytes()
                for path in second_output.rglob("*")
                if path.is_file() and path.name != "receipt.json"
            }
            self.assertEqual(second.invocation_correlation_id, "independent-J")
            self.assertEqual(second.decision, Decision.ACQUIRE)
            self.assertEqual(second_files, emitted_without_receipt)

    def test_legacy_core_path_does_not_invent_correlation(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "permissive_repo"),
                "sha256 file hashing",
                "small internal utility",
                temp,
            )
            serialized = json.loads((Path(temp) / "receipt.json").read_text(encoding="utf-8"))

            self.assertIsNone(receipt.invocation_correlation_id)
            self.assertIsNone(serialized["invocation_correlation_id"])

    def test_cli_failure_before_receipt_does_not_fabricate_correlation_testimony(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            result = main([
                "--repo", "not-a-local-repository-or-github-url",
                "--need", "need",
                "--intended-use", "use",
                "--invocation-correlation-id", "opaque-I",
                "--output", str(output),
            ])

            self.assertEqual(result, 2)
            self.assertFalse((output / "receipt.json").exists())

    def test_duplicate_validated_mit_license_documents_remain_eligible(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            mit = (FIXTURES / "permissive_repo" / "LICENSE").read_bytes()
            _write_repo(repo, {
                "LICENSE": mit,
                "LICENSE-COPY": mit,
                "cleaner.py": b"def normalize_customer_name(value: str) -> str:\n    return value.strip().lower()\n",
            })

            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertEqual(receipt.license.spdx_id, "MIT")
            self.assertEqual(receipt.decision, Decision.ACQUIRE)
            self.assertEqual(receipt.verification_status, "PASS")

    def test_validated_mit_and_conflicting_gpl_license_documents_hold(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            _write_repo(repo, {
                "LICENSE": (FIXTURES / "permissive_repo" / "LICENSE").read_bytes(),
                "LICENSE-GPL": (FIXTURES / "gpl_repo" / "LICENSE").read_bytes(),
                "cleaner.py": b"def normalize_customer_name(value: str) -> str:\n    return value.strip().lower()\n",
            })

            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertIsNone(receipt.license.spdx_id)
            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertEqual(receipt.verification_status, "NOT_RUN")
            self.assertFalse((root / "output" / "slice").exists())

    def test_validated_mit_and_unknown_license_documents_hold(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            _write_repo(repo, {
                "LICENSE": (FIXTURES / "permissive_repo" / "LICENSE").read_bytes(),
                "LICENSE-RESTRICTIVE": b"Use is prohibited without separate written permission.\n",
                "cleaner.py": b"def normalize_customer_name(value: str) -> str:\n    return value.strip().lower()\n",
            })

            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertIsNone(receipt.license.spdx_id)
            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertEqual(receipt.verification_status, "NOT_RUN")
            self.assertFalse((root / "output" / "slice").exists())

    def test_unvalidated_license_forms_cannot_acquire(self):
        license_samples = {
            "apache": (
                b"Apache License\nVersion 2.0\nAdditional restriction applies.\n",
                ["Apache-2.0"],
                None,
            ),
            "bsd": (
                b"Redistribution and use in source and binary forms are permitted.\nAdditional restriction applies.\n",
                ["BSD-2-Clause"],
                None,
            ),
            "gpl": (
                (FIXTURES / "gpl_repo" / "LICENSE").read_bytes(),
                ["GPL-3.0"],
                "GPL-3.0",
            ),
        }

        for name, (license_bytes, allowlist, expected_spdx) in license_samples.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                repo = root / "repo"
                _write_repo(repo, {
                    "LICENSE": license_bytes,
                    "cleaner.py": b"def normalize_customer_name(value: str) -> str:\n    return value.strip().lower()\n",
                })

                receipt = dissect(
                    str(repo),
                    "normalize customer name",
                    "utility",
                    root / "output",
                    allowlist=allowlist,
                )

                self.assertEqual(receipt.decision, Decision.HOLD)
                self.assertEqual(receipt.license.spdx_id, expected_spdx)
                self.assertEqual(receipt.verification_status, "NOT_RUN")
                self.assertFalse((root / "output" / "slice").exists())

    def test_module_cli_entry_points_show_help(self):
        repository_root = Path(__file__).parent.parent

        for module in ("opentooltrimmer", "opentooltrimmer.cli"):
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, "-m", module, "--help"],
                    cwd=repository_root,
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage: opentooltrimmer", result.stdout)

    def test_substantive_prefix_before_mit_license_holds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            prefixed = (
                b"This document imposes an additional field-of-use condition.\n\n"
                + (FIXTURES / "permissive_repo" / "LICENSE").read_bytes()
            )
            _write_repo(repo, {
                "LICENSE": prefixed,
                "cleaner.py": b"def normalize_customer_name(value: str) -> str:\n    return value.strip().lower()\n",
            })
            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertIsNone(receipt.license.spdx_id)
            self.assertEqual(receipt.verification_status, "NOT_RUN")
            self.assertFalse((root / "output" / "slice").exists())

    def test_static_verification_does_not_execute_candidate_side_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "LICENSE").write_bytes(
                (FIXTURES / "permissive_repo" / "LICENSE").read_bytes()
            )
            sentinel = root / "candidate-executed.txt"
            hidden = repo / "hidden.py"
            hidden.write_text(
                f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            (repo / "cleaner.py").write_text(
                "def normalize_customer_name(\n"
                f"    value: str, payload=__import__('subprocess').check_output([__import__('sys').executable, {str(hidden)!r}])\n"
                ") -> str:\n"
                "    return value.strip().lower()\n",
                encoding="utf-8",
            )
            source_before = (repo / "cleaner.py").read_bytes()
            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertEqual(receipt.decision, Decision.ACQUIRE)
            self.assertEqual(receipt.verification_status, "PASS")
            self.assertIn("without execution", receipt.verification_reason)
            self.assertFalse(sentinel.exists())
            self.assertEqual((repo / "cleaner.py").read_bytes(), source_before)

    def test_modified_mit_body_holds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            canonical = (FIXTURES / "permissive_repo" / "LICENSE").read_bytes()
            modified = canonical.replace(
                b"without limitation the rights",
                b"subject to additional limitations on the rights",
                1,
            )
            _write_repo(repo, {
                "LICENSE": modified,
                "cleaner.py": b"def normalize_customer_name(value: str) -> str:\n    return value.strip().lower()\n",
            })
            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertIsNone(receipt.license.spdx_id)
            self.assertEqual(receipt.verification_status, "NOT_RUN")
            self.assertFalse((root / "output" / "slice").exists())

    def test_comprehension_target_does_not_bind_enclosing_load(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            _write_repo(repo, {
                "LICENSE": (FIXTURES / "permissive_repo" / "LICENSE").read_bytes(),
                "cleaner.py": (
                    b"def normalize_customer_name(value: str) -> str:\n"
                    b"    [PREFIX for PREFIX in ()]\n"
                    b"    return PREFIX + value\n"
                ),
            })
            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertFalse(receipt.dependency_complete_v0_1)
            self.assertIn("global:cleaner.py:PREFIX", receipt.unresolved_project_imports)
            self.assertEqual(receipt.verification_status, "NOT_RUN")

    def test_static_verification_does_not_read_candidate_default_expression(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "LICENSE").write_bytes(
                (FIXTURES / "permissive_repo" / "LICENSE").read_bytes()
            )
            hidden = repo / "hidden.py"
            hidden.write_text("ESCAPED = True\n", encoding="utf-8")
            (repo / "cleaner.py").write_text(
                "def normalize_customer_name(\n"
                f"    value: str, loaded=eval(compile(open({str(hidden)!r}).read(), {str(hidden)!r}, 'exec'), {{}})\n"
                ") -> str:\n"
                "    return value.strip().lower()\n",
                encoding="utf-8",
            )
            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertEqual(receipt.decision, Decision.ACQUIRE)
            self.assertEqual(receipt.verification_status, "PASS")
            self.assertIn("without execution", receipt.verification_reason)

    def test_stale_dependency_cannot_cause_false_acquire(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            provider = root / "provider"
            consumer = root / "consumer"
            output = root / "output"
            license_bytes = (FIXTURES / "permissive_repo" / "LICENSE").read_bytes()
            _write_repo(provider, {
                "LICENSE": license_bytes,
                "cleaner.py": (
                    b"from helper import clean\n\n"
                    b"def normalize_customer_name(value: str) -> str:\n"
                    b"    return clean(value)\n"
                ),
                "helper.py": b"def clean(value: str) -> str:\n    return value.strip().lower()\n",
            })
            _write_repo(consumer, {
                "LICENSE": license_bytes,
                "cleaner.py": (
                    b"import helper\n\n"
                    b"def normalize_customer_name(value: str) -> str:\n"
                    b"    return helper.clean(value)\n"
                ),
            })

            first = dissect(str(provider), "normalize customer name", "utility", output)
            self.assertEqual(first.decision, Decision.ACQUIRE)
            self.assertTrue((output / "slice" / "helper.py").exists())

            second = dissect(str(consumer), "normalize customer name", "utility", output)
            self.assertEqual(second.decision, Decision.HOLD)
            self.assertEqual(second.verification_status, "FAIL")
            self.assertFalse(second.dependency_complete_v0_1)
            self.assertFalse((output / "slice").exists())

    def test_non_acquire_cleans_prior_tool_owned_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, repository, expected in (
                ("hold", FIXTURES / "no_license_repo", Decision.HOLD),
                ("point", FIXTURES / "gpl_repo", Decision.POINT_ONLY),
            ):
                with self.subTest(name=name):
                    output = root / name
                    dissect(
                        str(FIXTURES / "permissive_repo"),
                        "sha256 file hashing",
                        "utility",
                        output,
                    )
                    (output / "keep.txt").write_text("unrelated", encoding="utf-8")
                    receipt = dissect(
                        str(repository),
                        "sha256 file hashing",
                        "utility",
                        output,
                    )
                    self.assertEqual(receipt.decision, expected)
                    self.assertFalse((output / "slice").exists())
                    self.assertFalse((output / "SOURCE_LICENSE.txt").exists())
                    self.assertFalse((output / "PROVENANCE.md").exists())
                    self.assertTrue((output / "keep.txt").exists())

    def test_restrictive_terms_after_mit_license_hold(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            license_bytes = (FIXTURES / "permissive_repo" / "LICENSE").read_bytes()
            _write_repo(repo, {
                "LICENSE": license_bytes + b"\nAdditional restriction: Commercial use is prohibited.\n",
                "cleaner.py": b"def normalize_customer_name(value: str) -> str:\n    return value.strip().lower()\n",
            })
            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertIsNone(receipt.license.spdx_id)
            self.assertIn("additional terms", receipt.license.reason)
            self.assertEqual(receipt.verification_status, "NOT_RUN")
            self.assertFalse((root / "output" / "slice").exists())

    def test_nested_scope_assignment_does_not_bind_enclosing_load(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            _write_repo(repo, {
                "LICENSE": (FIXTURES / "permissive_repo" / "LICENSE").read_bytes(),
                "cleaner.py": (
                    b"def normalize_customer_name(value: str) -> str:\n"
                    b"    def unrelated_nested_scope():\n"
                    b"        PREFIX = 'customer_'\n"
                    b"        return PREFIX\n"
                    b"    return PREFIX + value\n"
                ),
            })
            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertFalse(receipt.dependency_complete_v0_1)
            self.assertIn("global:cleaner.py:PREFIX", receipt.unresolved_project_imports)
            self.assertEqual(receipt.verification_status, "NOT_RUN")

    def test_verification_failure_clears_dependency_completeness(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "broken_import_repo"),
                "normalize customer name",
                "utility",
                temp,
            )
            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertEqual(receipt.verification_status, "FAIL")
            self.assertFalse(receipt.dependency_complete_v0_1)
            self.assertFalse(receipt.code_emitted)
            self.assertEqual(receipt.emitted_slice_bytes, 0)

    def test_static_verification_does_not_run_dynamic_import_expression(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "LICENSE").write_bytes(
                (FIXTURES / "permissive_repo" / "LICENSE").read_bytes()
            )
            (repo / "hidden.py").write_text(
                "def clean(value):\n    return value.strip().lower()\n",
                encoding="utf-8",
            )
            (repo / "cleaner.py").write_text(
                "def normalize_customer_name(\n"
                f"    value: str, helper=(__import__('sys').path.insert(0, {str(repo)!r}) or __import__('hidden'))\n"
                ") -> str:\n"
                "    return helper.clean(value)\n",
                encoding="utf-8",
            )
            receipt = dissect(str(repo), "normalize customer name", "utility", root / "output")

            self.assertEqual(receipt.decision, Decision.ACQUIRE)
            self.assertEqual(receipt.verification_status, "PASS")
            self.assertIn("without execution", receipt.verification_reason)

    def test_permissive_complete_slice_acquires(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "permissive_repo"),
                "sha256 file hashing",
                "small internal utility",
                temp,
            )
            self.assertEqual(receipt.decision, Decision.ACQUIRE)
            self.assertTrue((Path(temp) / "slice" / "hash_utils.py").exists())
            self.assertTrue((Path(temp) / "SOURCE_LICENSE.txt").exists())
            self.assertTrue(receipt.code_emitted)
            self.assertEqual(receipt.verification_status, "PASS")

    def test_non_allowlisted_recognized_license_points_only(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "gpl_repo"),
                "sha256 file hashing",
                "proprietary internal utility",
                temp,
            )
            self.assertEqual(receipt.decision, Decision.POINT_ONLY)
            self.assertFalse((Path(temp) / "slice").exists())
            self.assertFalse(receipt.code_emitted)
            self.assertEqual(receipt.verification_status, "NOT_RUN")

    def test_missing_license_holds(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "no_license_repo"),
                "sha256 file hashing",
                "small internal utility",
                temp,
            )
            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertFalse((Path(temp) / "slice").exists())
            self.assertEqual(receipt.verification_status, "NOT_RUN")

    def test_cross_file_project_dependency_acquires(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "unresolved_repo"),
                "normalize customer name",
                "small internal utility",
                temp,
            )

            self.assertEqual(receipt.decision, Decision.ACQUIRE)
            self.assertTrue(receipt.dependency_complete_v0_1)
            self.assertEqual(receipt.unresolved_project_imports, [])
            self.assertEqual(receipt.verification_status, "PASS")

            slice_root = Path(temp) / "slice"
            
            self.assertTrue((slice_root / "cleaner.py").exists())
            self.assertTrue((slice_root / "helpers" / "__init__.py").exists())

    def test_module_attribute_project_dependency_holds(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "module_attribute_repo"),
                "normalize customer name",
                "small internal utility",
                temp,
            )
            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertFalse(receipt.dependency_complete_v0_1)
            self.assertTrue(receipt.unresolved_project_imports)
            self.assertFalse((Path(temp) / "slice").exists())

    def test_broken_emitted_dependency_fails_verification_and_holds(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "broken_import_repo"),
                "normalize customer name",
                "small internal utility",
                temp,
            )
            self.assertEqual(receipt.decision, Decision.HOLD)
            self.assertEqual(receipt.verification_status, "FAIL")
            self.assertIn("import target is not standard-library or emitted", receipt.verification_reason)
            self.assertFalse(receipt.code_emitted)
            self.assertFalse((Path(temp) / "slice").exists())

    def test_static_verification_rejects_syntax_invalid_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            slice_root = Path(temp)
            (slice_root / "candidate.py").write_bytes(b"def selected(:\n    pass\n")

            status, reason = _verify_slice(slice_root, "candidate.py", "selected")

            self.assertEqual(status, "FAIL")
            self.assertIn("SyntaxError", reason)

    def test_static_verification_rejects_absent_expected_symbol(self):
        with tempfile.TemporaryDirectory() as temp:
            slice_root = Path(temp)
            (slice_root / "candidate.py").write_bytes(b"def other():\n    return 1\n")

            status, reason = _verify_slice(slice_root, "candidate.py", "selected")

            self.assertEqual(status, "FAIL")
            self.assertIn("selected function definition is absent", reason)

    def test_static_verification_accepts_valid_expected_symbol(self):
        with tempfile.TemporaryDirectory() as temp:
            slice_root = Path(temp)
            (slice_root / "candidate.py").write_bytes(b"def selected():\n    return 1\n")

            status, reason = _verify_slice(slice_root, "candidate.py", "selected")

            self.assertEqual(status, "PASS")
            self.assertIn("without execution", reason)

    def test_same_file_static_literal_dependency_acquires_exact_regions(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "global_constant_repo"),
                "make customer name",
                "small internal utility",
                temp,
            )
            self.assertEqual(receipt.decision, Decision.ACQUIRE)
            self.assertTrue(receipt.dependency_complete_v0_1)
            self.assertEqual(receipt.unresolved_project_imports, [])
            self.assertEqual(
                receipt.resolved_static_bindings,
                ["names.py::PREFIX"],
            )
            emitted = (Path(temp) / "slice" / "names.py").read_bytes()
            self.assertIn(b'PREFIX = "customer_"', emitted)
            self.assertIn(b"def make_customer_name", emitted)
            self.assertNotIn(b"import pathlib", emitted)
            self.assertNotIn(b"try:", emitted)

    def test_filetype_shape_static_literal_dependency_is_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "filetype_shape_repo"),
                "get signature bytes",
                "small internal utility",
                temp,
            )

            self.assertEqual(receipt.decision, Decision.ACQUIRE)
            self.assertTrue(receipt.dependency_complete_v0_1)
            self.assertEqual(receipt.unresolved_project_imports, [])
            self.assertEqual(
                receipt.resolved_static_bindings,
                ["utils.py::_NUM_SIGNATURE_BYTES"],
            )
            emitted = (Path(temp) / "slice" / "utils.py").read_bytes()
            self.assertTrue(emitted.startswith(b"_NUM_SIGNATURE_BYTES = 8192"))
            self.assertIn(b"open(path, 'rb')", emitted)
            self.assertIn(b"bytearray(fp.read(_NUM_SIGNATURE_BYTES))", emitted)

    def test_unsupported_module_bindings_remain_unresolved(self):
        cases = {
            "function_call": b"VALUE = compute_value()\n\ndef selected_value():\n    return VALUE\n",
            "attribute_call": b'import os\nVALUE = os.getenv("VALUE")\n\ndef selected_value():\n    return VALUE\n',
            "constructor": b"VALUE = SomeClass()\n\ndef selected_value():\n    return VALUE\n",
            "class": b"class Formatter:\n    pass\n\ndef selected_value():\n    return Formatter()\n",
            "other_global": b"VALUE = OTHER_GLOBAL\n\ndef selected_value():\n    return VALUE\n",
            "multiple": b"VALUE = 1\nVALUE = 2\n\ndef selected_value():\n    return VALUE\n",
            "mutation": b"VALUE = 1\nVALUE += 1\n\ndef selected_value():\n    return VALUE\n",
            "global_rebind": (
                b"VALUE = 1\n\ndef mutate():\n    global VALUE\n    VALUE = 2\n\n"
                b"def selected_value():\n    return VALUE\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                repo = root / "repo"
                _write_repo(
                    repo,
                    {
                        "LICENSE": (FIXTURES / "permissive_repo" / "LICENSE").read_bytes(),
                        "candidate.py": source,
                    },
                )
                receipt = dissect(
                    str(repo), "selected value", "small internal utility", root / "output"
                )

                self.assertEqual(receipt.decision, Decision.HOLD)
                self.assertFalse(receipt.dependency_complete_v0_1)
                self.assertTrue(receipt.unresolved_project_imports)
                self.assertEqual(receipt.resolved_static_bindings, [])
                self.assertFalse((root / "output" / "slice").exists())

    def test_same_file_class_dependency_does_not_false_acquire(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = dissect(
                str(FIXTURES / "global_class_repo"),
                "normalize customer name",
                "small internal utility",
                temp,
            )
            self.assertNotEqual(receipt.decision, Decision.ACQUIRE)
            self.assertFalse(receipt.dependency_complete_v0_1)
            self.assertTrue(receipt.unresolved_project_imports)
            self.assertFalse((Path(temp) / "slice").exists())

    def test_emitted_source_regions_preserve_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            output = root / "output"
            cleaner, helper = _write_byte_preservation_repo(repo)

            receipt = dissect(
                str(repo),
                "normalize customer name",
                "small internal utility",
                output,
            )

            self.assertEqual(receipt.decision, Decision.ACQUIRE)
            emitted_cleaner = (output / "slice" / "cleaner.py").read_bytes()
            emitted_helper = (output / "slice" / "helpers.py").read_bytes()
            expected_function = cleaner[cleaner.index(b"def normalize_customer_name"):-2]
            expected_helper_function = helper[helper.index(b"def clean_name"):-1]

            self.assertEqual(emitted_cleaner[emitted_cleaner.index(b"def "):], expected_function)
            self.assertEqual(emitted_cleaner, cleaner[:-2])
            self.assertIn(b"\r\n", emitted_cleaner)
            self.assertNotIn(b"\n", emitted_cleaner.replace(b"\r\n", b""))
            self.assertEqual(
                emitted_helper[emitted_helper.index(b"def clean_name"):],
                expected_helper_function,
            )
            self.assertEqual(emitted_helper, helper[:-1])
            self.assertIn(b"caf\xe9", emitted_helper)
            self.assertNotIn(b"\r\n", emitted_helper)
            compile(emitted_helper, "helpers.py", "exec")

    def test_receipt_byte_accounting_matches_filesystem(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            output = root / "output"
            _write_byte_preservation_repo(repo)
            expected_source_bytes = sum(
                path.stat().st_size for path in repo.rglob("*") if path.is_file()
            )

            receipt = dissect(
                str(repo),
                "normalize customer name",
                "small internal utility",
                output,
            )
            actual_emitted_bytes = sum(
                path.stat().st_size
                for path in (output / "slice").rglob("*")
                if path.is_file()
            )
            receipt_json = json.loads((output / "receipt.json").read_text(encoding="utf-8"))

            self.assertEqual(receipt.source_repository_bytes, expected_source_bytes)
            self.assertEqual(receipt.emitted_slice_bytes, actual_emitted_bytes)
            self.assertEqual(receipt.trimmed_bytes, expected_source_bytes - actual_emitted_bytes)
            self.assertEqual(receipt.trim_ratio, actual_emitted_bytes / expected_source_bytes)
            self.assertEqual(receipt_json["source_repository_bytes"], expected_source_bytes)
            self.assertEqual(receipt_json["emitted_slice_bytes"], actual_emitted_bytes)
            self.assertEqual(receipt_json["trimmed_bytes"], receipt.trimmed_bytes)
            self.assertEqual(receipt_json["trim_ratio"], receipt.trim_ratio)

    def test_receipt_is_json(self):
        with tempfile.TemporaryDirectory() as temp:
            dissect(
                str(FIXTURES / "permissive_repo"),
                "sha256 file hashing",
                "small internal utility",
                temp,
            )
            data = json.loads((Path(temp) / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(data["decision"], "ACQUIRE")
            self.assertIn("source_snapshot_sha256", data)


if __name__ == "__main__":
    unittest.main()
