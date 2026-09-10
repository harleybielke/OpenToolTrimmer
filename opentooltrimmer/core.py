from __future__ import annotations

import ast
import json
import shutil
import sys
from pathlib import Path

from . import __version__
from .analyzer import (
    build_repository_slices,
    rank_candidates,
    trace_repository_dependencies,
)
from .license_policy import DEFAULT_ALLOWLIST, decide_acquisition, detect_license
from .models import AnalysisReceipt, Decision
from .source import repository_byte_count, resolved_source


def dissect(
    repo_source: str,
    need: str,
    intended_use: str,
    output: str | Path,
    allowlist: list[str] | tuple[str, ...] | None = None,
) -> AnalysisReceipt:
    active_allowlist = tuple(allowlist or DEFAULT_ALLOWLIST)
    output_path = Path(output)
    _clean_output_artifacts(output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    with resolved_source(repo_source) as resolved:
        repo = Path(resolved["root"])
        source_repository_bytes = repository_byte_count(repo)
        finding = detect_license(repo)
        candidates, analyses = rank_candidates(repo, need)

        if not candidates:
            receipt = AnalysisReceipt(
                opentooltrimmer_version=__version__,
                requested_capability=need,
                intended_use=intended_use,
                source=resolved["source"],
                source_revision=resolved["revision"],
                source_snapshot_sha256=resolved["snapshot_sha256"],
                selected=None,
                same_file_helpers=[],
                stdlib_imports=[],
                third_party_imports=[],
                unresolved_project_imports=[],
                dependency_complete_v0_1=False,
                license=finding,
                acquisition_allowlist=list(active_allowlist),
                decision=Decision.HOLD,
                decision_reason="no Python function matched the requested capability strongly enough for V0.1",
                code_emitted=False,
                source_repository_bytes=source_repository_bytes,
                emitted_slice_bytes=0,
                trimmed_bytes=source_repository_bytes,
                trim_ratio=0.0,
                verification_status="NOT_RUN",
                verification_reason="verification applies only to ACQUIRE candidates",
            )
            _write_receipt(output_path, receipt)
            _write_reference(output_path, receipt)
            return receipt

        selected = candidates[0]
        info = analyses[selected.file]
        symbols, stdlib, third_party, unresolved, complete = trace_repository_dependencies(
        analyses,
        selected.file,
        selected.name,
        )
        decision, reason = decide_acquisition(finding, active_allowlist, complete)

        slices = build_repository_slices(analyses, symbols) if decision == Decision.ACQUIRE else {}
        emitted_slice_bytes = sum(len(content) for content in slices.values())

        receipt = AnalysisReceipt(
            opentooltrimmer_version=__version__,
            requested_capability=need,
            intended_use=intended_use,
            source=resolved["source"],
            source_revision=resolved["revision"],
            source_snapshot_sha256=resolved["snapshot_sha256"],
            selected=selected,
            same_file_helpers=[
                f"{file_name}::{symbol_name}"
                for file_name, symbol_name in symbols
                if not (file_name == selected.file and symbol_name == selected.name)
            ],
            stdlib_imports=stdlib,
            third_party_imports=third_party,
            unresolved_project_imports=unresolved,
            dependency_complete_v0_1=complete,
            license=finding,
            acquisition_allowlist=list(active_allowlist),
            decision=decision,
            decision_reason=reason,
            code_emitted=decision == Decision.ACQUIRE,
            source_repository_bytes=source_repository_bytes,
            emitted_slice_bytes=emitted_slice_bytes,
            trimmed_bytes=source_repository_bytes - emitted_slice_bytes,
            trim_ratio=(
                emitted_slice_bytes / source_repository_bytes
                if source_repository_bytes
                else 0.0
            ),
            verification_status="NOT_RUN",
            verification_reason="verification applies only to ACQUIRE candidates",
        )

        if decision == Decision.ACQUIRE:
            slice_root = output_path / "slice"
            slice_root.mkdir(parents=True, exist_ok=True)
            for relative_path, content in slices.items():
                destination = slice_root / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)

            verification_status, verification_reason = _verify_slice(
                slice_root,
                selected.file,
                selected.name,
            )
            receipt.verification_status = verification_status
            receipt.verification_reason = verification_reason

            if verification_status == "FAIL":
                shutil.rmtree(slice_root)
                receipt.decision = Decision.HOLD
                receipt.decision_reason = (
                    "license policy and dependency closure permit acquisition, "
                    f"but emitted-slice verification failed: {verification_reason}"
                )
                receipt.code_emitted = False
                receipt.dependency_complete_v0_1 = False
                receipt.emitted_slice_bytes = 0
                receipt.trimmed_bytes = source_repository_bytes
                receipt.trim_ratio = 0.0

            if receipt.decision == Decision.ACQUIRE and finding.path:
                source_license = repo / finding.path
                if source_license.is_file():
                    shutil.copyfile(
                        source_license,
                        output_path / "SOURCE_LICENSE.txt",
                    )

            notice = repo / "NOTICE"
            if receipt.decision == Decision.ACQUIRE and notice.is_file():
                shutil.copyfile(
                    notice,
                    output_path / "SOURCE_NOTICE.txt",
                )

            if receipt.decision == Decision.ACQUIRE:
                _write_provenance(output_path, receipt)

    _write_receipt(output_path, receipt)
    _write_reference(output_path, receipt)

    return receipt


def _clean_output_artifacts(output: Path) -> None:
    slice_root = output / "slice"
    if slice_root.is_dir():
        shutil.rmtree(slice_root)
    elif slice_root.exists():
        slice_root.unlink()

    for name in (
        "receipt.json",
        "REFERENCE.md",
        "SOURCE_LICENSE.txt",
        "SOURCE_NOTICE.txt",
        "PROVENANCE.md",
    ):
        artifact = output / name
        if artifact.is_file() or artifact.is_symlink():
            artifact.unlink()


def _verify_slice(
    slice_root: Path,
    selected_file: str,
    selected_name: str,
) -> tuple[str, str]:
    parsed: dict[str, ast.Module] = {}
    python_files = sorted(path for path in slice_root.rglob("*.py") if path.is_file())

    for path in python_files:
        relative = path.relative_to(slice_root).as_posix()
        try:
            source = path.read_bytes()
            tree = ast.parse(source, filename=relative)
            compile(source, relative, "exec", dont_inherit=True)
        except (OSError, SyntaxError, UnicodeError) as exc:
            return "FAIL", f"static verification failed for {relative}: {type(exc).__name__}: {exc}"
        parsed[relative] = tree

    selected_relative = Path(selected_file).as_posix()
    selected_tree = parsed.get(selected_relative)
    if selected_tree is None:
        return "FAIL", f"selected module is absent from emitted slice: {selected_relative}"

    selected_symbols = {
        node.name
        for node in selected_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if selected_name not in selected_symbols:
        return "FAIL", f"selected function definition is absent: {selected_relative}::{selected_name}"

    for relative, tree in parsed.items():
        for node in tree.body:
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    return "FAIL", f"relative import is unsupported in emitted slice: {relative}"
                modules = [node.module or ""]
            else:
                continue

            for module in modules:
                top = module.split(".")[0]
                if top in sys.stdlib_module_names:
                    continue
                if _emitted_module_path(slice_root, module) is None:
                    return "FAIL", f"import target is not standard-library or emitted: {module}"

                if isinstance(node, ast.ImportFrom):
                    target_path = _emitted_module_path(slice_root, module)
                    target_tree = parsed.get(target_path.relative_to(slice_root).as_posix()) if target_path else None
                    if target_tree is None:
                        return "FAIL", f"emitted import target could not be inspected: {module}"
                    available = {
                        child.name
                        for child in target_tree.body
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    }
                    available.update(
                        child.targets[0].id
                        for child in target_tree.body
                        if isinstance(child, ast.Assign)
                        and len(child.targets) == 1
                        and isinstance(child.targets[0], ast.Name)
                    )
                    for alias in node.names:
                        if alias.name != "*" and alias.name not in available:
                            return "FAIL", f"imported symbol is absent from emitted target: {module}:{alias.name}"

    return "PASS", f"statically parsed and compiled emitted Python without execution; found {selected_relative}::{selected_name}"


def _emitted_module_path(slice_root: Path, module: str) -> Path | None:
    base = slice_root.joinpath(*module.split("."))
    candidates = (base.with_suffix(".py"), base / "__init__.py")
    return next((path for path in candidates if path.is_file()), None)


def _write_receipt(output: Path, receipt: AnalysisReceipt) -> None:
    (output / "receipt.json").write_text(json.dumps(receipt.to_dict(), indent=2) + "\n", encoding="utf-8")


def _write_reference(output: Path, receipt: AnalysisReceipt) -> None:
    selected = receipt.selected
    selected_text = "No candidate selected."
    if selected:
        selected_text = f"{selected.file} :: {selected.name}() :: lines {selected.line_start}-{selected.line_end}"
    text = f"""# OpenToolTrimmer Result\n\nDecision: **{receipt.decision.value}**\n\nRequested capability: {receipt.requested_capability}\n\nSource: {receipt.source}\n\nSelected: {selected_text}\n\nReason: {receipt.decision_reason}\n\nCode emitted: {'YES' if receipt.code_emitted else 'NO'}\n"""
    (output / "REFERENCE.md").write_text(text, encoding="utf-8")


def _write_provenance(output: Path, receipt: AnalysisReceipt) -> None:
    selected = receipt.selected
    text = f"""# Provenance\n\n- Source: {receipt.source}\n- Revision: {receipt.source_revision or 'not available'}\n- Source snapshot SHA-256: `{receipt.source_snapshot_sha256}`\n- License detected: {receipt.license.spdx_id}\n- License file: {receipt.license.path}\n- Selected file: {selected.file if selected else 'none'}\n- Selected symbol: {selected.name if selected else 'none'}\n- Same-file helpers: {', '.join(receipt.same_file_helpers) or 'none'}\n- Decision: {receipt.decision.value}\n\nThe emitted slice is provided only because the active OpenToolTrimmer acquisition policy allowed the detected license and V0.1 established dependency closure within its declared scope. Preserve and review the accompanying source license before reuse.\n"""
    (output / "PROVENANCE.md").write_text(text, encoding="utf-8")
