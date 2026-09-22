from __future__ import annotations

import ast
import builtins
import hashlib
import io
import re
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path

from .models import CandidateFunction

STOPWORDS = {
    "a", "an", "and", "the", "to", "of", "for", "from", "with", "into", "by", "in", "on",
    "function", "tool", "utility", "code", "python", "need", "want", "that", "this", "file", "files",
}

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "build",
    "dist",
}

@dataclass
class ImportBinding:
    module: str
    symbol: str | None
    project_local: bool
    relative_level: int = 0

@dataclass
class FileAnalysis:
    path: Path
    relative: str
    source_bytes: bytes
    encoding: str
    source: str
    tree: ast.Module
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    imports: dict[str, ImportBinding]  # alias -> (top module, project-local candidate)
    module_bindings: dict[str, list[ast.AST]]


def _terms(text: str) -> set[str]:
    words = set(re.findall(r"[a-z0-9]+", text.lower()))
    return {w for w in words if len(w) > 2 and w not in STOPWORDS}


def _split_identifier(name: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return _terms(spaced.replace("_", " ").replace("-", " "))


def _load_python_file(path: Path, repo: Path) -> FileAnalysis | None:
    try:
        source_bytes = path.read_bytes()
        encoding, _ = tokenize.detect_encoding(io.BytesIO(source_bytes).readline)
        source = source_bytes.decode(encoding)
        tree = ast.parse(source_bytes)
    except (OSError, SyntaxError, UnicodeError):
        return None

    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    local_module_roots = {p.name for p in repo.iterdir() if p.is_dir()} | {p.stem for p in repo.glob("*.py")}

    imports: dict[str, ImportBinding] = {}

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                top = alias.name.split(".")[0]
                imports[bound] = ImportBinding(
                    module=alias.name,
                    symbol=None,
                    project_local=top in local_module_roots,
                )

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            top = module.split(".")[0] if module else ""
            project_local = node.level > 0 or top in local_module_roots

            for alias in node.names:
                bound = alias.asname or alias.name
                imports[bound] = ImportBinding(
                    module=module,
                    symbol=alias.name,
                    project_local=project_local,
                    relative_level=node.level,
                )

    module_bindings: dict[str, list[ast.AST]] = {}
    for statement in tree.body:
        names = _module_statement_bound_names(statement)
        names.update(_module_statement_potentially_mutated_names(statement))
        for name in names:
            module_bindings.setdefault(name, []).append(statement)
        globally_rebound = {
            name
            for child in ast.walk(statement)
            if isinstance(child, ast.Global)
            for name in child.names
        }
        for name in globally_rebound:
            if statement not in module_bindings.get(name, []):
                module_bindings.setdefault(name, []).append(statement)

    return FileAnalysis(
        path,
        path.relative_to(repo).as_posix(),
        source_bytes,
        encoding,
        source,
        tree,
        functions,
        imports,
        module_bindings,
    )


def _module_statement_bound_names(statement: ast.stmt) -> set[str]:
    """Collect bindings made by one module statement without entering scopes."""
    bound: set[str] = set()

    class BindingVisitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                bound.add(node.id)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            bound.add(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            bound.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            bound.add(node.name)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_ListComp(self, node: ast.ListComp) -> None:
            return

        def visit_SetComp(self, node: ast.SetComp) -> None:
            return

        def visit_DictComp(self, node: ast.DictComp) -> None:
            return

        def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
            return

    BindingVisitor().visit(statement)
    return bound


def _module_statement_potentially_mutated_names(statement: ast.stmt) -> set[str]:
    """Conservatively reject bindings passed to or mutated by module code."""
    mutated: set[str] = set()

    def loaded_names(node: ast.AST) -> set[str]:
        return {
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
        }

    class MutationVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute):
                mutated.update(loaded_names(node.func.value))
            for argument in node.args:
                mutated.update(loaded_names(argument))
            for keyword in node.keywords:
                mutated.update(loaded_names(keyword.value))
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                if isinstance(target, (ast.Attribute, ast.Subscript)):
                    mutated.update(loaded_names(target))
            self.visit(node.value)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if isinstance(node.target, (ast.Attribute, ast.Subscript)):
                mutated.update(loaded_names(node.target))
            if node.value is not None:
                self.visit(node.value)

        def visit_Delete(self, node: ast.Delete) -> None:
            for target in node.targets:
                mutated.update(loaded_names(target))

    MutationVisitor().visit(statement)
    return mutated


def _static_literal_binding(info: FileAnalysis, name: str) -> ast.AST | None:
    """Prove one narrow direct module binding without evaluating source."""
    bindings = info.module_bindings.get(name, [])
    if len(bindings) != 1:
        return None

    node = bindings[0]
    value: ast.AST | None = None
    if (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ):
        value = node.value
    elif (
        isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == name
    ):
        value = node.value

    if not isinstance(value, ast.Constant):
        return None
    if type(value.value) not in {int, float, str, bytes, bool, type(None)}:
        return None
    return node


def _python_files(repo: Path):
    for path in repo.rglob("*.py"):
        if any(part in IGNORED_DIRS for part in path.relative_to(repo).parts):
            continue
        yield path


def rank_candidates(repo: Path, need: str) -> tuple[list[CandidateFunction], dict[str, FileAnalysis]]:
    need_terms = _terms(need)
    analyses: dict[str, FileAnalysis] = {}
    candidates: list[CandidateFunction] = []

    for path in _python_files(repo):
        info = _load_python_file(path, repo)
        if not info:
            continue
        analyses[info.relative] = info
        for name, node in info.functions.items():
            name_terms = _split_identifier(name)
            doc_terms = _terms(ast.get_docstring(node) or "")
            segment = ast.get_source_segment(info.source, node) or ""
            source_terms = _terms(segment)

            name_hits = need_terms & name_terms
            doc_hits = need_terms & doc_terms
            source_hits = need_terms & source_terms
            score = len(name_hits) * 6 + len(doc_hits) * 4 + len(source_hits)
            if score <= 0:
                continue
            matched = sorted(name_hits | doc_hits | source_hits)
            candidates.append(
                CandidateFunction(
                    file=info.relative,
                    name=name,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    score=score,
                    matched_terms=matched,
                )
            )

    candidates.sort(key=lambda c: (-c.score, (c.line_end - c.line_start), c.file, c.name))
    return candidates, analyses


def _called_names(node: ast.AST) -> set[str]:
    called = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
            called.add(child.func.id)
    return called


def _used_names(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _locally_bound_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    arguments = node.args
    bound = {
        argument.arg
        for argument in (
            arguments.posonlyargs
            + arguments.args
            + arguments.kwonlyargs
        )
    }
    if arguments.vararg:
        bound.add(arguments.vararg.arg)
    if arguments.kwarg:
        bound.add(arguments.kwarg.arg)
    class LocalBindingVisitor(ast.NodeVisitor):
        def visit_Name(self, child: ast.Name) -> None:
            if isinstance(child.ctx, ast.Store):
                bound.add(child.id)

        def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
            bound.add(child.name)

        def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:
            bound.add(child.name)

        def visit_ClassDef(self, child: ast.ClassDef) -> None:
            bound.add(child.name)

        def visit_Lambda(self, child: ast.Lambda) -> None:
            return

        def visit_ListComp(self, child: ast.ListComp) -> None:
            return

        def visit_SetComp(self, child: ast.SetComp) -> None:
            return

        def visit_DictComp(self, child: ast.DictComp) -> None:
            return

        def visit_GeneratorExp(self, child: ast.GeneratorExp) -> None:
            return

    visitor = LocalBindingVisitor()
    for statement in node.body:
        visitor.visit(statement)
    return bound


def _loaded_names(node: ast.AST) -> set[str]:
    loaded: set[str] = set()

    class LoadedNameVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.comprehension_bound: set[str] = set()

        def visit_Name(self, child: ast.Name) -> None:
            if isinstance(child.ctx, ast.Load) and child.id not in self.comprehension_bound:
                loaded.add(child.id)

        def _visit_comprehension(
            self,
            child: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        ) -> None:
            previous = set(self.comprehension_bound)
            for generator in child.generators:
                self.visit(generator.iter)
                self.comprehension_bound.update(
                    target.id
                    for target in ast.walk(generator.target)
                    if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store)
                )
                for condition in generator.ifs:
                    self.visit(condition)
            if isinstance(child, ast.DictComp):
                self.visit(child.key)
                self.visit(child.value)
            else:
                self.visit(child.elt)
            self.comprehension_bound = previous

        def visit_ListComp(self, child: ast.ListComp) -> None:
            self._visit_comprehension(child)

        def visit_SetComp(self, child: ast.SetComp) -> None:
            self._visit_comprehension(child)

        def visit_DictComp(self, child: ast.DictComp) -> None:
            self._visit_comprehension(child)

        def visit_GeneratorExp(self, child: ast.GeneratorExp) -> None:
            self._visit_comprehension(child)

    LoadedNameVisitor().visit(node)
    return loaded

def _module_candidates(module: str) -> list[str]:
    base = module.replace(".", "/")
    return [
        f"{base}.py",
        f"{base}/__init__.py",
    ]


def _resolve_imported_function(
    analyses: dict[str, FileAnalysis],
    binding: ImportBinding,
) -> tuple[FileAnalysis, str] | None:
    if not binding.project_local or not binding.symbol:
        return None

    for candidate in _module_candidates(binding.module):
        info = analyses.get(candidate)
        if info and binding.symbol in info.functions:
            return info, binding.symbol

    return None

def trace_repository_dependencies(
    analyses: dict[str, FileAnalysis],
    selected_file: str,
    selected_name: str,
    ):
    selected_info = analyses[selected_file]

    queue: list[tuple[str, str]] = [(selected_file, selected_name)]
    seen: set[tuple[str, str]] = set()

    symbols: list[tuple[str, str]] = []
    stdlib: set[str] = set()
    third_party: set[str] = set()
    unresolved_project: set[str] = set()
    static_bindings: set[tuple[str, str]] = set()

    while queue:
        file_name, function_name = queue.pop(0)
        key = (file_name, function_name)

        if key in seen:
            continue

        seen.add(key)

        info = analyses[file_name]
        node = info.functions[function_name]
        symbols.append(key)

        called = _called_names(node)
        used = _used_names(node)

        proven_names = (
            _locally_bound_names(node)
            | set(dir(builtins))
            | set(info.functions)
            | set(info.imports)
        )
        for name in sorted(_loaded_names(node) - proven_names):
            if _static_literal_binding(info, name) is not None:
                static_bindings.add((info.relative, name))
            else:
                unresolved_project.add(f"global:{info.relative}:{name}")

        # Same-file calls.
        for name in sorted(called):
            if name in info.functions:
                queue.append((file_name, name))

        # Imported names actually used by this function.
        for bound, binding in info.imports.items():
            if bound not in used:
                continue

            if not binding.project_local:
                top = binding.module.split(".")[0]

                if top in sys.stdlib_module_names:
                    stdlib.add(top)
                else:
                    third_party.add(top)

                continue

            resolved = _resolve_imported_function(analyses, binding)

            if resolved:
                target_info, target_name = resolved
                queue.append((target_info.relative, target_name))
            else:
                unresolved_project.add(
                    f"{binding.module}:{binding.symbol or bound}"
                )

    dependency_complete = not unresolved_project

    return (
        symbols,
        sorted(stdlib),
        sorted(third_party),
        sorted(unresolved_project),
        sorted(static_bindings),
        dependency_complete,
    )

def trace_same_file_dependencies(info: FileAnalysis, selected_name: str):
    selected = info.functions[selected_name]
    closure: list[str] = []
    seen = {selected_name}
    queue = list(_called_names(selected))

    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        if name in info.functions:
            seen.add(name)
            closure.append(name)
            queue.extend(sorted(_called_names(info.functions[name])))

    nodes = [selected] + [info.functions[name] for name in closure]
    used = set().union(*(_used_names(node) for node in nodes))

    stdlib: set[str] = set()
    third_party: set[str] = set()
    unresolved_project: set[str] = set()

    for bound, binding in info.imports.items():
       if bound not in used:
        continue

    module = binding.module
    project_local = binding.project_local

    if project_local:
        unresolved_project.add(module or bound)
    elif module.split(".")[0] in sys.stdlib_module_names:
        stdlib.add(module.split(".")[0])
    else:
        third_party.add(module.split(".")[0])

    dependency_complete = not unresolved_project
    return closure, sorted(stdlib), sorted(third_party), sorted(unresolved_project), dependency_complete


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def build_slice(info: FileAnalysis, selected_name: str, helpers: list[str]) -> str:
    selected = info.functions[selected_name]
    nodes = [selected] + [info.functions[name] for name in helpers]
    used = set().union(*(_used_names(node) for node in nodes))

    lines = info.source.splitlines()
    pieces: list[str] = []

    # Preserve leading comments / shebang / encoding header before first AST node.
    first_code_line = min((getattr(node, "lineno", 1) for node in info.tree.body), default=1)
    header = "\n".join(lines[: first_code_line - 1]).strip()
    if header:
        pieces.append(header)

    for node in info.tree.body:
        if isinstance(node, ast.Import):
            bound_names = [alias.asname or alias.name.split(".")[0] for alias in node.names]
            if any(name in used for name in bound_names):
                pieces.append("\n".join(lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)]))
        elif isinstance(node, ast.ImportFrom):
            bound_names = [alias.asname or alias.name for alias in node.names]
            if any(name in used for name in bound_names):
                pieces.append("\n".join(lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)]))

    ordered = sorted(nodes, key=lambda n: n.lineno)
    for node in ordered:
        pieces.append("\n".join(lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)]))

    return "\n\n".join(piece.rstrip() for piece in pieces if piece.strip()) + "\n"

def build_repository_slices(
    analyses: dict[str, FileAnalysis],
    symbols: list[tuple[str, str]],
    static_bindings: list[tuple[str, str]],
) -> dict[str, bytes]:
    by_file: dict[str, list[str]] = {}
    bindings_by_file: dict[str, list[str]] = {}

    for file_name, symbol_name in symbols:
        by_file.setdefault(file_name, []).append(symbol_name)
    for file_name, binding_name in static_bindings:
        bindings_by_file.setdefault(file_name, []).append(binding_name)

    output: dict[str, bytes] = {}

    for file_name in sorted(set(by_file) | set(bindings_by_file)):
        info = analyses[file_name]
        names = by_file.get(file_name, [])
        nodes = [info.functions[name] for name in names]
        used = set().union(*(_used_names(node) for node in nodes)) if nodes else set()

        pieces: list[bytes] = []

        for node in info.tree.body:
            if isinstance(node, ast.Import):
                bound_names = [
                    alias.asname or alias.name.split(".")[0]
                    for alias in node.names
                ]

                if any(name in used for name in bound_names):
                    pieces.append(_node_source_bytes(info, node))

            elif isinstance(node, ast.ImportFrom):
                bound_names = [
                    alias.asname or alias.name
                    for alias in node.names
                ]

                if any(name in used for name in bound_names):
                    pieces.append(_node_source_bytes(info, node))

        binding_nodes = [
            _static_literal_binding(info, name)
            for name in bindings_by_file.get(file_name, [])
        ]
        emitted_nodes = nodes + [node for node in binding_nodes if node is not None]
        for node in sorted(emitted_nodes, key=lambda item: item.lineno):
            pieces.append(_node_source_bytes(info, node))

        newline = _source_newline(info.source_bytes)
        body = (newline * 2).join(piece for piece in pieces if piece)
        encoding_prefix = _source_encoding_prefix(info.source_bytes)
        if encoding_prefix:
            separator = newline if encoding_prefix.endswith((b"\n", b"\r")) else b""
            body = encoding_prefix + separator + body
        output[file_name] = body

    return output


def _source_newline(source: bytes) -> bytes:
    crlf = source.find(b"\r\n")
    lf = source.find(b"\n")
    cr = source.find(b"\r")
    candidates = [
        (position, newline)
        for position, newline in ((crlf, b"\r\n"), (lf, b"\n"), (cr, b"\r"))
        if position >= 0
    ]
    return min(candidates, default=(0, b"\n"), key=lambda item: item[0])[1]


def _source_encoding_prefix(source: bytes) -> bytes:
    lines = source.splitlines(keepends=True)
    coding = re.compile(br"coding[:=][ \t]*[-_.a-zA-Z0-9]+")
    for index, line in enumerate(lines[:2]):
        if coding.search(line):
            return b"".join(lines[: index + 1])
    if source.startswith(b"\xef\xbb\xbf"):
        return b"\xef\xbb\xbf"
    return b""


def _node_source_bytes(info: FileAnalysis, node: ast.AST) -> bytes:
    raw_lines = info.source_bytes.splitlines(keepends=True)
    text_lines = info.source.splitlines(keepends=True)
    start_line = node.lineno - 1
    end_line = getattr(node, "end_lineno", node.lineno) - 1

    raw_starts: list[int] = []
    position = 0
    for raw_line in raw_lines:
        raw_starts.append(position)
        position += len(raw_line)

    content_encoding = "utf-8" if info.encoding.lower().replace("_", "-") == "utf-8-sig" else info.encoding
    bom_bytes = 3 if info.source_bytes.startswith(b"\xef\xbb\xbf") else 0

    def raw_offset(line_index: int, utf8_column: int) -> int:
        utf8_line = text_lines[line_index].encode("utf-8")
        prefix = utf8_line[:utf8_column].decode("utf-8")
        line_bom = bom_bytes if line_index == 0 else 0
        return raw_starts[line_index] + line_bom + len(prefix.encode(content_encoding))

    start = raw_offset(start_line, node.col_offset)
    end = raw_offset(end_line, getattr(node, "end_col_offset", node.col_offset))
    return info.source_bytes[start:end]
