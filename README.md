# OpenToolTrimmer

**Find the smallest policy-compatible reusable piece of an open-source Python tool that V0.1 can currently prove.**

Sometimes you do not need another dependency.

You need one function.

One parser. One formatter. One conversion routine. One small capability that somebody has already solved inside a much larger open-source project.

OpenToolTrimmer is an experimental Python utility for finding that capability, tracing the project-local code it depends on, checking whether the recognized source license is allowed by the configured acquisition policy, and emitting the smallest dependency-complete slice it can currently prove.

It keeps a receipt of what it found, what it copied, why the configured policy allowed acquisition, and what it could not prove. The `intended_use` value is recorded in that receipt but is not interpreted by V0.1.

```text
need
  ↓
source repository
  ↓
candidate capability
  ↓
dependency closure
  ↓
reuse boundary
  ↓
verification
  ↓
minimal source slice + receipt
```

## Why?

Open source gives us enormous amounts of useful code, but reuse often comes with an awkward choice:

- add an entire package for one tiny capability, or
- manually dig through somebody else's repository and figure out what can safely be reused.

OpenToolTrimmer explores a third option:

Find the smallest policy-compatible dependency-complete piece that preserves the capability you actually need within the configured allowlist and V0.1's proven scope.

The policy boundary matters just as much as smallest.

Finding code does not automatically mean you are allowed to take it. Likewise, finding a function does not mean that function is complete without the imports, helpers, constants, or other project-local material it depends on.

OpenToolTrimmer therefore treats discovery, dependency completeness, reuse authority, and verification as separate questions.

## Current status

OpenToolTrimmer is an early V0.1 implementation focused on Python repositories.

The current release can:

- search Python functions for a requested capability
- select a candidate from a natural-language need
- trace supported project-local dependencies across files
- preserve selected source regions byte-for-byte
- classify a deliberately small set of recognized license forms
- distinguish policy-allowed acquisition from reference-only or unresolved cases
- emit a dependency-complete source slice when the current evidence supports it
- structurally verify that the emitted module imports and the selected callable exists
- preserve license and provenance evidence
- produce byte accounting for the source snapshot and emitted slice
- fail conservatively when the current implementation cannot prove a required condition

V0.1 deliberately prefers HOLD over pretending an unsupported dependency shape is complete.

## Decisions

Every run ends in one of three decisions.

### ACQUIRE

The detected license is allowed by the configured acquisition policy and OpenToolTrimmer has enough evidence, within its current V0.1 capabilities, to support the dependency and verification claims.

Code may be emitted along with provenance and license evidence.

### POINT_ONLY

The repository contains something useful, but the detected license is not allowed by the configured acquisition policy.

The tool can identify the source location without copying the code.

### HOLD

Something material remains unresolved.

Examples include:

- missing or unrecognized license evidence
- unsupported dependency shapes
- unresolved project-local dependencies
- failed structural verification
- ambiguous reuse authority

HOLD is intentional. Unknown does not become permission simply because returning an answer would be convenient.

## Usage

From a local checkout:

```bash
python -m pip install -e .
```

Then:

```bash
opentooltrimmer \
  --repo path/to/source-repository \
  --need "describe the capability you need" \
  --intended-use "describe how you intend to reuse it"
```

Module execution is also supported:

```bash
python -m opentooltrimmer \
  --repo path/to/source-repository \
  --need "describe the capability you need" \
  --intended-use "describe how you intend to reuse it"
```

And:

```bash
python -m opentooltrimmer.cli --help
```

Use:

```bash
opentooltrimmer --help
```

for the current CLI options, including license-policy configuration and output location.

## Example

A real V0.1 trial was run against the public Python repository `jlevy/strif` at commit:

```text
f66ba7e7921130d8bd4c3a2ad3f7535845d55343
```

The request was:

```text
Abbreviate a string to a maximum length and add an ellipsis when truncated.
```

OpenToolTrimmer selected:

```text
src/strif/strif.py::abbrev_str
```

The run produced:

```text
Decision:                ACQUIRE
License:                 MIT
Dependency complete:     true
Verification:            PASS

Source snapshot:         153,087 bytes
Emitted source slice:        596 bytes
Retained:                 ~0.3893%
```

The emitted function was byte-identical to the selected source region, the copied license was byte-identical to the repository LICENSE, and the receipt byte totals matched the resulting filesystem.

The trial used a clean clone at the recorded commit and the emitted slice was not altered after extraction.

This is one successful example, not a claim that V0.1 can safely trim arbitrary Python repositories.

## Output

A successful ACQUIRE run may produce a structure similar to:

```text
opentooltrimmer_output/
├── slice/
│   └── ...
├── receipt.json
├── PROVENANCE.md
├── REFERENCE.md
└── SOURCE_LICENSE.txt
```

A source NOTICE may also be preserved when applicable.

The exact artifacts depend on the decision and the source repository.

POINT_ONLY and HOLD do not emit reusable source code.

## The receipt

OpenToolTrimmer is intentionally receipt-heavy.

The receipt records evidence about the run rather than merely saying "success."

Depending on the outcome, that includes information such as:

- selected source file and symbol
- source regions
- dependency status
- unresolved dependencies
- license classification
- decision and reason
- verification status and reason
- whether code was emitted
- source repository byte count
- emitted slice byte count
- trimmed byte count
- trim ratio

The receipt is evidence about what OpenToolTrimmer actually established during that run. It is not a legal opinion and it should not be interpreted as proving more than the recorded checks support.

## What "smallest" means in V0.1

OpenToolTrimmer does not currently claim to find the globally smallest mathematically possible program.

V0.1 minimizes at the level of the source regions and supported dependency relationships it can presently prove.

Selected source regions are preserved exactly, but separators between non-contiguous regions may be synthesized during reconstruction.

A smaller result is only better if all required invariants still hold:

- the requested capability remains represented
- supported dependency closure remains complete
- verification succeeds
- provenance remains accountable
- acquisition remains allowed by the configured policy

If removing something breaks one of those conditions, it was not excess.

## Verification boundary

V0.1 performs structural verification.

For an ACQUIRE candidate, it verifies that the emitted module can be imported under the current verification boundary and that the selected symbol resolves as a callable.

That is useful, but deliberately limited.

A PASS does not prove:

- semantic correctness of the function
- correctness for every possible input
- runtime resource closure after the function is called
- absence of every possible filesystem or process escape
- OS-level sandbox containment
- safety of arbitrary native code

OpenToolTrimmer contains conservative checks intended to prevent the original source repository from silently satisfying verification through supported Python-observable escape routes. These checks are not an operating-system security sandbox.

## Current V0.1 boundaries

OpenToolTrimmer intentionally has a narrow first contract.

Among the current limitations:

- Python only
- dependency analysis supports only the dependency shapes V0.1 explicitly understands
- relative imports are unsupported in V0.1
- module attributes and other unresolved forms may produce HOLD
- runtime files accessed only after calling the selected function are not currently proven as part of dependency closure
- structural verification is not semantic testing
- license recognition is deliberately narrow
- license classification is not legal advice
- source snapshot byte accounting follows the tool's repository-ignore policy
- exact preservation refers to included source regions, not necessarily a byte-identical reconstruction of the original whole file
- no OS-level execution sandbox is claimed

These are boundaries, not promises hidden behind a green test result.

## License handling

V0.1 intentionally avoids broad legal interpretation.

The built-in V0.1 acquisition allowlist contains only MIT. MIT acquisition requires one of the complete normalized MIT document forms that the current implementation explicitly validates. Substantive additions, removals, or modifications to those forms cause the tool to fail conservatively rather than infer permission. Other recognized licenses may support a reference-only result, but adding an unvalidated license to the configured allowlist cannot make it acquirable in V0.1. Unrecognized license evidence produces HOLD.

OpenToolTrimmer's license decision is a software policy decision based on the evidence it recognizes.

It is not legal advice.

Always review the source project's license and your obligations before redistributing code.

## Testing

The current V0.1 release has 27 tests passing.

The suite includes permanent regressions for failures discovered during external adversarial testing, including:

- stale output contaminating later verification
- prior source artifacts surviving HOLD or POINT_ONLY
- contradictory license modifications being treated as permissive
- Python scope mistakes creating false dependency completeness
- missing dependencies disagreeing with receipt claims
- verification reaching back into the original repository
- child-process verification escape
- CLI entry-point consistency

The project was also tested using disposable external hostile fixtures before those failures were converted into permanent regressions.

Passing this suite does not mean OpenToolTrimmer is bug-free. It means the current V0.1 claims have been exercised against the cases presently covered.

## Design posture

OpenToolTrimmer follows a simple rule:

The method must never contradict the goal.

A tool whose purpose is to extract the smallest policy-compatible, dependency-complete piece it can currently prove cannot reach that goal by quietly ignoring licensing, inventing dependency completeness, or verifying against code it did not actually emit.

So when OpenToolTrimmer cannot establish something important, V0.1 is designed to stop rather than bluff.

## Project scope

OpenToolTrimmer is currently an experimental local developer tool.

Future work may explore:

- additional Python dependency shapes
- stronger source minimization
- broader language support
- richer capability discovery
- additional license-policy support
- stronger verification strategies

Those are directions, not V0.1 claims.

For now, the question is deliberately smaller:

Can we take a real open-source repository, describe one capability we need, and recover the smallest piece we can honestly prove is policy-compatible under the configured allowlist?

V0.1 is the first working answer.

## License

OpenToolTrimmer itself is released under the MIT License.

See LICENSE.
