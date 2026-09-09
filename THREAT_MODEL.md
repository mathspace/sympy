# sympy threat model

## 1. Overview

This snapshot identifies itself as SymPy `0.7.7.dev`, a symbolic mathematics Python library with expression objects, parsers, solvers, numeric evaluation and printers (`sympy/release.py:1`). Packaging installs the `isympy` interactive entry point and requires mpmath (`setup.py:327`, `setup.py:353`). Normal use is a caller-owned Python process. Optional capabilities generate Python callables, compile native modules, render TeX and open viewers. Separate Fabric/Vagrant tools build and publish releases, documentation and website updates.

The principal runtime flow is input → symbolic expression → computation or output. Several entry points deliberately cross into stronger interpreters: string parsing reaches Python evaluation; lambdify evaluates generated Python; autowrap compiles and imports native code; preview runs external TeX/conversion/viewer programs. Their controls and caller obligations differ. None should be inferred to be an untrusted-math sandbox merely because it belongs to a mathematics library.

| Component | Input and authority | Evidence |
| --- | --- | --- |
| Sympification/parser | Objects or strings → expression construction/Python evaluation | `sympy/core/sympify.py:322`, `sympy/parsing/sympy_parser.py:800` |
| Symbolic/numeric library | Expression processing within host Python authority | `sympy/release.py:1`, `setup.py:353` |
| Lambdify | Expressions, names and module mappings → evaluated callable | `sympy/utilities/lambdify.py:325`, `sympy/utilities/lambdify.py:387` |
| Native wrapping | Generated source → compiler backend → imported module | `sympy/utilities/autowrap.py:135` |
| Preview | TeX/expression/settings → external renderer and optional viewer | `sympy/printing/preview.py:182`, `sympy/printing/preview.py:201` |
| Release tools | Maintainer checkout/configuration/credentials → build and publication | `release/fabfile.py:256`, `release/fabfile.py:885` |

The following table records the important effective resources without enumerating every generated intermediate file.

| Workflow | Configuration chain | Effective resource or capability | Recipient/control | Evidence |
| --- | --- | --- | --- | --- |
| String parsing | sympify → parse_expr → transformed code → eval | Python evaluation with caller locals/globals; default globals import SymPy | Host process; transformations are not isolation | `sympy/parsing/sympy_parser.py:894`, `sympy/parsing/sympy_parser.py:806` |
| Lambda creation | Selected modules and expression implementations → namespace → eval | Callable using assembled namespace, builtins and range | Host/selected numeric modules; trusted inputs required | `sympy/utilities/lambdify.py:325`, `sympy/utilities/lambdify.py:385` |
| Native wrapping | Explicit tempdir or new temporary directory → source/build/import | Default OS-temp `<random>_sympy_compile/wrapped_code_<counter>` and `wrapper_module_<counter>`; explicit directories retained | Compilers and host module loader; default directory cleanup, no native sandbox | `sympy/utilities/autowrap.py:99`, `sympy/utilities/autowrap.py:135` |
| TeX preview/export | Expression/string plus settings → temp files → executables | OS-temp `<random>/texput.tex`, `.dvi`, output format; optional caller `outputTexFile`/`filename` | TeX/converter/viewer or file/buffer recipient; argv and cleanup constrain mechanics | `sympy/printing/preview.py:189`, `sympy/printing/preview.py:194`, `sympy/printing/preview.py:245` |
| Release staging | Vagrant project in `<checkout>/release`, default project share → guest `/vagrant/release` | Normally host `<checkout>/release/release/<artifact>` | Maintainer host/guest; inferred normal Vagrant mapping, no explicit mount override | `release/Vagrantfile:4`, `release/README.md:54`, `release/fabfile.py:319` |
| SSH release access | Vagrant enables agent forwarding → ssh-config → Fabric ForwardAgent | Forwarded host SSH-agent signing capability available in guest session, subject to agent policy | Guest processes able to access forwarded socket; identities/policies external | `release/Vagrantfile:9`, `release/fabfile.py:1252` |
| GitHub publication | Token file/authentication and user/repo → create release → returned release ID → upload assets | Default `sympy/sympy`; API `/repos/&lt;user&gt;/&lt;repo&gt;/releases`, uploads endpoint `/repos/&lt;user&gt;/&lt;repo&gt;/releases/&lt;id&gt;/assets` | GitHub API/upload hosts; authentication and tag-existence check | `release/fabfile.py:972`, `release/fabfile.py:1001`, `release/fabfile.py:1167` |
| Other publication | Distutils upload in VM; configured docs/website checkouts | PyPI destination from external distutils configuration; docs/website `git push origin` in selected checkout | Registry or configured Git remote; actual accounts/origins external | `release/fabfile.py:922`, `release/fabfile.py:833`, `release/fabfile.py:879` |

## 2. Threat Model, Trust Boundaries, and Assumptions

The assets are host process integrity and availability, mathematical-result fidelity, confidential expressions/generated artifacts, filesystem authority, release credentials and published artifact integrity. An attacker may supply expression data only where a host exposes such an interface. No web application, tenant model, network listener or particular production deployment is inferred from this repository.

**Parsing and computation.** Non-strict string sympify calls `parse_expr`. The parser transforms tokens and ultimately calls Python `eval`. `evaluate=False` suppresses automatic expression simplification/canonicalization but still reaches that evaluator; it is not an execution restriction (`sympy/core/sympify.py:322`, `sympy/parsing/sympy_parser.py:901`). Custom locals/global dictionaries likewise do not, by themselves, establish a sandbox. Mathematica and Maxima adapters eventually use sympify, so alternate notation does not supply an independent safety boundary (`sympy/parsing/mathematica.py:8`, `sympy/parsing/maxima.py:65`).

Strict conversion is a different path: unsupported values are rejected before string parsing, and internal `_sympify` uses `strict=True`. Object conversion can still invoke `_sympy_` and numeric coercion behavior (`sympy/core/sympify.py:264`, `sympy/core/sympify.py:277`, `sympy/core/sympify.py:355`). Objects supplied by already-executing Python code are not a separate low-trust principal merely because they implement conversion hooks. A host accepting hostile mathematical data needs an independently constrained construction/grammar boundary and workload limits appropriate to its use.

**Generated code and rendering.** Lambdify combines implementation namespaces, giving expression `_imp_` implementations precedence when enabled. Defaults depend on installed modules. It then evaluates generated lambda text (`sympy/utilities/lambdify.py:307`, `sympy/utilities/lambdify.py:325`, `sympy/utilities/lambdify.py:387`). Trusted selection of names, expressions, printers and implementations is therefore material; disabling one convenience feature is not a demonstrated restriction of Python authority.

Native wrapping changes the process working directory, writes source, invokes a backend and imports the resulting module. The default work directory is unique and removed afterward; an explicitly selected directory is retained. Cython/NumPy wrappers run the current Python executable on generated `setup.py`; f2py uses the current Python executable to invoke its module (`sympy/utilities/autowrap.py:135`, `sympy/utilities/autowrap.py:249`, `sympy/utilities/autowrap.py:406`). Argument arrays avoid shell interpolation in this layer, but do not sandbox generated code, compilers, imports or inherited file access. Concurrent use must account for process-global cwd changes.

Preview accepts raw strings as TeX, or uses a printer for expression objects. Preamble, packages, converter options, viewer and export paths remain privileged configuration. `latex` and converters run with host authority in the temporary directory. `filename` and `outputTexFile` can send content to caller-selected files; errors can include subprocess output (`sympy/printing/preview.py:182`, `sympy/printing/preview.py:194`, `sympy/printing/preview.py:201`, `sympy/printing/preview.py:245`). Temporary cleanup and argument arrays are real controls, but do not establish TeX sandboxing or confidential-log handling (`sympy/printing/preview.py:321`).

**Maintainer build and release.** These tools act under a different principal from runtime expression users. The supplied Vagrantfile has no explicit synced-folder override. Under normal project-directory sharing, the project directory containing it is `/vagrant`, so guest `/vagrant/release` corresponds to host `<checkout>/release/release`, matching the README’s current-directory/release output. Provider/global overrides and actual mounts were not observed (`release/Vagrantfile:4`, `release/README.md:54`).

SSH agent forwarding is a distinct privilege grant. The Vagrantfile enables it, and Fabric consumes the generated SSH configuration’s ForwardAgent value (`release/Vagrantfile:9`, `release/fabfile.py:1252`). A compromised guest may be able to request authentication through the forwarded agent while the session exists, depending on socket access, loaded identities and agent restrictions. This is a signing/authentication capability, not evidence that private-key bytes are copied into the VM. Restricting shared files does not by itself remove this separate capability.

GitHub credential precedence must follow the consumer: although `GitHub_release` accepts a `token` argument, it overwrites that variable with `load_token_file(token_file_path)`, then uses interactive authentication if the file yields no token (`release/fabfile.py:972`, `release/fabfile.py:992`). The default token path resolves through expanduser/abspath to `<maintainer-home>/.sympy/release-token`. Creation requests a private directory and applies owner-only file modes after writing, but generated tokens are also printed to the terminal (`release/fabfile.py:1096`, `release/fabfile.py:1120`, `release/fabfile.py:1143`). Terminal/log recipients therefore matter alongside file permissions; no credential values are reproduced here.

GitHub URLs default to the public `sympy/sympy` destination and accept explicit user/repository selection. A source version determines `sympy-<version>` and the script requires an existing tag before release creation. Assets come from local `release/<tarball>`; a TODO explicitly leaves download/checksum readback unimplemented (`release/fabfile.py:984`, `release/fabfile.py:1001`, `release/fabfile.py:1039`, `release/fabfile.py:1046`). The check is not independent proof that the built artifact, selected account/repository and uploaded bytes match the maintainer’s intent.

PyPI upload operates from `/home/vagrant/repos/sympy` using distutils configuration. Documentation/website paths come from explicit arguments or `<maintainer-home>/.sympy/sympy-locations`; generators and Git pushes execute in those selected checkouts. Clean-index/worktree checks exist, while actual registry accounts and Git origins remain external (`release/fabfile.py:758`, `release/fabfile.py:790`, `release/fabfile.py:842`, `release/fabfile.py:922`).

## 3. Attack Surface, Mitigations, and Attacker Stories

The table contains hypotheses, not validated vulnerabilities. Intentional execution APIs are not intrinsically defects; the question is whether a lower-trust caller can reach authority the host meant to withhold.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| High, conditional | Host passes hostile expression text into Python-evaluating parsing | Untrusted input reaches non-strict sympify/parse_expr under stronger host authority | Python execution in host, if reachable payload is established | Transformations and syntax errors; strict object conversion is separate | Restrict grammar/object construction independently; isolate intentionally executable input | `sympy/core/sympify.py:322`, `sympy/parsing/sympy_parser.py:806` |
| High, conditional | Untrusted expression/name/config reaches lambdify or native code generation | Host exposes code-producing API beyond trusted callers | Python/native execution or file effects under host account | Fixed backend paths, argv invocation, temporary cleanup | Treat code generation as explicit capability; trust inputs and contain compiler/runtime authority | `sympy/utilities/lambdify.py:387`, `sympy/utilities/autowrap.py:135` |
| High, conditional | Host treats attacker TeX/settings as inert mathematical output | Raw TeX or privileged preview settings supplied across trust boundary | External-tool file/process effects, depending on TeX/tool configuration | Argument lists, unique workdir and cleanup | Restrict TeX input/settings and renderer permissions; control viewers/exports | `sympy/printing/preview.py:182`, `sympy/printing/preview.py:201` |
| Medium to High | Expensive symbolic workload exhausts a shared host | Unbounded attacker workload and insufficient containment | Latency or material production outage | Algorithm-specific behavior; no universal budget at parser boundary | Enforce measured time/memory/workload limits outside shared main process | `sympy/parsing/sympy_parser.py:812`, `sympy/utilities/autowrap.py:135` |
| High, conditional | Compromised release guest uses forwarded agent to authenticate elsewhere | Active forwarded agent, accessible socket, usable identity and accepting destination | Access under maintainer SSH identity within agent restrictions | Host agent restrictions and destination authorization, both external | Disable unnecessary forwarding or use narrowly scoped constrained identities | `release/Vagrantfile:9`, `release/fabfile.py:1252` |
| High, conditional | Release credentials or publication targets cross an unintended recipient boundary | Lower-trust configuration/log recipient or altered artifact/checkout | Credential disclosure or incorrect package/docs publication | Token file modes, existing-tag check, clean checkout checks | Verify actual credential precedence, recipients, targets and artifact digest/readback | `release/fabfile.py:992`, `release/fabfile.py:1096`, `release/fabfile.py:1046` |

Validation should follow the exact supported caller path and prove the new authority gained. A local interactive user evaluating their own Python, compiling their own expression, or publishing authorized artifacts has not crossed a security boundary. Private temporary directories reduce filesystem collisions; they do not restrict external programs’ ambient access. The guest agent, token file and package registry are separate resources requiring separate evidence.

## 4. Severity Calibration (Critical, High, Medium, Low)

**Critical:** Requires exceptional demonstrated reach: for example, a real low-trust path compromising a broadly trusted release channel or a highly privileged shared deployment with catastrophic impact. Neither `eval` nor agent forwarding alone establishes that rating. Scope of account authority, affected consumers and recovery must be shown.

**High:** A practical untrusted-input-to-host-execution boundary, meaningful credential compromise, or material shared production outage can qualify. The host integration or release prerequisite must exist. Intentional local use of eval/code generation, an inaccessible agent or a token visible only to its already-authorized owner are counterexamples.

**Medium:** Bounded cross-user availability loss, unintended disclosure of noncritical generated artifacts, or a consequential but limited publication/interpretation defect. An expensive computation must affect someone beyond its consenting caller; a configuration discrepancy needs a concrete resulting failure.

**Low:** Recoverable formatting errors, local development failures and diagnostics without sensitive recipients. Numerical correctness defects become security issues only when an actual security-relevant invariant depends on them.

This is an architecture model rather than exhaustive audit coverage. Historical version/build facts are not claims about current upstream behavior. Optional native implementation internals, running mounts, agent constraints, registry configuration and actual host exposure remain outside this offline source review. No application execution, network verification or exploit reproduction was performed.

---

Repository: https://github.com/mathspace/sympy  
Version: `53418c1c570e44a54f81796619e98da6ac97afbd`
