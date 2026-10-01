---
title: Detections
description: Every runtime fetch pattern pinprick audit looks for, with examples and rationale.
---

This is the canonical list of every rule `pinprick audit` checks. All rules emit findings under the `pinprick/shell_fetch`, `pinprick/javascript_fetch`, `pinprick/python_fetch`, or `pinprick/docker_unpinned` SARIF rule ids.

## Severity levels

- **High** — an attacker controlling the fetched resource gets arbitrary code execution in the job. Typical: `/latest/` URLs, piped-to-shell, missing Docker tags.
- **Medium** — an unversioned URL or unpinned download. Risk depends on what the URL points at.
- **Low** — unpinned package manager install (`pip install foo`, `npm install foo`). Usually a hygiene issue rather than an immediate exploit.

## How matches are scored

pinprick uses bounded source traversal, logical-command parsing, literal propagation, and precompiled patterns. It does not execute workflow or action code.

Workflow, reusable-workflow, and composite steps honor their declared `shell`, including inherited workflow/job defaults. Python and Node steps use the corresponding source scanner. Unsupported shells leave coverage incomplete. Declared action entrypoints lead to literal local imports, Python modules resolved from the entry script's directory, package initializers, and files executed through the action's or a script's own location: `$GITHUB_ACTION_PATH` and `${{ github.action_path }}` in any spelling (including step `env:` values, `$env:GITHUB_ACTION_PATH`, and `Join-Path`), `python -m` from the action directory, shell `$(dirname "$0")` and `BASH_SOURCE`, PowerShell `$PSScriptRoot`, Node `__dirname` and `import.meta.url`, and Python `__file__`. Composite shell, Python, and Node steps are all followed this way.

Path joins (with each language's rules for absolute parts), concatenation, template and f-string interpolation, conditional and logical expressions, variables holding these values, and working-directory changes (`cd`, `pushd`, `process.chdir`, `os.chdir`, and `cwd` options) are evaluated. Shell assignments and directory changes apply in command order; a change inside a branch, loop, function, or after `&&` or `||` may not have happened, a subshell's changes end with it, and a loop that changes its own directory or variables leaves coverage incomplete. A followed file starts in the directory it was run from. In a composite step, changing to any directory that is not a resolved action location leaves coverage incomplete, because the workspace or an input can lead back into the action. A file run by an interpreter is scanned as that interpreter's language whatever its extension; a container action's `ENTRYPOINT`, `CMD`, and `RUN` are traced back to the files `COPY` or `ADD` placed in the image.

Location provenance survives every expression: a value stored in an object or array, returned by an unrecognized function, spread into arguments, bound more than once, or too large or deeply aliased to evaluate is still derived from the location. An execution through a location that does not evaluate to exactly one existing file, and any other unresolved required source, leaves coverage incomplete; mentioning the location or reading a data file through it does not. Copying an action file (`cp`, `mv`, `ln`, `install`, `rsync`, or `cat` with an output redirection) scans a recognized source file, ignores structured data, and otherwise leaves coverage incomplete. Recognized JavaScript file copy, move, and link calls with an action-located source scan that source too, including calls through a variable that directly aliases a recognized copier, `readFileSync` into `writeFileSync`, and read streams piped into write streams. Generic `copy` and `moveSync` calls count as file copies only when their receiver or imported binding comes from a module; a method name alone would also match byte copies such as `Buffer.copy`. A copied source is scanned with its own runtime location unknown, so an execution or local import through that location leaves coverage incomplete; a copy without such a dependency can remain complete.

JavaScript and TypeScript are parsed and names resolve to their declarations, so a name reused in unrelated code does not inherit a location. Any mention of `__dirname`, `__filename`, `GITHUB_ACTION_PATH`, `import.meta`, or a step variable holding the action path draws on a location, whatever it is bound to. Provenance follows arguments into the parameters of functions and methods defined in the same file, callbacks, fields (per class, object, or variable where the holder is known, and by name where it is not), instances of classes whose fields hold a location, and objects a function changes through its parameters or `this`. Outside class and object-literal methods, `this` may be any object: fields read through it are matched by name, and a located receiver reaches `this` in the methods called on it, in getters defined on it, and in functions bound or applied to it or passed along with it, including methods passed as fields of an object whose methods are known. A getter, a property descriptor's `get`, or an implicit method such as `toString` that returns a location makes its object located. A field written through an object nested in another is matched by name, since the nested object may be anything stored there, unless the outer object is a literal that only ever holds fresh values. Because code can reach the global object without naming it, a field stored under a global is also matched by name through objects of unknown origin, and the global object, or any property on the path to that field, used as a value carries it. Arithmetic, comparison, and unary results are not paths; everything else derived from a location, including file contents and modules loaded through a located specifier or loader, keeps its provenance. Node's built-ins are modelled as behaving normally, a heuristic rather than a proof: path functions are evaluated as Node's, and `createRequire` imported from `node:module` is taken as Node's own, so the file it is given only sets where its loader resolves from. A built-in module such a loader returns carries no location, while any other module it loads may be one of the action's files and is treated as located. A method called on a built-in module, loaded by a literal name directly or through an interop helper that only copies its properties, such as esbuild's `__toESM`, is Node's own, so its located arguments do not reach functions of the same name in the action's files. That stops holding for a member any of those files may replace, by writing to it or with `Object.assign` or `Object.defineProperty`, whether on the module itself, a variable holding it, or a function the file passes it to, on the parameter that receives it or on what the function returns, when the call reaches that function through a variable that may name it, at once, as a method of an object literal a variable may hold, or through `call`; and a module with any such member is not trusted through an interop helper at all, since the helper may rename members. A replacement made through a function the analysis cannot identify is outside the model. An action whose files visibly replace or reach around the loader withdraws this for all of them: taking more than `createRequire` from `node:module`; loading `module` other than to call its `createRequire`, or loading `vm`, `inspector`, or `repl`; loading or importing a specifier it does not spell out, other than a path relative to itself; using a loader's cache or passing a loader on; naming `syncBuiltinESMExports` or `getBuiltinModule`; writing through a `constructor`; or evaluating code other than the `eval("require")` and `Function("return this")` forms bundlers emit. Replacement concealed from these checks, such as reaching the `Function` constructor through a computed key, is outside the model. A file that reassigns `__dirname` or `__filename` (directly or in `eval` code), writes or passes on `import.meta`, or writes the variable holding the action path does not evaluate it to the location, so executions through it are unresolved. A located execution option leaves the execution unresolved unless the option cannot choose what runs, such as `cwd`, `encoding`, `stdio`, or a timeout; `shell`, `execPath`, `execArgv`, `env`, and `input` can each run a helper. Functions reached only through a computed key, or passed as a field of an object whose methods are unknown, are not followed as callbacks or receivers. A file that cannot be parsed, or whose analysis fails or runs too long, leaves coverage incomplete. An `exec` call is treated as a regular-expression match only when its receiver is a literal, or a variable holding one that is only read or passed to a string method, and the file neither evaluates code nor exposes `RegExp` or a regular expression's prototype. Python bindings are not scope-aware, so a name reused in unrelated code can make an execution unresolved, and Python paths passed as function parameters are not followed, so a helper a Python function runs through its parameter can be missed.

- **Pipe-to-shell pre-empts other shell rules.** If a line matches a pipe-to-shell rule, no other shell or Docker rule fires on that line. So `curl ... | sh` produces a single high-severity finding instead of one medium (unversioned URL) plus one high (pipe-to-shell).
- **Versioned-URL downgrade.** Non-pipe shell, JavaScript, and Python fetch rules only fire if the URL is _unversioned_. A URL is versioned if any path segment matches `v?\d+(\.\d+)+` — e.g. `/v1.2.3/`, `/0.55.8/`. See [Versioned URL heuristic](#versioned-url-heuristic).
- **Trusted hosts exemption.** Unversioned-URL rules are downgraded to allowed matches when the URL host matches an entry in the user's [`trusted-hosts`](#trusted-hosts-exemption) list.
- **Data-format exemption.** If a fetch targets a URL whose path ends in a known data-format extension (`.json`, `.yaml`, `.toml`, etc.), it is treated as a data fetch, not a code fetch, and downgraded to an allowed match instead of a finding. See [Data-format exemption](#data-format-exemption).
- **Checksum suppression.** A non-pipe finding followed within 3 lines by `sha256sum`, `shasum`, `openssl dgst`, `gpg --verify`, or `Get-FileHash` is suppressed only when the command performs an actual comparison, does not mask or negate failure, and binds every downloaded target to independently trusted verification material. A downloaded sidecar such as `tool.sha256` is attacker-controlled alongside the payload and does not qualify on its own. Inline manifests require a literal full SHA-256 or SHA-512 digest; signature checks must name the downloaded target. Runtime downloads, imported keys, curl or wget configuration changes, and static copy, move, or link aliases remain tracked across later ordered steps in the same job or composite action. Literal `cd` and `Set-Location` paths are resolved within a shell block; conditional or dynamic directories, subshells, directory stacks, expanded or redirected verification operands, and a payload used as its own checksum manifest fail closed when the binding cannot be proven. Verified matches are recorded as allowed.

:::caution[Pipe-to-shell is never suppressed]
A piped payload is never written to disk, so no checksum command can verify it. Trusted-host and data-format exemptions also do not apply — the risk is the execution model, not the source.
:::

Verification applies to the downloaded file version that exists when the check runs; checking an earlier copy does not cover a later overwrite. The verifier must be the command that runs; verifier text an `echo` or `printf` prints does not count. Runtime key retrieval, URL-valued key operands, downloaded material copied through `tee`, `cat`, or `dd` (including by input redirection with or without a descriptor, such as `0<file`), imported into GPG from standard input or a pipe, and extracted downloaded archives (in any `tar` option form, including abbreviated long options) cannot establish independent trust. Recognized runtime fetches in Python or Node steps, in any source file beside a composite action, or anything a nested action a composite step uses may write, also prevent later shell verification in its steps from assuming that its file inputs are independent, because their output paths cannot be bound by the shell scanner.

## Pipe-to-shell

Flagged in shell `run:` blocks, composite `action.yml` steps, and Dockerfile `RUN` lines. High severity regardless of URL versioning.

### curl or wget piped to a shell interpreter

**Severity:** High

Triggers on `curl` or `wget` piped into a supported shell or interpreter, including `sh`, `bash`, `python`/`python3`, and `node`. Recognized command wrappers include `sudo`, `doas`, `env`, `command`, `exec`, `nice`, `nohup`, `time`, and `busybox`; `|&` is also treated as a pipeline. A wrapper asked only for help, its version, or (for `sudo` and `doas`) a permission check runs nothing, so nothing after it counts as a verifier, checkout, or `jq`.

```bash
curl -sSL https://example.com/releases/download/v1.2.3/install.sh | sh
curl -fsSL https://example.com/install.sh | sudo bash
wget -qO- https://example.com/install.sh | sh -s -- --yes
curl https://example.com/get.py | python3
```

Not flagged:

```bash
curl https://example.com/file.sh | tee out.sh     # not an interpreter
curl https://api.example.com/data | jq .          # not an interpreter
```

The versioned URL in the first example pins the _path_, not the _bytes on the wire_: release tags can be recreated, S3 buckets can be overwritten, in-flight bytes can be swapped. Writing the script to disk and checking a signature is always cheap; piping to `sh` forfeits that option.

### Process substitution of a fetched script

**Severity:** High

Triggers on Bash process substitution where the inner command is a fetch.

```bash
bash <(curl -L https://example.com/install.sh)
sh <(wget -qO- https://example.com/install.sh)
```

Equivalent to piping to shell: the script is executed without ever being written to disk.

### Command substitution of fetched content

**Severity:** High

Triggers on shell `-c`, Python `-c`, Node/Ruby/Perl `-e`, or `eval` wrapping a fetch in command substitution. Shell here-strings containing fetched command output, backtick substitution, and `source` or `.` of a `/dev/stdin` here-string are also checked.

```bash
bash -c "$(curl -fsSL https://example.com/install.sh)"
eval "$(wget -qO- https://example.com/install.sh)"
```

Same risk: fetched bytes are handed straight to a shell.

### PowerShell Invoke-Expression on fetched content

**Severity:** High

Triggers on `iex` / `Invoke-Expression` wrapping `iwr` / `Invoke-WebRequest` / `irm` / `Invoke-RestMethod` / `DownloadString` or receiving its output through a pipeline, and on `[scriptblock]::Create` wrapping a fetch. Fetched content stored in a variable and executed later is not tracked.

```powershell
iex (iwr https://example.com/install.ps1)
iex (Invoke-RestMethod -Uri https://example.com/install.ps1)
Invoke-Expression ((New-Object Net.WebClient).DownloadString("https://example.com/install.ps1"))
```

The PowerShell equivalent of `curl | sh`. Same risk, same high severity.

## Shell fetches

Flagged in shell `run:` blocks and composite `action.yml` steps.

### curl or wget to a `/latest/` URL

**Severity:** High

Triggers on `curl` or `wget` with a URL containing `/latest` or `=latest`.

```bash
curl -L "https://github.com/owner/repo/releases/latest/download/tool.tar.gz"
wget "https://example.com/releases/latest/tool.tar.gz"
```

Not flagged:

```bash
curl -L "https://github.com/owner/repo/releases/download/v1.2.3/tool.tar.gz"
```

`latest` is a mutable alias — whatever it resolves to today may be different tomorrow.

### curl or wget to an unversioned URL

**Severity:** Medium

Triggers on `curl` or `wget` fetching an HTTP(S) URL whose path contains no version segment. Scheme matching is case-insensitive. Literal domain/path operands without a scheme are also checked when they belong to a fetch command.

```bash
curl -L https://example.com/install.sh -o install.sh
wget https://example.com/bin/tool
```

Not flagged:

- Any URL whose path contains a segment matching `v?\d+(\.\d+)+`, e.g. `https://example.com/releases/download/v1.2.3/tool`.
- Any URL whose host matches [`trusted-hosts`](#trusted-hosts-exemption) in `.pinprick.toml`.
- Any URL whose path ends in a data-format extension (`.json`, `.yaml`, `.toml`, `.csv`, etc.). See [Data-format exemption](#data-format-exemption).

### curl or wget from a non-literal URL to an executable target

**Severity:** Low

Triggers when `curl` or `wget` writes a `$`-sourced URL to a target that does not look like a data file. pinprick cannot inspect the URL path, so this is intentionally lower severity than a known unversioned URL.

An unresolved output target is treated as potentially executable. For example, `--output "$2"` and `--output "${RUNNER_TEMP}/body.json"` trigger even when the intended response is JSON; the scanner cannot establish the destination. A literal `--output body.json` can use the data-format exemption. A literal executable target with a variable URL also triggers. Curl's `--disable` option does not resolve an expanded destination.

```bash
curl -fsSL "$RELEASE_URL" -o tool
wget "$TOOL_URL" -O bin/tool
curl "$DOWNLOAD_URL" > install.sh
```

Not flagged:

```bash
curl -fsSL "$SCHEMA_URL" -o schema.json
curl -fsSL "$RELEASE_URL" -o /dev/null
curl -fsSL "$RELEASE_URL" | cat > tool
curl -fsSL https://example.com/tool -o tool
```

Literal URLs stay on the normal versioned/unversioned URL path. Later pipeline stages are not treated as proof that the fetch itself wrote an executable file.

### gh release download without a pinned tag

**Severity:** Medium

Triggers on `gh release download` without a version argument.

```bash
gh release download --pattern '*.tar.gz'
```

Not flagged:

```bash
gh release download v1.2.3 --pattern '*.tar.gz'
```

The `gh` CLI grabs the most recent release when no tag is given — same problem as a `/latest/` URL.

### go install @latest

**Severity:** Medium

Triggers on `go install …@latest`.

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

Not flagged:

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.0
```

### deno run / install from an unversioned URL

**Severity:** High

Triggers on `deno run` or `deno install` when the command executes code from an unversioned URL.

```bash
deno run --allow-net https://deno.land/x/install/mod.ts
deno install https://example.com/scripts/tool.ts
```

Not flagged:

```bash
deno run https://deno.land/x/tool@v1.2.3/mod.ts
deno install https://example.com/releases/download/v1.2.3/tool.ts
```

Deno URL imports commonly pin by embedding the version after the package name (`tool@v1.2.3`), so the versioned-URL heuristic accepts `@` as a version boundary.

### git clone without a pinned ref

**Severity:** Medium

Triggers on `git clone` without `--branch`/`-b` or with a branch name that doesn't look like a version tag. The finding stands unless every clone on the line is parsed as pinned; a clone inside `sh -c` or text that only mentions one counts as unpinned.

```bash
git clone https://github.com/org/repo
git clone --branch main https://github.com/org/repo
git clone -b develop https://github.com/org/repo
```

Not flagged:

```bash
git clone --branch v1.2.3 https://github.com/org/repo
git clone -b 2.0.1 https://github.com/org/repo
git clone --depth 1 --branch v1.2.3 https://github.com/org/repo
```

A bare `git clone` defaults to HEAD of the default branch, which is mutable. Pinning to a version tag via `--branch` makes the clone deterministic (at least to the tag level).

:::tip[SHA checkout suppression]
If `git checkout <40-character-SHA>` runs as a command within 3 lines after an unpinned `git clone`, the finding is fully suppressed (recorded as an allowed match visible under `--verbose`). The SHA checkout deterministically pins the repository content.

```bash
# This produces zero findings:
git clone https://github.com/org/repo
cd repo
git checkout abcdef1234567890abcdef1234567890abcdef12
```

:::

Also flagged in Dockerfile `RUN` instructions under the `pinprick/docker_unpinned` rule.

### pip install without a version pin

**Severity:** Low

Triggers on `pip install <package>` where `<package>` has no `==`/`>=`/`~=` specifier and the line is not a `-r requirements.txt` install.

```bash
pip install requests
pip3 install flask
pip install requests --quiet
pip install requests --user
```

Not flagged:

```bash
pip install requests==2.31.0
pip install requests>=2.0
pip install -r requirements.txt
```

### pipx install without a version pin

**Severity:** Low

Triggers on `pipx install <package>` where the package has no Python version specifier.

```bash
pipx install poetry
pipx install black --include-deps
```

Not flagged:

```bash
pipx install poetry==1.8.3
pipx install black>=24.0
```

### npm install without a version pin

**Severity:** Low

Triggers on `npm install <package>` where `<package>` has no `@version` specifier (a digit after `@`). Scoped packages like `@babel/core` are not version-pinned; `@babel/core@1.0.0` is.

```bash
npm install typescript
npm install @babel/core
npm install typescript --save-dev
```

Not flagged:

```bash
npm install typescript@5.6.0
npm install @babel/core@1.0.0
npm install    # no package argument — uses package-lock.json
```

### npx without a version pin

**Severity:** Medium

Triggers on `npx <package>` (or `npx -p <package>`, `npx --package=<package>`) where no token on the line has an `@<digit>` version specifier. Rated higher than `npm install` because `npx` is fetch-and-execute with no lockfile: every CI run pulls whatever the registry currently resolves, and the resolved code runs immediately.

```bash
npx create-react-app my-app
npx typescript
npx -y @angular/cli new my-app
npx --yes typescript
```

Not flagged:

```bash
npx typescript@5.6.0
npx @angular/cli@17.0.0 new my-app
npx -p typescript@5.6.0 tsc
npx --package=typescript@5.6.0 tsc
```

### uv tool install without a version pin

**Severity:** Low

Triggers on `uv tool install <package>` where the tool spec has no version pin.

```bash
uv tool install ruff
uv tool install black --with click
```

Not flagged:

```bash
uv tool install ruff==0.8.0
uv tool install ruff@0.8.0
```

### uvx without a version pin

**Severity:** Medium

Triggers on `uvx <package>` where no token on the line has a version specifier. Like `npx`, `uvx` fetches and runs a tool in one step, so an unpinned invocation can change between CI runs.

```bash
uvx ruff check .
uvx --from black black --check .
```

Not flagged:

```bash
uvx ruff@0.8.0 check .
uvx --from black@24.10.0 black --check .
```

### pip install git+URL without a ref

**Severity:** Medium

Triggers on `pip install git+https://…` (or `git+http://…`) where the VCS URL has no `@<ref>` suffix. Without a ref, pip installs from the repository default branch. A version-like tag or full commit SHA suppresses the finding; branch refs such as `main` remain findings.

```bash
pip install git+https://github.com/owner/repo.git
pip install --user git+https://github.com/owner/repo.git
pip3 install git+https://gitlab.example.com/team/tool.git
pip install git+https://github.com/owner/repo.git@main
```

Not flagged:

```bash
pip install git+https://github.com/owner/repo.git@v1.2.3
pip install git+https://github.com/owner/repo.git@abc1234567890abcdef1234567890abcdef123456
```

### cargo install without a version pin

**Severity:** Low

Triggers on `cargo install <crate>` where the line has neither `@version` on the crate name nor a `--version` flag. Note: `--locked` pins the crate's _dependencies_ via its lockfile, not the crate's own version, so it does not suppress this finding.

```bash
cargo install ripgrep
cargo install typos-cli --locked
cargo install cargo-deny --locked
```

Not flagged:

```bash
cargo install ripgrep@14.0.0
cargo install ripgrep --version 14.0.0
cargo install    # no crate argument — uses Cargo.toml
```

### gem install without a version pin

**Severity:** Low

Triggers on `gem install <gem>` where the line has neither `-v <version>` nor `--version <version>`.

```bash
gem install rubocop
gem install rubocop --no-document
```

Not flagged:

```bash
gem install rubocop -v 1.0.0
gem install rubocop --version 1.0.0
gem install    # no gem argument
```

### brew install --HEAD

**Severity:** Medium

Triggers on `brew install <pkg> --HEAD` (or `--head`). `--HEAD` ignores the formula's bottle/version and builds from the upstream repository's main branch, so the installed code silently changes between runs.

```bash
brew install ffmpeg --HEAD
brew install imagemagick --head
```

Not flagged:

```bash
brew install ffmpeg
brew install ffmpeg --with-chromaprint
```

## PowerShell fetches

Flagged in shell `run:` blocks that happen to be PowerShell.

### Invoke-WebRequest / iwr / Invoke-RestMethod / irm to a `/latest/` URL

**Severity:** High

```powershell
Invoke-WebRequest "https://example.com/releases/latest/tool"
irm "https://example.com/releases/latest/tool"
```

### Invoke-WebRequest / iwr / Invoke-RestMethod / irm to an unversioned URL

**Severity:** Medium

```powershell
Invoke-WebRequest "https://example.com/tool"
iwr https://example.com/tool -OutFile tool.exe
```

Not flagged:

```powershell
Invoke-WebRequest "https://example.com/releases/download/v1.2.3/tool"
```

### Start-BitsTransfer to a `/latest/` or unversioned URL

**Severity:** High for `/latest/`, Medium for other unversioned URLs

```powershell
Start-BitsTransfer -Source "https://example.com/releases/latest/tool.ps1" -Destination tool.ps1
Start-BitsTransfer -Source "https://example.com/tool.ps1" -Destination tool.ps1
```

Not flagged:

```powershell
Start-BitsTransfer -Source "https://example.com/releases/download/v1.2.3/tool.ps1" -Destination tool.ps1
```

### WebClient.DownloadFile to a `/latest/` or unversioned URL

**Severity:** High for `/latest/`, Medium for other unversioned URLs

```powershell
(New-Object Net.WebClient).DownloadFile("https://example.com/releases/latest/tool.exe", "tool.exe")
(New-Object Net.WebClient).DownloadFile("https://example.com/tool.exe", "tool.exe")
```

Not flagged:

```powershell
(New-Object Net.WebClient).DownloadFile("https://example.com/releases/download/v1.2.3/tool.exe", "tool.exe")
```

### Install-Module / Install-Script without -RequiredVersion

**Severity:** Medium

Triggers on `Install-Module` or `Install-Script` without `-RequiredVersion <version>`. Only `-RequiredVersion` pins to a single release; `-MinimumVersion` and `-MaximumVersion` (alone or together) leave at least one end of the range unbounded and are not accepted as a pin.

```powershell
Install-Module -Name Pester -Force
Install-Script -Name Get-WindowsAutoPilotInfo
Install-Module -Name Pester -MinimumVersion 5.0.0
```

Not flagged:

```powershell
Install-Module -Name Pester -RequiredVersion 5.3.1 -Force
```

## JavaScript / TypeScript fetches

Flagged in reachable `.js` and `.ts` action entrypoints and explicitly referenced helpers. Minified and generated bundle files are scanned for literal URL and process-spawn patterns. Conservative unresolved-variable sink reporting is limited to authored JavaScript and TypeScript source because generic networking internals in bundled dependencies are not actionable evidence of an unpinned runtime fetch. Generated bundles are recognized from conventional `dist/` paths, `.min.js` names, and narrow bundler-runtime markers. Relative imports that the bounded scanner does not follow make coverage incomplete rather than producing a clean verdict.

### fetch() / axios / got / http.get to a `/latest/` URL

**Severity:** High

```javascript
fetch('https://api.github.com/repos/owner/repo/releases/latest');
axios.get('https://example.com/releases/latest/tool');
got('https://example.com/releases/latest/tool');
https.get('https://example.com/releases/latest/tool', cb);
```

### exec / child_process shelling out to curl or wget

**Severity:** High

```javascript
exec('curl -L https://example.com/install.sh | sh');
child_process.execSync('wget https://example.com/tool');
```

A JavaScript action reaching for `curl` is almost always doing something that should be a signed release download instead.

### fetch() / axios to an unversioned URL

**Severity:** Medium

```javascript
const r = await fetch('https://example.com/api/data');
const r = await axios.get('https://example.com/api/data');
```

In authored source, a recognized sink with an unresolved variable or interpolated template is also reported at medium severity because its version cannot be verified statically. Exact literal assignments and aliases are propagated; concatenation or other dynamic reassignment invalidates that binding.

Not flagged:

- Versioned URL: `fetch('https://example.com/api/1.2.3/data')`
- Trusted host via [`trusted-hosts`](#trusted-hosts-exemption)
- Data-format URL: `fetch('https://example.com/config.json')` — see [Data-format exemption](#data-format-exemption).

## Python fetches

Flagged in reachable `.py` action helpers. A recognized sink with an unresolved variable or interpolated value is reported at medium severity. Imports that the bounded scanner cannot prove are covered make source coverage incomplete rather than producing a clean verdict.

### urllib.request.urlopen / requests.get to a `/latest/` URL

**Severity:** High

```python
urllib.request.urlopen("https://example.com/releases/latest/tool")
requests.get("https://example.com/releases/latest/tool")
```

### subprocess shelling out to curl or wget

**Severity:** High

```python
subprocess.run(["curl", "-L", url])
subprocess.check_output(["wget", url])
```

### urllib.request.urlopen / requests.get to an unversioned URL

**Severity:** Medium

```python
requests.get("https://example.com/api/data")
urllib.request.urlopen("https://example.com/file")
```

Not flagged:

- Versioned URL: `requests.get("https://example.com/releases/download/v1.2.3/tool")`
- Trusted host via [`trusted-hosts`](#trusted-hosts-exemption)
- Data-format URL: `requests.get("https://example.com/data.json")` — see [Data-format exemption](#data-format-exemption).

## Docker CLI patterns

Flagged in shell `run:` blocks and composite `action.yml` steps.

### docker pull / run image:latest or untagged

**Severity:** High

Triggers on literal image names in `docker pull` and `docker run` commands when the image has no tag or uses `:latest`.

```bash
docker pull alpine:latest
docker run --rm alpine echo hi
docker image pull ghcr.io/org/app
docker container run ghcr.io/org/app:latest
```

Not flagged:

```bash
docker run alpine:3.20 echo hi
docker pull ghcr.io/org/app@sha256:abc123
docker run "$IMAGE" echo hi
docker build .
docker compose up
```

Variable or GitHub-expression image names are not classified: the value might expand to a digest-pinned image, and pinprick cannot inspect that value statically.

## Dockerfile patterns

Flagged in the Dockerfile named by a reachable container action's `runs.image`, or the exact action-root `Dockerfile`/`dockerfile` when no action metadata exists. Unreferenced Dockerfiles in examples, fixtures, or the action repository's own CI are not scanned. Docker continuation parsing skips full comment lines. Wildcard or directory `COPY` sources require a complete repository tree to establish complete coverage.

### FROM image:latest

**Severity:** High

```dockerfile
FROM ubuntu:latest
FROM node:latest AS builder
```

`:latest` is a mutable tag. Pin to a specific version or, better, a digest.

### FROM image without a tag

**Severity:** High

```dockerfile
FROM ubuntu
FROM node AS builder
```

An untagged `FROM` implicitly pulls `:latest`.

### FROM image@sha256:…

**Not flagged.** Digest-pinned images are immutable.

```dockerfile
FROM ubuntu@sha256:abc123def456...
```

### RUN curl or wget piped to a shell

**Severity:** High

Caught by the shared [pipe-to-shell rules](#curl-or-wget-piped-to-a-shell-interpreter). Escalated from the medium-severity generic `RUN curl` rule below.

```dockerfile
RUN curl -sSL https://example.com/install.sh | sh
RUN wget -qO- https://example.com/install.sh | sh
```

### RUN curl or wget (no pipe)

**Severity:** Medium

```dockerfile
RUN curl -L https://example.com/install.sh -o /usr/local/bin/install
RUN wget https://example.com/tool
```

Not flagged: a `curl` line followed within 3 lines by a checksum command fed an inline literal digest for the downloaded target, or by an independent signature verification naming the target. Downloading a checksum sidecar from the same trust domain does not suppress the finding.

### ADD with a URL source

**Severity:** Medium

Dockerfile's `ADD` instruction accepts an `http://` or `https://` URL as its source, which is downloaded at build time. Unlike `COPY`, it can reach the network.

```dockerfile
ADD https://example.com/install.tar.gz /tmp/
ADD --chown=user:group https://example.com/tool.tgz /opt/
```

Not flagged:

- Versioned URL: `ADD https://example.com/releases/download/v1.2.3/install.tar.gz /tmp/`
- Trusted host via [`trusted-hosts`](#trusted-hosts-exemption)
- Data-format URL: `ADD https://example.com/config.json /etc/` — see [Data-format exemption](#data-format-exemption).
- Local source: `ADD ./local.tar.gz /tmp/`

## Versioned URL heuristic

A URL is considered _versioned_ if it contains a path segment matching `v?\d+(\.\d+)+` at a path boundary or in a versioned filename (for example `tool-1.2.3.tar.gz`). Hostnames, query strings, and fragments do not qualify:

| URL                                                        | Versioned?                         |
| ---------------------------------------------------------- | ---------------------------------- |
| `https://example.com/releases/download/v1.2.3/tool.tar.gz` | yes                                |
| `https://example.com/releases/download/0.55.8/tool`        | yes                                |
| `https://deno.land/x/tool@v1.2.3/mod.ts`                   | yes                                |
| `https://example.com/releases/latest/download/tool.tar.gz` | no                                 |
| `https://api.example.com/data`                             | no                                 |
| `https://example.com/v4/resource`                          | no (single numeric component only) |

This is intentionally strict — `v4` alone is a sliding major-version alias, not a pinned release.

Literal and percent-encoded dot segments are normalized before the version check: `/v1.2.3/../tool` does not retain a version segment. A `latest` path component or query value remains high severity even when another component contains a version or the URL ends in a data-format extension.

## Data-format exemption

Unversioned URL rules (`curl`/`wget` to an unversioned URL, `fetch()`/`axios` to an unversioned URL, `urllib`/`requests` to an unversioned URL) are **not** emitted as findings when the URL's path ends in a known data-format extension. Instead, the match is recorded as an _allowed_ match with reason `data format URL` and is only visible under `--verbose`.

Rationale: a workflow fetching JSON for `jq` or YAML for parsing is a different risk class from fetching an install script. The extension is a heuristic for intended data use; it does not prove how a later step consumes the bytes. Homebrew/core's `curl -s https://formulae.brew.sh/api/analytics/install/homebrew-core/30d.json` is a real example — the JSON is assigned to a shell variable and parsed, never run.

**Extensions considered data formats:**

| Category | Extensions                   |
| -------- | ---------------------------- |
| JSON     | `.json`, `.jsonl`, `.ndjson` |
| Config   | `.yaml`, `.yml`, `.toml`     |
| Tabular  | `.csv`, `.tsv`, `.xml`       |
| Text     | `.txt`, `.md`, `.rst`        |

Matching is case-insensitive. Query strings (`?foo=bar`) and fragments (`#section`) are stripped before the extension check.

:::caution[`.html` and `.svg` are not data formats]
Both can carry embedded scripts (`<script>` in HTML, `<script>` and event handlers in SVG), so an unversioned fetch ending in `.html` or `.svg` is still flagged. This is intentional — treating them as data would defeat the rule.
:::

The exemption applies only to the _unversioned-URL_ rules. `/latest/` URLs, pipe-to-shell, and `gh release download` without a tag still fire regardless of extension, because the risk there is about the _path_ being mutable, not about what the bytes decode to.

The list can be extended via `extra-data-formats` in [`.pinprick.toml`](/configuration/config-file#extra-data-formats) to add project-specific extensions (e.g., `.proto`, `.graphql`).

## Piped-to-`jq` exemption

A `curl`/`wget` whose output is piped directly into `jq` is recorded as an allowed match with reason `piped to jq` even when the URL has no data-format extension. Every occurrence of the exact URL must be an operand of a qualifying fetch. Saving the response separately, passing it through an intermediate command such as `tee`, or invoking `jq` with null input, raw input, or a separate input file does not qualify. This heuristic describes the observed pipeline; it cannot prove how later commands consume saved output.

This covers the case the [data-format exemption](#data-format-exemption) misses: a REST API endpoint that returns JSON but carries no `.json` in its path. Resolving the latest release of a crate from the registry API is a real example:

```sh
curl -fsSL "https://crates.io/api/v1/crates/ripgrep" | jq -r '.crate.max_stable_version'
```

**Pipe-to-shell still takes precedence.** A `curl … | jq -r .url | bash` line is flagged as pipe-to-shell (high severity) before this exemption is considered — routing a fetch through `jq` on its way to a shell does not make it safe. This exemption needs no configuration; it is always on.

## Trusted hosts exemption

Unversioned-URL rules are downgraded to allowed matches when the URL host matches an entry in the user's [`trusted-hosts`](/configuration/config-file#trusted-hosts) list. Configured via `.pinprick.toml`:

```toml
trusted-hosts = ["artifacts.example.com"]
```

Matching is exact hostname, case-insensitive. `example.com` does _not_ trust `api.example.com` — each subdomain must be listed separately. Port numbers and paths are stripped before comparison.

The exemption applies only to the _unversioned-URL_ rules — the same scope as the data-format exemption. It does **not** cover:

- `/latest/` URLs — the risk is the path being mutable, regardless of who's serving it.
- Pipe-to-shell — the piped payload is never written to disk, so host trust doesn't change the safety profile.
- `gh release download` without a pinned tag.
- Package manager installs (`pip install foo`, `npm install foo`) — those go through package registries, not the HTTP host.

## Suppressing findings

When a finding is intentional and you want `pinprick audit` to stop flagging it, reach for the tightest mechanism that covers the case. Each mechanism lives in [`.pinprick.toml`](/configuration/config-file), is visible in code review, and applies across the whole repo.

There are three distinct outcomes to be aware of:

- **Accepted finding** — a repository-local [`accept-workflow-findings`](/configuration/config-file#accept-workflow-findings) entry binds an exact finding to the complete reviewed workflow's SHA-256 and a reason. It remains visible in every output format, including ordinary human output. Source coverage is unchanged, and workflow changes invalidate the acceptance.

- **Allowed match** — the rule still matched, but the finding is recorded as allowed instead of emitted. Visible under `--verbose` with a reason, so a reviewer auditing the audit can still see what fired. Used by [`trusted-hosts`](#trusted-hosts), [`extra-data-formats`](#extra-data-formats), the [versioned-URL heuristic](#versioned-url-heuristic), the [data-format exemption](#data-format-exemption), the [piped-to-`jq` exemption](#piped-to-jq-exemption), and the [audited-actions list](/commands/audit#audited-actions-list).
- **Removed finding** — the finding is dropped from the report entirely and is not visible under `--verbose`. Used by [`ignore.patterns`](#ignorepatterns), [`ignore.actions`](#ignoreactions), and [`severity`](#severity-threshold).

:::tip[Prefer allowed matches over removed findings]
Allowlist mechanisms (`trusted-hosts`, `extra-data-formats`) keep a record under `--verbose` of what fired and why. Removal mechanisms (`ignore.patterns`, `ignore.actions`, `severity`) drop the finding entirely. Reach for the audit-trail-preserving option whenever it fits.
:::

### `trusted-hosts`

Allowlist a URL host. Any `curl`/`wget`/`fetch` to that host becomes an allowed match instead of a finding.

```toml
trusted-hosts = ["artifacts.example.com"]
```

Use this when you operate an internal artifact server and control what lives at `https://artifacts.example.com/`. Covers the unversioned-URL rules for shell, JavaScript, Python, and Docker `ADD`. See [Trusted hosts exemption](#trusted-hosts-exemption) for what it does _not_ cover (pipe-to-shell, `/latest/` URLs, package-manager installs).

### `extra-data-formats`

Allowlist a file extension. Unversioned URL fetches ending in that extension become allowed matches.

```toml
extra-data-formats = ["proto", "graphql"]
```

Use this when you regularly fetch a schema, config, or data file format that isn't in [pinprick's built-in data-format list](#data-format-exemption). The fetched bytes have to be consumed as data, not executed — the exemption is wrong if you're fetching an `install.proto` that happens to be a shell script.

### `ignore.patterns`

Drop any finding whose description contains a given substring.

```toml
[ignore]
patterns = [
  "pip install without version pin",
]
```

Use this to silence a specific _rule_ across all actions. Matches by substring against the rule's description — so `"pip install"` silences the pip rule, `"unversioned URL"` silences every unversioned-URL rule. Empty entries match nothing. Findings matching a suppressed pattern are removed entirely, not visible under `--verbose`.

Prefer `extra-data-formats` or `trusted-hosts` when they fit — those keep the audit trail; this one doesn't.

### `ignore.actions`

Skip an action entirely. The action's source code is never fetched, never scanned, and never counted in the "audited" total — it shows up on its own as `ignored` in the per-line output and the summary.

```toml
[ignore]
actions = [
  "actions/checkout",
]
```

Matching is case-insensitive and respects path boundaries. `"actions/checkout"` matches that repository at any ref; `"actions"` or `"actions/"` matches the owner. Use this when you've manually reviewed an action and decided it's out of scope — e.g. an action maintained by your own org that you already security-review separately. The blast radius is the entire action, so use sparingly.

### `severity` threshold

Raise the minimum severity that gets reported.

```toml
severity = "medium"
```

Accepts `"low"`, `"medium"`, or `"high"`. Findings below the threshold are removed from the report. Useful in CI when you want the audit to fail on real risks (high and medium) but not on hygiene issues (unpinned `pip install`, etc.). Not a targeted suppression — it silences _every_ finding below the bar.

### Why there's no inline comment syntax

pinprick deliberately does not read `# pinprick: ignore`-style inline comments. All suppression lives in `.pinprick.toml` so silencing is explicit, auditable in one place, and does not travel with copy-pasted code from another repo. If a specific line in a workflow needs to bypass a finding, your options are:

1. Rewrite the line to avoid the pattern (pin the URL to a version, add a checksum check, etc.).
2. Add a targeted allowlist entry in `.pinprick.toml` using the mechanisms above.
3. Raise the `severity` threshold if the finding is structurally low-value.

The trade-off is intentional: a little more friction for the edge case, in exchange for no per-line escape hatch that a malicious or careless commit could hide in a workflow.
