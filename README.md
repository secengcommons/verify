<div align="center">
  <h1>Security Engineering Commons Verify</h1>
  Bounded repository verification for Go
</div>
<br>

Verify discovers a Go repository then runs its static analysis, compatibility, test and fuzz controls

This bootstrap covers Go modules, shell scripts and GitHub workflows. Repository-specific semantic checks remain ordinary Go tests

## Summary
- [Install](#install)
- [Use](#use)
- [Profiles](#profiles)
- [Plans](#plans)
- [Output](#output)
- [Bounds](#bounds)
- [Performance](#performance)
  - [Benchmark method](#benchmark-method)
  - [Benchmark results](#benchmark-results)
- [Boundary](#boundary)
- [Verification](#verification)

## Install
```sh
go install github.com/secengcommons/verify/cmd/secverify@v1.0.0-alpha4
```

Requires Go 1.26 or newer

## Use
```text
secverify static
secverify compatibility
secverify test
secverify campaign
secverify fuzz-inventory
secverify benchmark
secverify all
```

`--root`, `-root` and `-r` select another repository:
```text
secverify --root .. all
secverify all --root=..
```

Help and version actions do not inspect the repository or resolve tools:
```text
secverify help
secverify help static
secverify version
secverify --version
```

Automatic discovery requires:
- A root `go.mod` with `go` and `toolchain` directives
- One root `.golangci.yml` or `.golangci.yaml`
- Tool directives for GolangCI-Lint and Govulncheck
- Tool directives for Actionlint and ShellCheck when workflows exist
- Bash and ShellCheck when shell sources exist
- Git when workflows exist

Verify resolves each tool through its exact upstream package path with module-readonly mode. Modules containing tool directives cannot contain replacements; vendored tools are not used

Nested modules retain their own optional `toolchain` preference. Two-component Go floors such as `go 1.24` select `go1.24.0`; exact patch releases remain exact

Source discovery and child Go commands use the same native platform, cgo setting and empty `GOFLAGS`

## Profiles

Profile | Controls
--- | ---
static | Toolchain identity, module tidiness, integrity and currency, `go fix`, formatting, vet, GolangCI-Lint, Govulncheck, compile-only test binaries, shell analysis and workflow dependencies
compatibility | Older Go minors from the lowest module floor to the declared toolchain, with each module admitted at its own floor
test | Atomic 100% statement coverage and the race detector for every production test scope
campaign | Every discovered native Go fuzz target under bounded parallel ownership
fuzz-inventory | The complete ordered fuzz-target inventory
benchmark | Every discovered benchmark grouped by package
all | Every applicable static, compatibility, test and fuzz control

Static checks suppress routine success output. Coverage, race, fuzz and benchmark controls retain their useful output. The first non-pass result stops later work

Source discovery retains possible fuzz and benchmark declarations. Go compilation owns signature validity and precedes fuzz-inventory output

The default campaign schedules two lanes with native parallelism of two and at least 100,000 executions per target. `FUZZTIME` and `FUZZ_PARALLEL` replace those values within the declared bounds. One aggregate deadline owns every lane; completion requires each declared `Nx` count in a terminal Go fuzz record

Remote workflow actions require a lowercase 40-character Git commit. Container images require a lowercase SHA-256 digest. The YAML parser follows job, step, service and container structure so matching text inside `run`, `env` or `with` is ignored. Anchors and aliases are expanded within the workflow bounds. Duplicate keys, merge keys, alias cycles and multiple documents are rejected

Workflow byte, line, parser-depth and tree bounds are admitted before Actionlint starts

Repository-local actions require exactly one `action.yml` or `action.yaml`. Composite-action dependencies are inspected recursively. Local reusable workflows must resolve within `.github/workflows`

Remote actions carry their stable version beside the pin:
```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

Version comments use `vN`, `vN.N` or `vN.N.N` with decimal components

Verify resolves Git tags then requires the comment and pinned commit to identify the exact highest stable tag. One incompatible latest version can be excluded with a bounded reason:
```yaml
- uses: owner/action@0123456789abcdef0123456789abcdef01234567 # v1.4.0; exclude v2.0.0: requires a later runtime
```

The exclusion names the exact latest version and the pin remains the highest non-excluded stable tag. A later release makes the exclusion stale

Go dependency currency covers production graphs, direct requirements and declared tool modules through `go list -m -u`. Go `exclude` directives retain incompatible-version exceptions

Dependency currency queries the configured Go proxy and public GitHub repositories when the corresponding dependencies are present. Git configuration and credentials are ignored for workflow resolution. The verdict can change when upstream versions or tags change

## Plans

The root package executes explicit plans through fixed argument vectors:
```go
plan := verify.Plan{
    ID: "repository",
    Profiles: []verify.Profile{{
        ID: "test",
        Controls: []verify.Control{{
            ID: "unit",
            Name: "Unit",
            Command: verify.Command{
                Executable: "/absolute/path/to/go",
                Arguments:  []string{"test", "-count=1", "./..."},
                Environment: environment,
                Timeout:    5 * time.Minute,
                OutputLimit: verify.MaxOutputBytes,
            },
        }},
    }},
}

result, err := verify.Execute(ctx, root, plan, "test", output)
```

`Validate` checks and copies the same plan without execution. Identifiers are lowercase ASCII tokens. Command material and execution resources are bounded before the first process starts

Internal coverage, compile, fuzz, benchmark, workflow and dependency controls receive a canonical bounded operation envelope through standard input. The child executes that exact specification and does not rediscover semantic ownership

`goverify` owns repository discovery, Go control construction, coverage parsing, fuzz and benchmark discovery, bounded fuzz campaigns and workflow-reference checks

## Output

The first line reports the executable version, source state, Go version and platform. Repository builds identify their Git commit; released Go tools identify their module version and checksum. Each control reports its position and result with elapsed time. The profile ends with one acknowledgement:
```text
secverify 0.1.0 source=commit:0123456789abcdef0123456789abcdef01234567 go=go1.27.1 platform=linux/amd64
profile=test controls=2

[1/2] Coverage
ok  example.test/repository  0.56s  coverage: 100.0% of statements
1945 statements covered across 1435 rows
PASS Coverage (2.45s)

[2/2] Race
ok  example.test/repository  1.69s
PASS Race (8.71s)

PASS test: 2 controls in 11.16s
```

Expected output is compared byte-for-byte. Displayed tool output preserves printable UTF-8, escapes terminal controls and invalid bytes then neutralises GitHub and Azure workflow-command prefixes. A missing final line feed is added before verifier output

State | Exit status
--- | ---:
`pass` | 0
`fail` | 1
`invocation_error` | 2
`unavailable` | 3
`cancelled` | 4

Reporting failures are invocation errors

Race verification is available only where Go supports the race detector and cgo is enabled. Fuzz campaigns are available on the operating systems supported by the active Go toolchain. Unsupported requested profiles return `unavailable`

## Bounds

Limit | Value
--- | ---:
Profiles per plan | 32
Controls per profile | 2,048
Controls per plan | 8,192
Command material per plan | 64 MiB
Arguments per command | 256
Argument bytes | 8 KiB
Environment bytes | 16 KiB
Input or expected-output bytes | 1 MiB
Output per stream | 16 MiB
Maximum control timeout | 30 minutes
Ordinary control timeout | 5 minutes
Fuzz-lane timeout | 2 minutes
Repository entries | 100,000
Repository modules | 16
Dependency command output | 1 MiB
Shell or workflow files | 254 per class
Workflow or action file | 64 KiB
Workflow line | 4 KiB
Workflow depth | 100
YAML parser depth | 10,000
Workflow nodes | 65,536
Workflow references | 4,096
Workflow path components | 64
Local actions | 254
Local-action metadata | 16 MiB
Coverage profile | 64 MiB
Coverage line | 64 KiB
Fuzz source file | 1 MiB
Fuzz source total | 64 MiB
Fuzz targets | 1,024
Fuzz workers | 32
Native fuzz parallelism | 256
Filesystem discovery rejects symbolic links, special files, invalid names, duplicate module identities and exceeded counts before execution

## Performance

Benchmarks cover plan admission, repository parsing and output handling

### Benchmark method

(6 September 2026) - The measurements use:
- Linux AMD64
- 13th Gen Intel Core i5-13400F
- Go 1.26.6
- five 500 ms samples per operation
- the median of each five-sample set

### Benchmark results

Operation | Time | Bytes | Allocations
--- | ---: | ---: | ---:
Copy and validate four environment entries | 123.4 ns | 64 | 1
Admit four profiles containing 80 controls | 29,573 ns | 25,376 | 43
Inventory 64 Go source directories | 477,595 ns | 67,831 | 1,406
Construct a two-module repository | 1,487 ns | 616 | 15
Check a complete atomic coverage profile | 971.9 ns | 4,144 | 2
Inspect three workflow execution references | 14,174 ns | 12,984 | 124
Expand one anchored workflow job | 12,970 ns | 15,112 | 140
Inspect one local composite action | 8,983 ns | 10,376 | 96
Validate two GitHub action tags | 521.1 ns | 944 | 3
Inspect one fuzz target and one benchmark | 2,192 ns | 2,048 | 53
Write 4 KiB of printable output | 9,652 ns | 0 | 0
Write 4.5 KiB containing active controls | 29,876 ns | 4,864 | 1
Render one diagnostic | 204.1 ns | 32 | 1

Repository inventory numbers include real filesystem operations. Selected tools govern command-execution costs. Run the complete set with:
```sh
go test -run '^$' -bench . -benchmem -benchtime=500ms -count=5 ./...
```

## Boundary

Plans, module declarations, linter configuration and Go source are trusted execution input. Workflow material and tool output are parsed as untrusted data

Verify passes arguments directly without shell construction, selects a closed environment, confines working directories to the repository and bounds output. [Proctree](https://github.com/secengcommons/proctree) owns each process tree; cancellation and timeouts return after cleanup

The release version is reported only when CLI, Proctree and the YAML parser match the qualified versions without replacements

Go may download declared toolchains, modules and tools through its persisted user configuration or defaults. Process-only proxy variables are not forwarded

Verify is not a sandbox and must not run against a hostile repository. Tools and tests retain the caller's filesystem, network and operating-system access. Repository discovery rejects existing symlinks but a same-user process can replace files after discovery

## Verification

Run focused checks with:
```sh
go test -count=1 ./...
go test -race -count=1 ./...
```

Run the complete local gate with:
```sh
go run -a -buildvcs=true ./cmd/secverify all
```

The complete gate runs applicable static analysis, supported Go versions, 100% statement coverage, race detection and every discovered fuzz target. The benchmark profile remains separate from pass or fail verification

Hosted CI and native macOS or BSD execution evidence are not retained in this bootstrap
