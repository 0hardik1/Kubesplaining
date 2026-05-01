# Contributing to Kubesplaining

Thanks for taking the time to contribute. The goal of this guide is to keep the patch loop fast — read it once, then defer to the linked references for detail.

## Before you open a PR

- For non-trivial work (new analyzer, new rule family, behavior change), open an issue first so we can align on scope. Trivial fixes (typos, small bugs, doc tweaks) can go straight to a PR.
- Security issues do **not** belong here — see [SECURITY.md](SECURITY.md) for private disclosure.

## Local setup

Developer tooling (Go, kubectl, kind, ripgrep, golangci-lint, goreleaser) is pinned via [Hermit](https://cashapp.github.io/hermit/) under `bin/`. No system Go install required.

```bash
. ./bin/activate-hermit          # adds ./bin/ to PATH for this shell
make setup                       # downloads Go modules into ./.tmp
make install-hooks               # activates pre-commit + commit-msg hooks (one-time per clone)
```

The `make install-hooks` step is the one most people skip — it wires up the Conventional-Commits enforcement and the staged-files lint that match what runs in CI. Skipping it means your commits will fail CI for reasons your local clone won't catch.

## The development loop

```bash
make lint        # gofmt + go vet (full repo)
make test        # go test ./...
make build       # builds ./bin/kubesplaining
make e2e         # spins up kind, applies risky manifests, asserts findings (needs Docker)
```

A fast inner loop for a single package:

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/analyzer/rbac/...
```

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/). Allowed types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `build`, `perf`, `style`, `revert`. Subject ≤ 72 chars, no trailing period, imperative mood (`add`, not `added`). The `commit-msg` hook (and a CI check on PR titles) enforces this; see [.githooks/README.md](.githooks/README.md) for details and emergency bypass.

Examples:
- `feat(privesc): emit finding when SA can impersonate cluster-admin`
- `fix(report): escape HTML in Finding.Description`
- `docs: refresh collector.go line count in CLAUDE.md`

## Adding a rule

Every analyzer emits `models.Finding` with a stable `RuleID` of the form `KUBE-<AREA>-<SUFFIX>`. The suffix is usually a zero-padded number (`KUBE-PRIVESC-001`, `KUBE-ESCAPE-005`); for privesc graph paths it's a descriptive sink name (`KUBE-PRIVESC-PATH-CLUSTER-ADMIN`). Multi-segment areas are common when a module covers several axes — e.g. `KUBE-PODSEC-APE-001`, `KUBE-NETPOL-COVERAGE-001`, `KUBE-SA-DEFAULT-001`. RuleIDs are a public surface — they are referenced from [`docs/findings.md`](docs/findings.md), the e2e assertions in `scripts/kind-e2e.sh`, and likely downstream consumers — so don't rename them once shipped.

When adding a rule:

1. Pick the next free number under the matching prefix. Existing prefixes today: `KUBE-PRIVESC-`, `KUBE-PRIVESC-PATH-`, `KUBE-ESCAPE-`, `KUBE-CONTAINERD-SOCKET-`, `KUBE-HOSTPATH-`, `KUBE-PODSEC-APE-`, `KUBE-PODSEC-ROOT-`, `KUBE-IMAGE-LATEST-`, `KUBE-NETPOL-COVERAGE-`, `KUBE-NETPOL-WEAKNESS-`, `KUBE-ADMISSION-`, `KUBE-SECRETS-`, `KUBE-CONFIGMAP-`, `KUBE-SA-DEFAULT-`, `KUBE-SA-PRIVILEGED-`, `KUBE-SA-DAEMONSET-`, `KUBE-RBAC-OVERBROAD-`. See [`docs/findings.md`](docs/findings.md) for the authoritative list.
2. Implement the detection in the matching `internal/analyzer/<module>/analyzer.go`.
3. Add a table-driven test in the same package (`*_test.go`).
4. If the rule should produce findings against the e2e fixture, update `testdata/e2e/vulnerable.yaml` and the `rg -q` assertions in `scripts/kind-e2e.sh`.
5. Document the rule in [`docs/findings.md`](docs/findings.md) — title, severity, what it detects, remediation. This is the catalog users will actually consult.
6. If the rule introduces a new resource/subject Kind or privesc Action slug, add the corresponding `Glossary` / `Techniques` entry in `internal/report/glossary.go` so the HTML report renders the educational copy.

## Architecture quick-reference

The four-stage pipeline (`connection → collection → analysis → report`) and the cross-package vocabulary live in [CLAUDE.md](CLAUDE.md). Read it once before touching the engine.

## Where to file issues

- Bugs / feature requests: [GitHub Issues](https://github.com/0hardik1/kubesplaining/issues) — pick the matching template.
- Open-ended questions / show-and-tell: [GitHub Discussions](https://github.com/0hardik1/kubesplaining/discussions).
- Security: see [SECURITY.md](SECURITY.md) (GitHub Private Vulnerability Reporting only).
