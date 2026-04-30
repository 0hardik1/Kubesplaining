# Repo-local git hooks

These hooks run locally on every commit. Activate them once per clone:

```
make install-hooks
```

That sets `core.hooksPath` to this directory and marks the scripts executable.

## What runs

| Hook         | Action                                                                 |
|--------------|------------------------------------------------------------------------|
| `pre-commit` | `gofmt -l` + `golangci-lint` over the packages of staged `.go` files. |
| `commit-msg` | Enforces [Conventional Commits](https://www.conventionalcommits.org/). |

`pre-commit` requires `./bin/golangci-lint`, which is pinned via Hermit:

```
./bin/hermit install golangci-lint
```

## Bypass

Use sparingly:

```
git commit --no-verify
SKIP_HOOKS=1 git commit ...
```
