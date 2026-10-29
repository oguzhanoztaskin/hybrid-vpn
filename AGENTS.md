# Guidance for coding agents

## Before changing code
- Read `README.md` and `docs/ARCHITECTURE.md`. Before touching networking code (`engine/`,
  `app/.../vpn/`, `go/`), also read `docs/ROUTING.md`, `docs/THREAT_MODEL.md` and the ADRs in `docs/adr/`.
- Check `git status` first. Never discard, reset or overwrite changes you did not make.

## How to work
- Keep changes small and focused. Preserve working functionality and existing tests.
- Prefer the existing code's idioms. Avoid new abstractions, tools and dependencies unless they clearly pay for themselves.
- Don't migrate working Kotlin code to Go (or back) for consistency alone.
- Use a temporary branch (`experiment/<topic>`) for risky experiments. Merge only verified results.

## Verification before committing
```sh
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"   # macOS
./gradlew :engine:test :discovery:test :app:assembleDebug :app:lintDebug
(cd go && go vet ./... && go test ./...)   # when Go code changed; go.mod pins the Go toolchain
```
Networking changes also need the relevant device checks in `docs/TEST_PLAN.md`. Don't claim a
feature works unless it was actually tested; say what was and wasn't verified.

## Commits and versions
- Commit completed, verified steps with descriptive messages.
- Semantic Versioning: minor for new capabilities, patch for fixes. Bump `versionName`, increase
  `versionCode` monotonically, and update `CHANGELOG.md`. Tag releases as annotated `vX.Y.Z`.
- Never commit secrets (auth keys, tsnet state, signing keys, `local.properties`) or build outputs.

## Never without explicit authorisation
- Force-push, push to any remote, publish releases, or rewrite published history.
- `git reset --hard`, `git clean`, or deleting user files.
- Installing large toolchains (NDK, SDK components). Explain what is needed first.

## Documentation
Update `docs/` and the ADRs whenever an architectural decision or a documented behaviour changes.


## Private development and public snapshots
- `origin` is the private `hybrid-vpn-priv` repository; back up development branches/history there.
- `publish` is `hybrid-vpn`; publish only when the user explicitly requests a public release.
- Public releases must use `scripts/prepare-public-release.sh` so development ancestry never reaches
  the public main branch. Follow `docs/RELEASING.md`; never push all branches/tags to publish.
- Build/upload architecture-specific APKs only for explicit public releases. Ordinary development
  pushes must not produce a public release. Signing keys and runtime state remain private.
