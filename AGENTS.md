# Agent guide

Instructions for any coding agent working in this repository, whether human
driven or autonomous.

Marco is a LAN DNS forwarder, filter and local name service. It ships as one
CGO-free Go binary with an embedded HTTPS admin console and its own SQLite
databases. `README.md` covers operation, `SPEC.md` gives the design intent and
acceptance criteria, and `docs/` holds the operator and verification guides.

## Layout

| Path | Responsibility |
| --- | --- |
| `cmd/marco` | CLI commands, startup wiring, end-to-end and soak tests |
| `internal/config` | Deployment and desired-config models, defaults, validation |
| `internal/store` | SQLite state, revisions, audit, backup and restore |
| `internal/runtime` | Builds and publishes immutable DNS views per revision |
| `internal/dnsserver` | UDP/TCP wire handling and the resolution order |
| `internal/upstream` | DoT, DoH and DoQ transports, bootstrap and response cache |
| `internal/policy`, `internal/filter` | Client policy selection, blocklists, service rules |
| `internal/inventory`, `internal/localdns` | UniFi discovery, device naming, local records |
| `internal/auth`, `internal/admin` | Sessions, OIDC and password sign-in, the console |
| `internal/querylog` | Bounded query history and dashboard statistics |
| `internal/migrate` | Offline import from AdGuard Home and the legacy scraper |

`internal/contract` holds the shared types between these packages. Change it
deliberately and update every caller.

## Build and verify

Use Go 1.25 or newer. Before you push, run:

```sh
gofmt -l .            # must print nothing
go vet ./...
go test ./...
go test -race ./...
```

For changes to startup, packaging or DNS serving, also run the binary smoke test:

```sh
CGO_ENABLED=0 go build -trimpath -o dist/marco ./cmd/marco
./dist/marco validate --config examples/marco.json
scripts/smoke-test.sh ./dist/marco
```

`docs/verification.md` lists the complete checks, including the soak test and
cross-architecture packaging. CI runs the same commands from
`.github/workflows/ci.yml`.

## Working conventions

- Add a regression test with every bug fix, and make sure it fails without
  the fix. Tests live next to the package. Fixtures for migration live in
  `cmd/marco/testdata` and must stay synthetic, with no real hostnames,
  addresses or credentials.
- Keep the binary CGO-free and dependencies few. Discuss before adding a
  module.
- When you change behavior an operator can see, update `README.md`,
  `docs/operations.md`, or the route table in `internal/admin/README.md` in
  the same change.
- Settings changes go through the revisioned `contract.Update` path so they
  are validated, audited and published atomically. Don't write desired state
  to the store directly.
- User-facing text in the console is short, plain and ends with a period.
  Don't put internal error details in it. Log them instead.

## Security expectations

Marco answers DNS for a whole network and its console controls it, so treat
security-sensitive code with care and preserve the existing defenses:

- **Admin console.** Every page goes through `secure` and every mutation
  through `protected`, with a CSRF check against the session token. Keep the
  strict CSP and render HTML only through `html/template`. No inline script,
  `template.HTML` or `innerHTML`.
- **Network input.** DNS clients, UniFi data, blocklists and upstream replies
  are all untrusted. Bound sizes and counts, validate before use, and give
  every network call a timeout.
- **Outbound fetches.** Blocklist URLs must pass `filter.ValidateSource` and
  dial through the public-address-only dialer. Local list files are opened
  through `os.OpenRoot`.
- **Names learned from devices.** Hostnames reported by devices can't
  override manual records or claim protected labels such as `wpad`.
- **Secrets.** Secrets live in the deployment file as env or file references
  and never in desired config, exports, logs, audit records or error pages.
- **Files.** Create data files with mode `0600` and directories with mode
  `0700`.
- **SQL.** Use parameter placeholders. Never build queries from input.

If you find a vulnerability outside your task, report it separately rather
than folding a silent fix into an unrelated change.

## Commits and pull requests

Use Conventional Commits. Write a specific, imperative subject in the form
`type(scope): concise description`, where the scope is optional and usually
the package name (`fix(inventory): ...`, `feat(admin): ...`).

Every commit needs a body after a blank line. Briefly explain what changed and
why in plain language. Keep it to one or two short paragraphs and no more than
200 words. The diff covers the details.

End each commit message with a `Co-Authored-By` trailer that names the agent
that did the work, after a blank line. For example:

```text
Co-Authored-By: OpenAI Codex <noreply@openai.com>
Co-Authored-By: Claude <noreply@anthropic.com>
```

Use your own tool's identity, never another agent's. The trailer doesn't count
toward the body limits.

Work on a branch and open a pull request against `main`. Describe the change,
how you verified it, and any follow-up you left out of scope.
