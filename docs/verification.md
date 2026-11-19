# Verification

## Reproducible checks

Run from the repository root.

```sh
go vet ./...
go test ./...
go test -race ./...
CGO_ENABLED=0 go build -trimpath -o dist/marco ./cmd/marco
./dist/marco validate --config examples/marco.json
scripts/smoke-test.sh ./dist/marco
for arch in amd64 arm64 armv7; do scripts/package-linux.sh "$arch"; done
```

The fixtures cover UDP and TCP, IPv4 and IPv6 CIDRs, EDNS truncation, split and private zones, reverse DNS, local chains and suppressions, encrypted TLS and QUIC listeners, upstream failure and negative caching, client policy changes on a warm cache, UniFi pagination and reassignment, durable list refreshes, stale revisions and audit rollback, and query-history pressure. The migration fixtures under `cmd/marco/testdata` use a synthetic AdGuard export, rendered scraper TOML and seed SQL. The binary smoke test uses an enabled local list and checks that DNS returns NXDOMAIN for its blocked name.

Go 1.25.0 and 1.26.5 passed the native tests on macOS arm64. The Linux amd64, arm64 and ARMv7 package builds passed. A Linux arm64 Alpine container also ran the static binary and validated the example deployment.

## Admin console

The OIDC authorization fixture exercises a TLS identity provider, state, PKCE, nonce, group authorization, and local recovery during a provider error. Session, same-origin CSRF, logout, audit and login-rate limits are covered by tests.

Chrome 157 verified the running console at 1440 by 900 and 390 by 844 in the light and dark system schemes. Checks included keyboard sign-in and navigation, a skip link, focus visibility, horizontal table scrolling, live query-history filters, policy preview and logout.

## Resource workload

```sh
MARCO_SOAK=15m go test -timeout 17m -run '^TestResourceSoak$' -v ./cmd/marco
```

The workload runs real UDP queries against Marco with 250 discovered devices, 500,000 subscription entries, and SQLite history prefilled with 10,000 queries. It alternates local answers and repeated queries to a verified fixture DoH upstream at a nominal 250 QPS. At the midpoint it increases the nominal rate to 1,000 QPS for 30 seconds and replaces the entire subscription concurrently. The harness reports latency, RSS, CPU, DNS errors and timeouts, queue drops, and upstream RTT separately.

## Deployment checks

Run the resource workload on the intended Raspberry Pi host and measure latency from a separate LAN client under the site's normal network conditions. Check official API field coverage against the deployed UniFi firmware. A NextDNS smoke test requires an operator profile, and a live PocketID test requires the intended issuer. Review a sanitized AdGuard export and the services actually in use before site cutover.
