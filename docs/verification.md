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

Go 1.25.0 and 1.26.5 passed the native tests on macOS arm64. The Linux amd64, arm64 and ARMv7 package builds passed. A Linux arm64 Alpine container also ran the static binary, validated the example deployment, and passed the migration, publication and audit integration tests.

## Admin console

The OIDC authorization fixture exercises a TLS identity provider, state, PKCE, nonce, group authorization, and local recovery during a provider error. Session, same-origin CSRF, logout, audit and login-rate limits are covered by tests.

Chrome 157 verified the running console at 1440 by 900 and 390 by 844 in the light and dark system schemes. Checks included keyboard sign-in and navigation, a skip link, focus visibility, horizontal table scrolling, live query-history filters, policy preview and logout.

## Resource workload

```sh
MARCO_SOAK=15m go test -timeout 17m -run '^TestResourceSoak$' -v ./cmd/marco
```

The workload runs real UDP queries against Marco with 250 discovered devices, 500,000 subscription entries, and SQLite history prefilled with 10,000 queries. It alternates local answers and repeated queries to a verified fixture DoH upstream at a nominal 250 QPS. At the midpoint it increases the nominal rate to 1,000 QPS for 30 seconds and replaces the entire subscription concurrently. The harness reports latency, RSS, CPU, DNS errors and timeouts, queue drops, and upstream RTT separately.

### Local results

| Measurement | macOS arm64 | Alpine Linux arm64 |
| --- | ---: | ---: |
| Duration | 15 minutes | 15 minutes |
| Queries and average QPS | 247,467 at 275.0 | 247,425 at 274.9 |
| Local p95 | 0.223 ms | 0.227 ms |
| Cached p95 | 0.245 ms | 0.247 ms |
| Process CPU as a share of one core | 7.4% | 7.8% |
| Fresh RSS | 22.6 MiB | 22.1 MiB |
| Loaded RSS before the soak | 146.8 MiB | 117.2 MiB |
| Peak RSS sampled during refresh | 284.8 MiB | 197.5 MiB |
| Peak RSS across the run | 293.0 MiB | 235.3 MiB |
| Concurrent subscription refresh | 244 ms | 244 ms |
| DNS errors and timeouts | 0 | 0 |
| Load generator drops | 0 | 0 |
| History queue and storage drops | 0 | 0 |
| Last upstream request RTT | 4.82 ms | 3.29 ms |

Both runs used Go 1.26.5 on a Mac arm64 host. The Linux run used Alpine 3.23 in Docker with four CPUs and a 512 MiB memory limit. The harness includes the fixture server and load generator in the measured process. Darwin reports RSS high-water marks, and Linux samples current RSS. The native run used the original history row ceiling. The Linux run used page-based retention.

```sh
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o dist/marco-soak-arm64 ./cmd/marco
docker run --rm --network none --platform linux/arm64 --cpus 4 --memory 512m \
  --mount "type=bind,src=$(pwd)/dist/marco-soak-arm64,dst=/marco-soak,readonly" \
  -e MARCO_SOAK=15m alpine:3.23 /marco-soak -test.v \
  -test.run '^TestResourceSoak$' -test.timeout 17m
```

## Deployment checks

Run the resource workload on the intended Raspberry Pi host and measure latency from a separate LAN client under the site's normal network conditions. Check official API field coverage against the deployed UniFi firmware. A NextDNS smoke test requires an operator profile, and a live PocketID test requires the intended issuer. Review a sanitized AdGuard export and the services actually in use before site cutover.
