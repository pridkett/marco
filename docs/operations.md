# Marco operations

## Admin and HTTPS

Use a direct HTTPS bind with `admin.certFile` and `admin.keyFile`, or bind the backend to loopback and set `admin.trustedProxies` to the reverse proxy's exact source CIDRs. Set `X-Forwarded-Host` and `X-Forwarded-Proto` at the trusted proxy and overwrite incoming values. Set `X-Real-IP` to the transport peer for per-client sign-in rate limiting. The public URL must match the browser origin. The DNS CIDR ACL is independent of admin access.

The local username defaults to `admin` when a password is configured. `MARCO_ADMIN_USERNAME` overrides `admin.username`. A non-empty `MARCO_ADMIN_PASSWORD` takes precedence over the credential reference in `marco.json`. It accepts a literal password or the Argon2id hash printed by `marco password`. Marco hashes literal passwords in memory at startup. Supply the variable through the process environment or your service manager’s secret configuration. Restart Marco to pick up credential changes.

The sample uses `"password": {"env": "MARCO_ADMIN_PASSWORD"}`. Use `admin.password` to reference a different environment variable or mounted file containing either representation. Use `admin.passwordHash` for a reference that accepts only a generated hash.

### OIDC sign-in

Create a confidential client at your identity provider. Register the callback URI by appending `/auth/callback` to Marco’s public URL, for example `https://marco.wagstrom.net/auth/callback`. Merge these fields into the `admin` object in `marco.json` and set `MARCO_OIDC_CLIENT_SECRET` in the service environment. Use the provider’s HTTPS issuer URL and the client ID it assigned to Marco. [Pocket ID client setup](https://pocket-id.org/docs/setup/connect-an-app)

```json
{
  "issuer": "https://id.wagstrom.net",
  "clientID": "your-client-id",
  "clientSecret": {"env": "MARCO_OIDC_CLIENT_SECRET"}
}
```

Marco grants the same console access as the local administrator when the signed ID token’s `groups` array contains `admin`. Group names are case-sensitive. Set `admin.adminGroup` to use a different group. With Pocket ID, use the group's name included in the ID token. [Pocket ID scopes and claims](https://pocket-id.org/docs/guides/scopes-and-claims)

You can keep the local password account for recovery during provider outages. For OIDC-only sign-in, remove the local password reference and leave `MARCO_ADMIN_PASSWORD` unset. The client secret reference also accepts a mounted file such as `{"file":"/run/secrets/marco-oidc"}`.

### Management MCP and REST API

Set `"managementAPI": true` in the `admin` object and restart Marco. The management endpoints require the admin HTTPS listener and a configured OIDC issuer. Use the exact HTTPS URL ending in `/api/v1/mcp` as both the Streamable HTTP server URL and the OAuth resource. For example, use `https://marco.example.net/api/v1/mcp` when `admin.publicURL` is `https://marco.example.net`. Forward `/api/v1/*` and `/.well-known/oauth-protected-resource/api/v1/mcp` through the HTTPS reverse proxy, preserving the `Authorization` and MCP headers. Clients discover the configured issuer from Marco's protected resource metadata.

At the issuer, register the resource as an API and create the permissions `marco:read` and `marco:policies:write`. Grant `marco:read` to connector clients and users who should have access to network analytics and inventory. Grant both permissions when the connector should edit policies. For an interactive connector, use its registered callback URL and authorization code flow with PKCE. With Pocket ID, use a preregistered client or a Client ID Metadata Document with the corresponding API grants. [Pocket ID APIs and permissions](https://pocket-id.org/docs/guides/apis)

The issuer must return a signed JWT access token with type `at+jwt`, the exact resource URL in its `aud` claim, and the granted permissions in `scope`. The API checks those permissions independently of the console's OIDC group. REST uses the same resource and sends `Authorization: Bearer <access-token>`. Requests without valid credentials receive HTTP 401 with a discovery challenge. Insufficient permissions return HTTP 403 with the scopes required by the operation. MCP supports Streamable HTTP with JSON responses, using `server/discover` in `2026-07-28` or the `initialize` handshake for `2025-11-25`, `2025-06-18`, and `2025-03-26` clients. [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

| MCP tool | REST route | Arguments and result |
| --- | --- | --- |
| `get_dashboard` | `GET /api/v1/dashboard` | `range` accepts `15m`, `1h`, or `24h` (default). Returns counts, activity buckets, average latency, cache hit rate, blocking status, and the top five clients, queried domains, blocked domains, and upstream-blocked domains. `blocks` counts Marco's policy blocks and `upstreamBlocks` counts blocks by an upstream resolver. Rankings are cached for a minute. `rankings.asOf` gives their time, and `rankings.updating` means newer ones are being calculated. `rankingsPending` means the first rankings for the range are not ready yet, so ask again in a few seconds. |
| `search_query_log` | `GET /api/v1/query-log` | Filter by `client` (comma-separated IPs or anonymized IDs), `question` (substring), `type` (for example `AAAA`), `outcome` (for example `blocked`, `upstream blocked`, `allowed`, or `NXDOMAIN`), `after` (inclusive), or `until` (exclusive). Times use RFC 3339. Pass `next` as `before` with the same filters to read older entries. |
| `test_policy` | `POST /api/v1/policies/test` | Send `client` IP, `question` as a DNS name or an HTTP(S) URL, and optional `type` (default `A`). Returns the selected policy and predicted result. An external-eligible result means a live DNS request would proceed to an upstream. |
| `get_policies` | `GET /api/v1/policies` | Returns current settings, their revision, and valid pool, subscription, and built-in service IDs. |
| `update_policies` | `PATCH /api/v1/policies` | Takes the current `revision` and any of `default`, `groups`, `assignments`, or `services`. Requires both permissions. |
| `list_clients` | `GET /api/v1/devices` | Filter by exact `id`, `controller`, `site`, or `presence` (`connected`, `absent`, `manual`, or `legacy`), or use a `search` substring. Returns observed addresses, configured group and policy, publication status, and site poll timestamps. Pass `next` as `after` to continue. |

The query log and client inventory return 50 entries when `limit` is omitted, up to a default maximum of 200 per request. Set `admin.managementMaxPageSize` to a value from 1 to 5000 and restart Marco to change the maximum for both MCP and REST. For 1,000 records at a time, set `"managementMaxPageSize": 1000` in the `admin` object and pass `"limit": 1000` in MCP or `?limit=1000` in REST. If the configured maximum is below 50, an omitted `limit` uses that lower value.

Query history and rankings use retained rows and respect history anonymization. Dashboard counts also include queries whose history entries were dropped. Inventory can contain IP and MAC addresses and is governed by the API's read permission.

Send JSON bodies with `Content-Type: application/json`. Policy edits replace the `default` policy or full `assignments` array when supplied. An empty `assignments` array clears it. `groups` and `services` replace only the specified keys and accept `null` for removing an entry. Omit `services` or `subscriptions` within a replacement policy to inherit that selection, or use an empty array to clear it. This example creates a local-only group at revision 42.

```json
{
  "revision": 42,
  "groups": {"IoT": {"mode": "local-only"}}
}
```

The response gives the applied revision. REST returns HTTP 409 on a stale revision and 422 when the candidate fails validation. MCP reports those failures in the tool result. Fetch the current settings before retrying a conflict. Marco saves policy changes and their audit record together with the issuer and subject from the token.

### Wildcard HTTPS certificate

Choose a hostname covered by the certificate, such as `marco.wagstrom.net` for a DNS-validated `*.wagstrom.net` certificate. Point that name at the admin listener using a DNS A or AAAA record. For direct HTTPS, merge these fields into the startup config’s `admin` object alongside its sign-in settings.

```json
{
  "listen": "192.168.1.53:443",
  "publicURL": "https://marco.wagstrom.net",
  "certFile": "/run/secrets/wagstrom.net/fullchain.pem",
  "keyFile": "/run/secrets/wagstrom.net/privkey.pem"
}
```

Replace the listen address with the resolver’s LAN address. Give the service user read access to the mounted certificate chain and private key. Restart Marco after renewal so it reloads the PEM files. If a reverse proxy terminates TLS, install the wildcard certificate there and keep Marco on the trusted loopback backend using the same public URL.

## JSON settings

The device, Local DNS, policy, blocklist, upstream pool, and portable settings forms highlight JSON as you type and show line numbers. The editor and JSON diagnostics follow your browser’s light or dark preference. Very large documents and browsers with scripting disabled use plain text fields so you can still edit and submit settings.

## DNS dashboard

The dashboard defaults to 24 hours and also offers 15-minute and 1-hour views. When query history is enabled, Marco restores recent traffic counts from retained history at startup and displays client and domain rankings. Select a ranked client or domain to open the corresponding query log filter. Rankings are calculated only while someone views the dashboard or asks the API, then reused for up to a minute. On small devices such as a Raspberry Pi, ranking a full day of history takes a few seconds. While newer rankings are being calculated, the dashboard shows the previous rankings with the time they cover. When there are none yet, for example just after Marco starts, it shows **Calculating query rankings**. The page replaces either with the new rankings when they are ready, without a reload. When query history is disabled, the chart and summary counts cover only the current run.

### Conditional forwarding

Map a DNS suffix to a named upstream pool to send queries for that name and its descendants to a dedicated resolver. Marco uses the most specific matching suffix, ignoring letter case and an optional trailing dot. It selects the pool after local DNS and policy checks, using the name it will send upstream, including the external target of a local CNAME. A query without a match uses its client policy's pool. When the matching pool is exhausted, Marco returns SERVFAIL and keeps the query within that pool.

For Tailscale MagicDNS, merge this pool into the existing object in **Settings → Pools JSON**. Replace `example-tailnet.ts.net` in the forwarding example with your tailnet's DNS suffix. `100.100.100.100` is a device-local resolver, so the Marco process must be able to reach it from where it runs.

```json
{
  "magicdns": [{"transport": "udp", "address": "100.100.100.100"}]
}
```

Add the matching entry to **Settings → Forwarding JSON** and save upstreams. The same objects are available as `pools` and `forwarding` in portable settings. If you are adding a second pool to a configuration with an implicit default, select the existing resolver as `default.pool` under **Policies** first. Add these entries manually when migrating from AdGuard Home.

```json
{
  "example-tailnet.ts.net": "magicdns"
}
```

Plain endpoints use `"transport": "udp"` or `"transport": "tcp"` and default to port 53. Set `port` for a nonstandard port. A UDP endpoint retries a truncated reply over TCP at the same address and port. TCP endpoints send queries directly over TCP. Both transports send DNS messages without encryption.

### Upstream blocks

Marco also notices when a filtering upstream resolver, such as NextDNS, blocks a query. It treats a reply as an upstream block when it carries an Extended DNS Error (RFC 8914) of Blocked, Censored, Filtered or Prohibited, or when every address in the answer is `0.0.0.0` or `::`. **Upstream blocks** on the dashboard counts these separately from **Policy blocks**, which are Marco's own blocklists, service blocks and manual denies. **Top upstream-blocked domains** ranks the names.

In the Query Log these rows show an **Upstream block** badge. Expand a row to see the upstream's reason. NextDNS, for example, names the blocklist that matched. Filter with the outcome `upstream blocked` to list them. Detection only affects statistics. Marco caches and returns the upstream reply unchanged. History recorded before this feature shows these queries as ordinary upstream answers.

In the Query Log, click a row to expand or collapse its details. Use the Type filter for an exact DNS question type such as `A`, `AAAA`, `HTTPS`, or `TYPE65400`. Older matching rows load as you scroll to the bottom. The Older queries link also lets you continue manually.

SQLite may use temporary files when grouping larger sets of history. Marco's container image provides a writable `/tmp`. With a read-only container root filesystem, mount a writable `/tmp` for dashboard rankings and startup counter restoration.

Use **Pause blocking** to suspend blocklists, service blocks, and manual domain denies on this Marco instance. DNS source admission, client deny-all and local-only modes, local DNS publication rules, and any upstream provider filtering still apply. The dashboard shows the remaining time and scheduled resume time for a timed pause. Choose **Indefinite** to keep domain filtering paused until you select **Resume blocking**. Both types of pause survive a Marco restart.

## UniFi

Set `unifi.controller` to a stable operator-assigned ID, `unifi.url` to the HTTPS controller origin, and `unifi.site` to the site ID. The `api-key` mode defaults to the UniFi OS Network integration path. Use `api-key-standalone` for a standalone controller. Provision `unifi.apiKey` with a read-only Network application key. Use `unifi.caFile` if the controller uses a private CA.

Confirm that the deployed firmware's clients and adopted devices endpoints return the expected devices and IP fields. If official API coverage is incomplete, use `local-account` on UniFi OS or `local-account-standalone` on a standalone Network application, set the legacy site name, and provision `unifi.username` and `unifi.password`. Marco preserves the last usable published data through incomplete polls and controller failures.

For local-account polling, add this section to `marco.json` and supply `UNIFI_PASSWORD` in the service environment. Use a UniFi account with read-only access to the Network site. Replace `default` if your site has a different legacy name.

```json
{
  "unifi": {
    "mode": "local-account",
    "controller": "home",
    "url": "https://unifi.example.net",
    "site": "default",
    "username": "marco-reader",
    "password": {"env": "UNIFI_PASSWORD"}
  }
}
```

Marco polls clients and adopted infrastructure immediately and every 60 seconds by default. For the official API, use `api-key` and set `"apiKey": {"env": "UNIFI_API_KEY"}` with the site ID.

Marco does not publish a client-reported name of `wpad` or `isatap`. Clients look up these names to discover proxy and tunnel settings, so any device could otherwise redirect their traffic by reporting one. To publish one of these names on purpose, set it as the device's name in **Devices → Edit**.

When a local-account poll supplies a client fingerprint ID, the Devices page loads the corresponding artwork from Ubiquiti's `static.ui.com` CDN. The image request identifies the device model by its fingerprint ID and omits the page URL. Clients polled through the official Network integration API have no documented fingerprint field.

### Controller address at startup

Set `unifi.dialIP` when the controller hostname depends on Marco’s discovery. This field accepts a fixed IPv4 or IPv6 address. Marco connects to that address on the port in `unifi.url` and uses the URL hostname for HTTP routing and TLS certificate verification.

For example, merge these fields into the `unifi` section of `marco.json` and replace the example IP with the controller or HTTPS proxy's address.

```json
{
  "url": "https://unifi.wagstrom.net/",
  "dialIP": "192.0.2.10"
}
```

Use `caFile` for a private CA. A manual `A` or `AAAA` record also works when the OS resolver queries Marco for that hostname. Marco publishes manual records before starting UniFi discovery.

## Service catalog

Marco’s default catalog is stored in `catalog/services.json` alongside its source and license information. The Linux packages include this file next to the binary. Marco looks for the catalog next to `marco.json`, next to the executable, and under the working directory. Set `serviceCatalog` in `marco.json` to choose a file explicitly. Restart Marco after updating the resource. Keep the same catalog alongside exported settings when moving a configuration that selects its service IDs.

Open **Services → Filter services** to select a group or an individual device. **Customize service blocks** saves the full list for that policy. Search by name, choose a category, or select **Blocked only** to review the list before saving. Clearing every checkbox saves an empty list. Choose **Inherit service blocks** to follow the parent policy again. Groups inherit the default policy, and devices can inherit their group's list. Service blocks apply during filtered DNS resolution. Use **Policies → Test a DNS decision** to check the result for a particular client address, including address assignments and manual rules.

You can keep a service edit open through inventory polls, blocklist refreshes, and edits to other groups. If a relevant policy changes, the console shows the current blocks and keeps your draft available for review. Compare the two selections before saving the reviewed draft.

Marco advances the applied revision when settings, device bindings or publication, or active list content changes. Routine inventory freshness updates and fetches of identical list content are saved at the same applied revision.

To manage a household group, create it under **Policies → Client groups**, choose its blocked services, and assign each device under **Devices → Edit → Device group**. Marco identifies devices through fresh inventory observations or address assignments that name the device. For a manually configured device without observations, use a named address assignment in **Policies** to bind the DNS client address.

The service catalog still supports browsing by category or name. Detail pages show hostname rules and exceptions, with a test that uses the same service matcher as DNS. An entry in the desired configuration’s `services` map can define a custom service or override the catalog entry with the same ID. Both catalog and custom services appear in the editor.

## Offline migration

Run with sanitized copies. To create a consistent PowerDNS backup, use SQLite's `.backup` command against the legacy database. Keep that copy separate from the running legacy service.

```sh
sqlite3 hostnames.db '.backup hostnames-copy.db'
marco migrate --config marco.json \
  --scraper scraper-redacted.toml --powerdns hostnames-copy.db \
  --adguard adguard-redacted.yaml --disposition disposition.json
```

The command prints a read-only JSON preview. Review accepted entries, exclusions, conflicts, unsupported features, unresolved client selectors, and staged subscriptions. Dispositions can set a default `addressRows` choice and individual `rowChoices` keyed by the PowerDNS row ID. Choices are `observation`, `manual`, and `skip`. Observation rows keep their exact local owners and never authorize a source IP. Use `retiredAliases` for names removed from legacy configuration. Use `services` to define reviewed, versioned app domain groups by legacy service ID, `deviceSelectors` to map known client identifiers to stable Marco device IDs, and `upstreamPools` and `defaultPool` for approved non-secret encrypted endpoints. Declare `reverse` with the LAN CIDRs.

Stop Marco and rerun with `--apply --base BASE`, using the preview's `baseRevision` value. This value tracks all persisted state because a migration can replace inventory as well as settings. After reviewing any remaining unsupported entries, pass `--allow-unsupported` to accept the losses described in the preview. A repeated import of the same files and dispositions preserves subsequent admin edits. Review a new preview when inputs or dispositions change.

Export desired settings with `marco export --config marco.json > desired.json`. On another instance set this file as `initialConfig` or use `marco migrate --desired desired.json --config marco.json`. A full import replacing a different existing desired configuration requires `--replace-settings` and the current base revision. Export device data separately with `marco export --config marco.json --inventory` and import it with `marco migrate --inventory`. An inventory import retains history and local publication. A successful site poll is required to establish live source identity.

The checked-in fixtures are synthetic. Complete a site parity review with the operator's sanitized AdGuard export and services before migrating an active deployment.

## Backup and restore

Stop the instance. The backup command takes SQLite-aware snapshots of the resolver and query history, including durable list artifacts, sessions and audit records. Store the backup in a private location. Back up the deployment file, referenced secrets, certificates and provisioned list sources separately through the operator's normal secret-handling system.

```sh
marco backup --config marco.json --output backup-01
# Set dataDir in restored.json to a fresh directory.
marco restore --config restored.json --backup backup-01
marco validate --config restored.json
marco run --config restored.json
```

Use an empty restore destination. Retain the original instance files until restored DNS, admin access and background integrations have been verified.
