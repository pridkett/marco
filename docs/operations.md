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

## DNS dashboard

The dashboard defaults to 24 hours and also offers 15-minute and 1-hour views. When query history is enabled, Marco restores recent traffic counts from retained history at startup and displays client and domain rankings. Select a ranked client or domain to open the corresponding query log filter. When query history is disabled, the chart and summary counts cover only the current run.

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
