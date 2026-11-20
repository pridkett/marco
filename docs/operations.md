# Marco operations

## Admin and HTTPS

Use a direct HTTPS bind with `admin.certFile` and `admin.keyFile`, or bind the backend to loopback and set `admin.trustedProxies` to the reverse proxy's exact source CIDRs. Set `X-Forwarded-Host` and `X-Forwarded-Proto` at the trusted proxy and overwrite incoming values. Set `X-Real-IP` to the transport peer for per-client sign-in rate limiting. The public URL must match the browser origin. The DNS CIDR ACL is independent of admin access.

The local username defaults to `admin` when a password is configured. `MARCO_ADMIN_USERNAME` overrides `admin.username`. A non-empty `MARCO_ADMIN_PASSWORD` takes precedence over `admin.passwordHash`. Marco hashes the environment password in memory at startup. Supply the variable through the process environment or your service manager’s secret configuration. Restart Marco to pick up credential changes.

To add PocketID or another OIDC provider, configure `admin.issuer`, `admin.clientID`, `admin.clientSecret`, and `admin.adminGroup`. Register the callback URI formed by appending `/auth/callback` to the public URL. Use the provider's group claim for authorization. Leave the local password account configured for recovery during provider outages. A secret reference takes either `{"env":"ENV_NAME"}` or `{"file":"/run/secrets/name"}`. Restart the instance after rotating a hash with `marco password --out admin.hash`.

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

## Offline migration

Run with sanitized copies. To create a consistent PowerDNS backup, use SQLite's `.backup` command against the legacy database. Keep that copy separate from the running legacy service.

```sh
sqlite3 hostnames.db '.backup hostnames-copy.db'
marco migrate --config marco.json \
  --scraper scraper-redacted.toml --powerdns hostnames-copy.db \
  --adguard adguard-redacted.yaml --disposition disposition.json
```

The command prints a read-only JSON preview. Review accepted entries, exclusions, conflicts, unsupported features, unresolved client selectors, and staged subscriptions. Dispositions can set a default `addressRows` choice and individual `rowChoices` keyed by the PowerDNS row ID. Choices are `observation`, `manual`, and `skip`. Observation rows keep their exact local owners and never authorize a source IP. Use `retiredAliases` for names removed from legacy configuration. Use `services` to define reviewed, versioned app domain groups by legacy service ID, `deviceSelectors` to map known client identifiers to stable Marco device IDs, and `upstreamPools` and `defaultPool` for approved non-secret encrypted endpoints. Declare `reverse` with the LAN CIDRs.

Stop Marco and rerun with `--apply --base REVISION`, using the preview's base revision. After reviewing any remaining unsupported entries, pass `--allow-unsupported` to accept the losses described in the preview. A repeated import of the same files and dispositions preserves subsequent admin edits. Review a new preview when inputs or dispositions change.

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
