# Admin console routes

The console serves HTML and CSS from the Marco binary. Run it at the HTTPS
origin configured by `admin.publicURL`. A trusted loopback proxy must replace
any inbound `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Real-IP` headers
before forwarding the request. The public origin remains the authority for
browser security checks. Point the OIDC redirect URI at
`<public origin>/auth/callback` and configure the IdP to return the authorized
group in the ID token’s `groups` claim.

| Page | Purpose |
| --- | --- |
| `/` | DNS traffic, query rankings, blocking pause controls, and integration health |
| `/devices` | Inventory, device search and presence filters, controller polling and publication conflicts |
| `/devices/edit?id=<id>` | Edit an observed or manual device’s settings. Use `?new=1` to add a manual device |
| `/local-dns` | Zones, aliases, records, reverse ranges and exclusions |
| `/policies` | Default policies, groups, address assignments, service groups and dry-run decisions |
| `/services` | Service categories, hostname rule details, and per-service matching tests |
| `/services/filter` | Edit inherited or custom service blocks for a group or device |
| `/blocklists` | Subscription settings, artifact health, enable or disable, manual refresh and dry-run decisions |
| `/query-log` | Query history filtered by client, name, outcome and UTC time |
| `/settings` | Upstream pools, endpoint tests, portable configuration and instance status |

Pages and actions require an administrator session. The sign-in page is at
`/login`. For unauthenticated health checks, `/livez` reports process liveness
and `/readyz` reports overall DNS listener readiness.

## Forms and settings

Update actions read URL-encoded forms and use the `csrf` value embedded in
the page. Persistent settings edits also require the displayed `revision`
and return `X-Marco-Revision` with the applied revision. Stale submissions
return HTTP 409 and preserve the submitted revision. Copy edits out before
reloading the current settings. JSON editors validate the object and affected
DNS view before publication.

| POST path | Additional form fields |
| --- | --- |
| `/login` | `method` is `local` or `oidc`. Local sign-in also takes `username` and `password` |
| `/logout` | No fields beyond `csrf` |
| `/devices/edit` | `id`, `settings` as a device settings object, optional `create=1` |
| `/devices/poll` | No fields beyond `csrf` |
| `/local-dns` | `settings` with `zones`, `reverse`, `records`, `suppressions`, `dynamicTTL`, `staticTTL`, `autoRename`, and `multiplePTRs` |
| `/policies` | `settings` with `default`, `groups`, `assignments`, and `services` |
| `/policies/groups` | `group-name` for a new group that inherits the default policy |
| `/services/filter` | `target` as `group:<name>` or `device:<id>`, `mode` as `inherit` or `custom`, and repeated `service` IDs for the custom selection |
| `/blocklists` | `settings` as the named subscriptions object |
| `/blocklists/toggle` | `id` and boolean `enabled` |
| `/blocklists/refresh` | `id` |
| `/policies/test` and `/blocklists/test` | `client` IP, `question` and DNS `type` |
| `/settings/upstreams` | `settings` as the named upstream pools object |
| `/settings/test-upstream` | `pool` |
| `/settings/import` | `settings` as a complete portable settings document |

Download portable settings from `GET /settings/export`. This returns the
versioned desired DNS configuration and excludes inventory, query history,
sessions and deployment credentials. The same format works in the import
editor and CLI. Device and policy editors distinguish omitted selection fields
from empty arrays. Omission inherits the selection and an empty array clears
it for that scope.

Use the Device group picker to assign or clear a group. The console provides
revision-checked forms at `POST /policies/defaults` and
`POST /blocklists/defaults` for adding the starter groups and subscriptions
to an existing instance. Existing policies and list selections retain their settings.
