- Feature Name: peer_whitelist
- Status: Implemented
- Start Date: 2026-04-15
- Authors: Hathor Labs
- Hathor Issue:
- Implementation PR(s):

# Overview

A peer whitelist mechanism for the P2P layer that restricts which peers a node
may connect to. The whitelist is fetched from a remote URL or read from a local
file, refreshed periodically, and supports two policies: `only-whitelisted-peers`
(default) and `allow-all`. Selection happens at startup via a single CLI spec
string, and the whitelist can be replaced, suspended, or inspected at runtime
via sysctl.

Enforcement is identity-based (peer IDs derived from public keys), applied
after the TLS+PEER-ID handshake, and uses a last-known-good strategy: a failed
fetch never downgrades admission.

# Specification

## Configuration

### CLI

The whitelist is configured via a single CLI argument:

```
--p2p-whitelist-source <spec>
```

**RULE-01**: When `--p2p-whitelist-source` is omitted (or its value is falsy),
the builder MUST substitute the literal string `default`
(`hathor_cli/builder.py`).

**RULE-02**: The `<spec>` value MUST be resolved case-insensitively by
`create_peers_whitelist` (`hathor/p2p/whitelist/factory.py`) in the following
order:

| `<spec>` value (lowercased) | Resolution |
|---|---|
| `default` or `hathorlabs` | If `settings.WHITELIST_URL` is `None`, the whitelist MUST be disabled (return `None`). Otherwise construct `URLPeersWhitelist(reactor, settings.WHITELIST_URL, mainnet=True)`. |
| `none` or `disabled` | Whitelist MUST be disabled — all peers allowed. |
| A value for which `os.path.isfile(<spec>)` is `True` | Construct `FilePeersWhitelist(reactor, <spec>)`. |
| Anything else | Construct `URLPeersWhitelist(reactor, <spec>, mainnet=True)`. |

**RULE-03**: `URLPeersWhitelist` with `mainnet=True` MUST reject the URL with
`ValueError` when the scheme is not `https` or the netloc is empty. With
`mainnet=False`, no scheme/netloc validation is performed.

**RULE-04**: `URLPeersWhitelist` MUST treat the literal URL string `"none"`
(case-insensitive) as equivalent to `None`: `_url` is reset to `None` and all
subsequent fetches become no-ops (an already-resolved `Deferred`).

### Hathor settings used

| Setting | Type | Default | Effect |
|---|---|---|---|
| `WHITELIST_URL` | `str \| None` | Mainnet: `https://hathor-public-files.s3.amazonaws.com/whitelist_peer_ids`. Testnet/other: `None`. | Source URL for the `default` / `hathorlabs` spec. |
| `WHITELIST_WARN_BLOCKED_PEERS` | `bool` | `False` | Controls verbosity of the rejection error sent to a blocked peer (see RULE-18). |

Note: the P2P handshake capability `CAPABILITY_WHITELIST` (`'whitelist'`,
advertised in HELLO) is a separate mechanism and is not part of this
feature's enforcement path. It is flagged here only because the naming
overlaps; see Open Questions.

### Constants

| Constant | Value | Defined in | Purpose |
|---|---|---|---|
| `WHITELIST_REFRESH_INTERVAL` | 30 s | `peers_whitelist.py` | Period of the refresh `LoopingCall`. |
| `WHITELIST_RETRY_INTERVAL_MIN` | 30 s | `peers_whitelist.py` | Base of exponential backoff on looping-call crash. |
| `WHITELIST_RETRY_INTERVAL_MAX` | 300 s | `peers_whitelist.py` | Cap of exponential backoff. |
| `WHITELIST_REQUEST_TIMEOUT` | 45 s | `url_whitelist.py` | Timeout applied to the whole HTTP round trip. |

## Data format

**RULE-05**: Whitelist content (whether served over HTTP or read from a file)
MUST conform to:

```
hathor-whitelist
# Optional comment
policy: <policy-type>
<peer-id-hex>
<peer-id-hex>
...
```

**RULE-06**: The first line MUST be the literal string `hathor-whitelist`. If
the header does not match, `parse_file` MUST raise `ValueError('invalid header')`.

**RULE-07**: After the header, lines MUST be stripped. Empty lines (after
strip) and lines starting with `#` MUST be ignored.

**RULE-08**: The `policy:` directive is optional. If present, it MUST appear
before any peer-ID line. A `policy:` line that appears after at least one peer
ID has been accumulated MUST cause
`ValueError('policy must be defined in the header, before any peer IDs')`.

**RULE-09**: Valid policy values (case-insensitive) are:

| Value | Maps to | Behavior |
|---|---|---|
| `only-whitelisted-peers` | `WhitelistPolicy.ONLY_WHITELISTED_PEERS` | Default when no `policy:` line is present. Only peers in the list are accepted. |
| `allow-all` | `WhitelistPolicy.ALLOW_ALL` | All peers are accepted regardless of list membership. |

Any other policy value MUST raise `ValueError('invalid whitelist policy: ...')`.

**RULE-10**: Each non-policy, non-comment, non-blank line MUST be parsed as a
peer ID by taking the first whitespace-delimited token and passing it to
`PeerId(...)`. A line that fails to parse (`ValueError` or `IndexError`) MUST
be logged as a warning and skipped; it MUST NOT fail the entire update.

## Lifecycle

### Operational states

| State | Detection | Peer admission |
|---|---|---|
| DISABLED | `connections.peers_whitelist is None` and nothing suspended | All peers allowed. |
| GRACE_PERIOD | whitelist exists AND `_has_successful_fetch == False` | Only peers in `_bootstrap_peers`. |
| ENFORCING | whitelist exists AND `_has_successful_fetch == True` | Policy-driven (see RULE-16). |
| SUSPENDED | whitelist moved to `P2pManagerSysctl._suspended_whitelist`; `connections.peers_whitelist is None` | All peers allowed (same as DISABLED). |

### State transitions

| From | Event | To | Side effects |
|---|---|---|---|
| GRACE_PERIOD | Fetch succeeds | ENFORCING | Apply whitelist; clear `_bootstrap_peers`; reset backoff. |
| GRACE_PERIOD | Fetch fails | GRACE_PERIOD | Increment `_consecutive_failures`. Keep bootstrap-only mode. |
| ENFORCING | Fetch succeeds | ENFORCING | Apply new whitelist (diff, disconnect removed peers); reset backoff. |
| ENFORCING | Fetch fails | ENFORCING | Preserve `_current` and `_policy`. Increment `_consecutive_failures`. |
| ENFORCING / GRACE_PERIOD | Looping call crashes | same (restarted after backoff) | `_handle_refresh_err` schedules `_start_lc` after `_get_retry_interval()`. |
| ENFORCING | Sysctl `off` | SUSPENDED | Whitelist stored in `_suspended_whitelist`; active set to `None`. |
| SUSPENDED | Sysctl `on` | ENFORCING | Restore `_suspended_whitelist` as active; immediately disconnect non-whitelisted peers. |
| Any | Sysctl set URL/path | GRACE_PERIOD → ENFORCING | Old whitelist `stop()`ped; `_suspended_whitelist` discarded; new whitelist starts refresh loop. |

### Startup

**RULE-11**: `Builder.build()` MUST pass the constructed `peers_whitelist`
into `ConnectionsManager`. On `ConnectionsManager.start()`, if
`peers_whitelist` is not `None`, the manager MUST call
`peers_whitelist.start(self.drop_connection_by_peer_id)`. `start()` installs
the callback and schedules the first iteration of the refresh `LoopingCall` at
period `WHITELIST_REFRESH_INTERVAL`.

**RULE-12**: During `do_discovery()`, for every discovered entrypoint whose
`peer_id` is not `None`, the manager MUST call
`peers_whitelist.add_bootstrap_peer(entrypoint.peer_id)`. This seeds the
grace-period allowlist so the node can connect to bootstrap peers before the
first successful fetch.

### Periodic refresh

**RULE-13**: The refresh looping call MUST fire every
`WHITELIST_REFRESH_INTERVAL` (30 s). Each invocation calls `update()`, which
MUST be re-entrancy-guarded by `_is_running`: a call while `_is_running` is
`True` MUST log a warning (`'whitelist update already running, skipping
execution.'`) and return an already-resolved `Deferred[None]` without starting
a new fetch. The flag MUST be cleared by an `addBoth` callback on the update
deferred.

**RULE-14**: If `_unsafe_update()` raises an unhandled exception that kills
the looping call, `_handle_refresh_err` MUST:

1. Compute `retry_interval = min(WHITELIST_RETRY_INTERVAL_MIN * 2^_consecutive_failures, WHITELIST_RETRY_INTERVAL_MAX)`.
2. Call `_on_update_failure()` (increments `_consecutive_failures`).
3. Log an error with the retry interval and failure count.
4. Schedule `_start_lc` via `reactor.callLater(retry_interval, ...)`, storing
   the `IDelayedCall` in `_pending_retry`.

| `_consecutive_failures` before error | Retry interval |
|---|---|
| 0 | 30 s |
| 1 | 60 s |
| 2 | 120 s |
| 3 | 240 s |
| 4+ | 300 s (cap) |

**RULE-15**: On a successful update, `_on_update_success()` MUST reset
`_consecutive_failures` to 0.

### Shutdown

**RULE-16**: On `ConnectionsManager.stop()`, if `peers_whitelist` is not
`None`, the manager MUST call `peers_whitelist.stop()`. `stop()` MUST cancel
`_pending_retry` if active and MUST stop `lc_refresh` if it is running.

## Behavior

### Peer admission check

**RULE-17**: The whitelist check occurs in `PeerIdState` during the PEER-ID
handshake, after the remote peer sends its identity. The check logic is:

1. If the connection has no manager or `connections.peers_whitelist is None`
   → peer is **allowed**.
2. Delegate to `PeersWhitelist.is_peer_whitelisted(peer_id)`:
   1. If `_has_successful_fetch` is `False` (grace period) → allowed **only
      if** `peer_id in _bootstrap_peers`.
   2. Else if `_policy == ALLOW_ALL` → **allowed**.
   3. Else (`_policy == ONLY_WHITELISTED_PEERS`) → allowed **only if**
      `peer_id in _current`.

**RULE-18**: When admission returns `False`, the protocol MUST close the
connection with an error message:

- If `settings.WHITELIST_WARN_BLOCKED_PEERS` is `True`:
  `"Blocked (by {peer_id}). Get in touch with Hathor team."`
- Otherwise: `"Connection rejected."`

### Applying a new whitelist

**RULE-19**: When a new whitelist is successfully parsed,
`_apply_whitelist_update(new_whitelist, new_policy)` MUST, **in this order**:

1. Compute the diff between the old and new peer sets; log additions and
   removals.
2. Replace `_current` with `new_whitelist`.
3. Replace `_policy` with `new_policy`.
4. Set `_has_successful_fetch = True`.
5. Clear `_bootstrap_peers`.
6. Call `_on_update_success()` (resets the backoff counter to 0).
7. For each removed peer, call `_on_remove_callback(peer_id)` if the callback
   is set. The callback (`drop_connection_by_peer_id`) disconnects the peer.

State MUST be updated **before** the remove callbacks fire, so that any
re-entrant `is_peer_whitelisted` check triggered during disconnect observes
the new whitelist rather than the stale one. See DEC-03.

**RULE-20**: On fetch failure (network error, non-2xx HTTP status, decode
error, parse error, file read error), `_current` and `_policy` MUST be
preserved. The failure MUST increment `_consecutive_failures` via
`_on_update_failure()`.

### URL source

**RULE-21**: `URLPeersWhitelist._unsafe_update()` MUST:

1. If `_url is None`, return an immediately-resolved `Deferred[None]`.
2. Issue an HTTP GET via `twisted.web.client.Agent` with header
   `User-Agent: hathor-core`.
3. Validate HTTP response status: if `code < 200` or `code >= 300`, raise
   `ValueError(f'Whitelist URL returned HTTP {code}')` so the errback runs.
4. Read the full response body.
5. Apply a `WHITELIST_REQUEST_TIMEOUT` (45 s) timeout to the deferred chain.
6. Decode the body as UTF-8. On `UnicodeDecodeError`, log at `error` and call
   `_on_update_failure()`.
7. Parse via `parse_whitelist_with_policy`. On `ValueError` or other
   exception, log and call `_on_update_failure()`.
8. On success, call `_apply_whitelist_update(new_whitelist, new_policy)`.

**RULE-22**: The errback `_update_whitelist_err` MUST call
`_on_update_failure()` and MUST log at `warning` for
`twisted.internet.defer.TimeoutError`, and at `error` for any other failure
type.

### File source

**RULE-23**: `FilePeersWhitelist._unsafe_update()` MUST read the file via
`twisted.internet.threads.deferToThread` to avoid blocking the reactor.

**RULE-24**: File-source failure handling:

| Failure | Log level | Effect |
|---|---|---|
| `FileNotFoundError` | warning | Keep existing whitelist; call `_on_update_failure()`. |
| `PermissionError` | warning | Keep existing whitelist; call `_on_update_failure()`. |
| Any other read error | error | Keep existing whitelist; call `_on_update_failure()`. |
| Parse error (`ValueError` / other) | error / exception | Keep existing whitelist; call `_on_update_failure()`. |

## Integration points

### ConnectionsManager

**RULE-25**: `ConnectionsManager.set_peers_whitelist(new)` MUST:

1. Call `self.peers_whitelist.stop()` if the current one is not `None`.
2. Assign `self.peers_whitelist = new`.
3. If `new is not None`: call `new.start(self.drop_connection_by_peer_id)`,
   then call `self._disconnect_non_whitelisted_peers()`.

**RULE-26**: `_disconnect_non_whitelisted_peers()` MUST iterate all current
connections. For each connection whose peer ID is known and is not currently
whitelisted, it MUST force-disconnect with reason `'Whitelist updated'`.
Connections whose peer ID is still unknown (mid-handshake) MUST be skipped.

### Status HTTP resource

**RULE-27**: The `/v1a/status` response MUST include a `peers_whitelist` key
containing the list of hex-string peer IDs from
`connections.peers_whitelist.current_whitelist()`. If the whitelist is `None`,
the list MUST be empty.

### Sysctl

**RULE-28**: The sysctl key `p2p.connections.whitelist` MUST support get and
set:

- **Get**: return `whitelist.source()` when an active whitelist exists and its
  source is not `None`; otherwise return the literal string `'none'` (this
  covers both DISABLED and SUSPENDED, and the edge case of a URL whitelist
  whose `_url` was normalized to `None`).
- **Set `"on"`**: if `_suspended_whitelist is None`, this is a silent no-op
  (returns without changing state). Otherwise
  `connections.set_peers_whitelist(_suspended_whitelist)` and clear
  `_suspended_whitelist`.
- **Set `"off"`**: if `connections.peers_whitelist is None`, this is a silent
  no-op. Otherwise move the active whitelist into `_suspended_whitelist` and
  call `connections.set_peers_whitelist(None)`.
- **Set URL/path (any other string)**: call
  `create_peers_whitelist(reactor, value, settings)`. If the result is
  `None`, raise
  `SysctlException('Sysctl does not allow whitelist swap to None. Use "off" to disable it.')`.
  Otherwise set `_suspended_whitelist = None` and call
  `connections.set_peers_whitelist(new)`. Any previously suspended whitelist
  is discarded.

**RULE-29**: The sysctl key `p2p.connections.whitelist.status` MUST be
read-only and return a `WhitelistStatus` dataclass:

| Field | Type | Value when ON | Value when OFF | Value when DISABLED |
|---|---|---|---|---|
| `state` | `WhitelistState` | `ON` | `OFF` | `DISABLED` |
| `policy` | `WhitelistPolicy \| None` | active whitelist's policy | suspended whitelist's policy | `None` |
| `peer_count` | `int` | `len(current_whitelist())` | `len(current_whitelist())` | `0` |
| `source` | `str \| None` | `whitelist.source()` | `whitelist.source()` | `None` |

# Edge Cases & Decisions

**DEC-01: Grace period uses bootstrap peers, not open admission**
Decision: Before the first successful fetch, admit only peers seeded via
`add_bootstrap_peer` (entrypoints discovered during `do_discovery`) — not all
peers.
Rationale: Open admission during the grace period would allow connecting to
arbitrary peers before the authoritative list is loaded, defeating the
whitelist during the most vulnerable window (startup).
Alternative rejected: Allow all peers during grace period. Rejected because it
creates a window for eclipse attacks at startup.

**DEC-02: Whitelist failures preserve the existing list**
Decision: When a fetch fails (network error, HTTP error, decode error, parse
error, file I/O error), the previously loaded whitelist remains in effect.
Rationale: Transient failures should not cause the node to either lock out all
peers (empty list) or admit all peers. The last known good state is the
safest default.
Alternative rejected: Clear the whitelist on failure (too disruptive). Fall
back to `allow-all` on failure (defeats the security purpose).

**DEC-03: State is mutated before remove callbacks fire**
Decision: `_apply_whitelist_update` assigns `_current`, `_policy`,
`_has_successful_fetch`, and clears `_bootstrap_peers` *before* invoking
`_on_remove_callback`.
Rationale: The disconnect callback (`drop_connection_by_peer_id`) can trigger
synchronous re-entrant calls into `is_peer_whitelisted`. If state were still
stale at that point, a just-removed peer would still appear whitelisted while
its disconnect was propagating.

**DEC-04: Identity-based whitelisting, not IP-based**
Decision: The whitelist operates on peer IDs (derived from public keys), not
on IP addresses. The enforcement point is inside `PeerIdState`, after
TLS+PEER-ID.
Rationale: IP-based filtering is trivially bypassed via spoofing or NAT. Peer
IDs are cryptographically bound to the TLS handshake, so they cannot be
forged. Earlier stages do not yet know the peer's cryptographic identity.
Alternative rejected: IP-based filtering via netfilter. Rejected because
netfilter has no peer-identity awareness at decision time.

**DEC-05: File I/O runs in a thread**
Decision: `FilePeersWhitelist` reads the file via `deferToThread`.
Rationale: The Twisted reactor is single-threaded; blocking on file I/O would
stall all networking. Thread delegation keeps the reactor responsive even on
slow storage (NFS, slow disks).
Alternative rejected: Synchronous read in the reactor thread.

**DEC-06: Sysctl `off` suspends but does not destroy the whitelist**
Decision: `set_whitelist("off")` stores the current whitelist object in
`_suspended_whitelist` and sets the active whitelist to `None`.
`set_whitelist("on")` restores it.
Rationale: Operators need a quick toggle for debugging or emergencies without
losing the configured source. A destroy-and-recreate cycle would require
re-specifying the URL/path.
Alternative rejected: Destroy the whitelist on `off`. Rejected for poor
operational ergonomics.

**DEC-07: Sysctl `on` re-runs enforcement immediately**
Decision: When the whitelist is re-enabled via sysctl `on`, the manager
immediately disconnects all currently-connected peers that are not
whitelisted.
Rationale: Peers that connected while the whitelist was suspended should not
remain connected after enforcement resumes. Immediate enforcement closes the
gap that would otherwise last up to a refresh interval.
Alternative rejected: Wait for the next refresh cycle.

**DEC-08: Sysctl on/off on empty state are silent no-ops, not errors**
Decision: `set_whitelist("on")` with no suspended whitelist, and
`set_whitelist("off")` with no active whitelist, both return silently
without raising.
Rationale: Idempotent operator semantics — an operator can script `off`
safely regardless of current state. Only illegal transitions (swap-to-None)
raise `SysctlException`.

**DEC-09: Swapping the whitelist source discards the suspended one**
Decision: When `set_whitelist(<url-or-path>)` installs a new whitelist, any
`_suspended_whitelist` is cleared first.
Rationale: After an explicit swap, a later `on` would have ambiguous
semantics (restore the old suspended one? the new one?). Discarding on swap
makes `on` always mean "resume the most recently active whitelist".

**DEC-10: The `allow-all` policy still fetches and tracks the peer list**
Decision: Under `ALLOW_ALL`, fetches and diffs still occur; only the
admission check short-circuits to `True`.
Rationale: This allows monitoring which peers are on the list without
enforcing it, and a remote flip from `allow-all` to `only-whitelisted-peers`
takes effect on the next refresh without any local action.

**DEC-11: Invalid peer-ID lines are skipped, not fatal**
Decision: A line that fails to parse as a peer ID is logged as a warning and
skipped. The rest of the whitelist is still applied.
Rationale: A single typo in a large whitelist should not block the entire
update. Operators can detect the issue via logs.
Alternative rejected: Reject the entire whitelist on any parse error.
Rejected because it makes the system too brittle for operational use.

**DEC-12: Factory disambiguates file vs URL by filesystem probe**
Decision: `create_peers_whitelist` checks `os.path.isfile(<spec>)` before
falling back to URL interpretation. Reserved words (`default`, `hathorlabs`,
`none`, `disabled`) are matched first.
Rationale: Allows operators to pass a plain path without any prefix. The
file check is unambiguous — if the file exists, it's a file source.
Alternative rejected: Require a `file://` prefix. Rejected for unnecessary
verbosity.

**DEC-13: Mainnet requires HTTPS for URL-based whitelists**
Decision: On mainnet (`URLPeersWhitelist(..., mainnet=True)`), the URL MUST
use `https`.
Rationale: An HTTP whitelist can be MITM'd to inject arbitrary peer IDs,
defeating the security purpose.
Alternative rejected: Allow HTTP everywhere. Rejected for security.

# Open Questions

- Should the grace period have a timeout after which the node falls back to
  DISABLED (or refuses all peers) rather than remaining in bootstrap-only
  mode indefinitely?
- Should `_on_remove_callback` be async / return a `Deferred` so the
  whitelist can await graceful disconnect (e.g. draining in-flight sync)
  before considering the update complete?
- `Builder.set_url_whitelist(..., mainnet=False)` exists as a second entry
  point that bypasses the HTTPS constraint on mainnet. Is this intended only
  for tests, or is it a supported production affordance? If the former,
  consider renaming or restricting it.
- `CAPABILITY_WHITELIST` shares the "whitelist" name with this feature but is
  a distinct handshake capability. Consider renaming one of them to avoid
  confusion.
- `FilePeersWhitelist.refresh()` is a public method that simply calls
  `update()` and has no in-tree caller. Delete or document its intended
  audience.

# Changelog

| Date | Author | Description |
|------|--------|-------------|
| 2026-04-15 | Hathor Labs | Initial draft. |
| 2026-04-15 | Compiled | Merged authored spec and codebase-bootstrapped draft into a single document; fixed step order in the update routine, completed the backoff table, clarified sysctl no-op semantics, added settings table and errback log levels. |
