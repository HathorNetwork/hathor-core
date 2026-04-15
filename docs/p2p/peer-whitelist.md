- Feature Name: peer_whitelist
- Status: Implemented
- Start Date: 2026-04-15
- Authors: Hathor Labs
- Hathor Issue:
- Implementation PR(s):

# Overview

A peer whitelist mechanism for the P2P layer that restricts which peers a node
may connect to. The whitelist is sourced from a remote URL or a local file,
refreshed periodically, and supports two policies: `only-whitelisted-peers`
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

**RULE-01**: When `--p2p-whitelist-source` is omitted or its value is falsy,
the node MUST behave as if `default` was passed.

**RULE-02**: The `<spec>` value MUST be resolved case-insensitively, in the
following order:

| `<spec>` value (lowercased) | Resolution |
|---|---|
| `default` or `hathorlabs` | Use the URL from `settings.WHITELIST_URL`. If `WHITELIST_URL` is unset, the whitelist MUST be disabled (all peers allowed). |
| `none` or `disabled` | Whitelist MUST be disabled. |
| A value that resolves to an existing local file | Use a file-based whitelist reading from that path. |
| Anything else | Treat the value as a URL. |

**RULE-03**: On mainnet, URL sources MUST use the `https` scheme and MUST have
a non-empty host. A URL that violates either constraint MUST be rejected at
construction time.

**RULE-04**: A URL source whose value is the literal string `none`
(case-insensitive) MUST behave as if no URL were configured: the source is
treated as inactive and refreshes are no-ops.

### Hathor settings used

| Setting | Type | Default | Effect |
|---|---|---|---|
| `WHITELIST_URL` | `str \| None` | Mainnet: `https://hathor-public-files.s3.amazonaws.com/whitelist_peer_ids`. Testnet/other: unset. | Source URL for the `default` / `hathorlabs` spec. |
| `WHITELIST_WARN_BLOCKED_PEERS` | `bool` | `false` | Controls verbosity of the rejection error sent to a blocked peer (see RULE-18). |

Note: the P2P handshake capability `CAPABILITY_WHITELIST` (`'whitelist'`,
advertised in HELLO) is a separate mechanism and is not part of this
feature's enforcement path. It is flagged here only because the naming
overlaps; see Open Questions.

### Constants

| Constant | Value | Purpose |
|---|---|---|
| `WHITELIST_REFRESH_INTERVAL` | 30 s | Refresh period for the whitelist. |
| `WHITELIST_RETRY_INTERVAL_MIN` | 30 s | Base of exponential backoff when the refresh mechanism crashes. |
| `WHITELIST_RETRY_INTERVAL_MAX` | 300 s | Cap of exponential backoff. |
| `WHITELIST_REQUEST_TIMEOUT` | 45 s | Timeout for a single URL fetch (full round trip). |

## Data format

**RULE-05**: Whitelist content (whether served over HTTP or read from a file)
MUST conform to:

```
hathor-whitelist
# Optional comment
# policy: <policy-type>
<peer-id-hex>
<peer-id-hex>
...
```

**RULE-06**: The first line MUST be the literal string `hathor-whitelist`.
Content with any other first line MUST be rejected.

**RULE-07**: After the header, empty lines MUST be ignored.

**RULE-08**: The `policy:` directive is optional and MUST be written as a
commented line (`# policy: <value>`) for backward compatibility with parsers
that do not recognize the directive. If present, it MUST appear before any
peer-ID line. A `policy:` line that appears after at least one peer ID has
been accumulated MUST cause the content to be rejected.

**RULE-09**: Valid policy values (case-insensitive) are:

| Value | Behavior |
|---|---|
| `only-whitelisted-peers` | Default when no `policy:` line is present. Only peers in the list are accepted. |
| `allow-all` | All peers are accepted regardless of list membership. |

Any other policy value MUST cause the content to be rejected.

**RULE-10**: Each non-policy, non-comment, non-blank line MUST be parsed as a
peer ID (first whitespace-delimited token). A line that fails to parse as a
valid peer ID MUST be logged as a warning and skipped; it MUST NOT fail the
entire update.

## Lifecycle

### Operational states

| State | Description | Peer admission |
|---|---|---|
| DISABLED | No whitelist configured. | All peers allowed. |
| GRACE_PERIOD | Whitelist configured but no successful fetch yet. | Only bootstrap peers (see RULE-12) allowed. |
| ENFORCING | Whitelist loaded from at least one successful fetch. | Policy-driven (see RULE-17). |
| SUSPENDED | Whitelist configured but temporarily not enforced (via sysctl). | All peers allowed (same as DISABLED). |

### State transitions

| From | Event | To | Side effects |
|---|---|---|---|
| GRACE_PERIOD | Fetch succeeds | ENFORCING | Apply whitelist; drop bootstrap-peer state; reset backoff. |
| GRACE_PERIOD | Fetch fails | GRACE_PERIOD | Increment failure counter. Keep bootstrap-only admission. |
| ENFORCING | Fetch succeeds | ENFORCING | Apply new whitelist (diff, disconnect removed peers); reset backoff. |
| ENFORCING | Fetch fails | ENFORCING | Preserve the active whitelist and policy. Increment failure counter. |
| ENFORCING / GRACE_PERIOD | Refresh mechanism crashes | same (restarted after backoff) | Restart scheduled after `min(BASE * 2^failures, MAX)` (see RULE-14). |
| ENFORCING | Sysctl `off` | SUSPENDED | Whitelist retained for later restore; enforcement paused. |
| SUSPENDED | Sysctl `on` | ENFORCING | Enforcement resumes; currently-connected non-whitelisted peers MUST be disconnected immediately (see DEC-07). |
| Any | Sysctl set URL/path | GRACE_PERIOD → ENFORCING | Old whitelist stopped; any suspended whitelist discarded; new whitelist begins refreshing. |

### Startup

**RULE-11**: When the node starts and a whitelist is configured, the whitelist
MUST begin refreshing periodically and MUST be registered with a
disconnect-on-removal callback that drops any peer removed from the list.

**RULE-12**: During peer discovery, every entrypoint whose peer ID is known
MUST be registered as a bootstrap peer so the node can connect to it during
the grace period.

### Periodic refresh

**RULE-13**: The whitelist MUST be refreshed every `WHITELIST_REFRESH_INTERVAL`.
Refreshes MUST NOT overlap: if a refresh is triggered while another is still
in progress, the new invocation MUST be skipped (with a warning log) and MUST
NOT start a parallel fetch.

**RULE-14**: If the refresh mechanism fails unexpectedly (not a single fetch
failure, but the refresh loop itself), it MUST be restarted after a delay of
`min(WHITELIST_RETRY_INTERVAL_MIN * 2^failures, WHITELIST_RETRY_INTERVAL_MAX)`:

| Consecutive failures | Retry interval |
|---|---|
| 0 | 30 s |
| 1 | 60 s |
| 2 | 120 s |
| 3 | 240 s |
| 4+ | 300 s (cap) |

**RULE-15**: A successful refresh MUST reset the consecutive-failure counter
to 0.

### Shutdown

**RULE-16**: When the node shuts down, any pending retry MUST be cancelled and
the refresh mechanism MUST stop cleanly.

## Behavior

### Peer admission check

**RULE-17**: The whitelist check occurs during the PEER-ID handshake, after
the remote peer has sent its identity. The check MUST follow this logic:

1. If no whitelist is configured → peer is **allowed**.
2. If the whitelist has never completed a successful fetch (grace period) →
   peer is allowed **only if** it is a registered bootstrap peer.
3. Else if the active policy is `allow-all` → peer is **allowed**.
4. Else (`only-whitelisted-peers`) → peer is allowed **only if** its ID is in
   the active whitelist.

**RULE-18**: When admission fails, the connection MUST be closed with an error
message:

- If `WHITELIST_WARN_BLOCKED_PEERS` is `true`:
  `"Blocked (by {peer_id}). Get in touch with Hathor team."`
- Otherwise: `"Connection rejected."`

### Applying a new whitelist

**RULE-19**: When a refresh successfully parses a new whitelist, the system
MUST update the active whitelist, active policy, and grace-period flag
**before** invoking any disconnect-on-removal callback for peers that left
the set. This ordering is observable: a re-entrant admission check performed
inside a disconnect callback MUST see the new whitelist, not the old one.
(See DEC-03.)

**RULE-20**: A refresh failure (network error, non-2xx HTTP status, decode
error, parse error, or file I/O error) MUST preserve the active whitelist
and policy unchanged. The failure MUST increment the consecutive-failure
counter.

### URL source

**RULE-21**: A URL fetch MUST:

1. Issue an HTTP GET with header `User-Agent: hathor-core`.
2. Reject any HTTP status outside the 2xx range.
3. Apply `WHITELIST_REQUEST_TIMEOUT` to the entire round trip.
4. Decode the body as UTF-8.
5. Parse the body per the data-format rules above.
6. On success, apply the parsed whitelist per RULE-19.
7. On any failure, leave the active whitelist unchanged per RULE-20.

**RULE-22**: A fetch timeout SHOULD be logged at a lower severity (e.g.
`warning`) than other fetch failures (e.g. `error`), since timeouts are
expected during transient network issues.

### File source

**RULE-23**: File reads for the whitelist MUST NOT block the reactor thread.

**RULE-24**: A file that is missing or unreadable MUST be treated as a
transient failure: the active whitelist is preserved, the failure counter
is incremented, and the event is logged. A missing file MUST NOT cause the
node to lock out all peers.

## Integration points

### Runtime replacement

**RULE-25**: Replacing the active whitelist at runtime MUST:

1. Stop the previous whitelist (if any).
2. Install the new whitelist and begin refreshing it.
3. Immediately disconnect any currently-connected peer that is not admitted
   by the new whitelist.

**RULE-26**: When disconnecting peers on a whitelist change, peers whose
identity is not yet known (still handshaking) MUST be skipped — their
admission will be evaluated when they reach the PEER-ID state.

### Status HTTP resource

**RULE-27**: The `/v1a/status` response MUST include a `peers_whitelist` key
containing the list of currently whitelisted peer IDs as hex strings. If no
whitelist is active, the list MUST be empty.

### Sysctl

**RULE-28**: The sysctl key `p2p.connections.whitelist` MUST support:

- **Get**: returns the source string (URL or file path) of the active
  whitelist, or the literal `"none"` if no whitelist is currently active
  (covers DISABLED, SUSPENDED, and a URL source whose URL is unset).
- **Set `"on"`**: resume enforcement of a previously suspended whitelist. If
  nothing is suspended, this is a silent no-op. (See DEC-08.)
- **Set `"off"`**: suspend the active whitelist (retain it for a later `on`).
  If no whitelist is active, this is a silent no-op.
- **Set any other value**: treat it as a new whitelist spec, construct the
  corresponding whitelist, and replace the active one. If the spec resolves
  to "no whitelist", the operation MUST fail (operators must use `off` to
  disable). Any previously suspended whitelist MUST be discarded.

**RULE-29**: The sysctl key `p2p.connections.whitelist.status` MUST be
read-only and MUST return a structured status value with the following
fields:

| Field | Value when ON | Value when OFF (suspended) | Value when DISABLED |
|---|---|---|---|
| `state` | `ON` | `OFF` | `DISABLED` |
| `policy` | active whitelist's policy | suspended whitelist's policy | unset |
| `peer_count` | size of the whitelist | size of the suspended whitelist | 0 |
| `source` | source string (URL or file path) | source string | unset |

# Edge Cases & Decisions

**DEC-01: Grace period uses bootstrap peers, not open admission**
Decision: Before the first successful fetch, admit only peers discovered via
entrypoints (bootstrap peers) — not all peers.
Rationale: Open admission during the grace period would allow connecting to
arbitrary peers before the authoritative list is loaded, defeating the
whitelist during the most vulnerable window (startup).
Alternative rejected: Allow all peers during grace period. Rejected because
it creates a window for eclipse attacks at startup.

**DEC-02: Whitelist failures preserve the existing list**
Decision: When a refresh fails (network error, HTTP error, decode error,
parse error, file I/O error), the previously loaded whitelist remains in
effect.
Rationale: Transient failures must not cause the node to either lock out all
peers (empty list) or admit all peers. Last-known-good is the only safe
default.
Alternative rejected: Clear the whitelist on failure (too disruptive). Fall
back to `allow-all` on failure (defeats the security purpose).

**DEC-03: State is updated before disconnect callbacks fire**
Decision: On a whitelist update, the active whitelist and policy are updated
before any disconnect-on-removal callback is invoked.
Rationale: A disconnect callback can trigger a synchronous re-entrant
admission check. If the state were still stale at that point, a just-removed
peer would still appear whitelisted while its disconnect was propagating, and
the reverse for newly-added peers.

**DEC-04: Identity-based whitelisting, not IP-based**
Decision: The whitelist operates on peer IDs (derived from public keys), not
on IP addresses. Enforcement happens after TLS+PEER-ID.
Rationale: IP-based filtering is trivially bypassed via spoofing or NAT. Peer
IDs are cryptographically bound to the TLS handshake and cannot be forged.
The earliest point at which identity is known is after PEER-ID.
Alternative rejected: IP-based filtering via netfilter. Rejected because
netfilter has no peer-identity awareness at decision time.

**DEC-05: File I/O MUST NOT block the reactor**
Decision: File reads are performed off the reactor thread.
Rationale: The reactor is single-threaded; blocking on file I/O stalls all
networking. This must hold even on slow storage (NFS, slow disks).
Alternative rejected: Synchronous reads on the reactor thread.

**DEC-06: Sysctl `off` suspends but does not destroy the whitelist**
Decision: `off` retains the configured whitelist so `on` can restore it
without re-specifying the URL/path.
Rationale: Operators need a quick toggle for debugging or emergencies without
losing the configured source.
Alternative rejected: Destroy the whitelist on `off`. Rejected for poor
operational ergonomics.

**DEC-07: Sysctl `on` re-runs enforcement immediately**
Decision: When the whitelist is re-enabled via sysctl `on`, currently-connected
peers that are not admitted by the whitelist are disconnected immediately.
Rationale: Peers that connected while the whitelist was suspended must not
remain connected after enforcement resumes. Immediate enforcement closes the
gap that would otherwise last up to a refresh interval.
Alternative rejected: Wait for the next refresh cycle.

**DEC-08: Sysctl on/off on empty state are silent no-ops, not errors**
Decision: `on` with no suspended whitelist, and `off` with no active
whitelist, both return silently.
Rationale: Idempotent operator semantics — operators can script `off`/`on`
safely regardless of current state. Only illegal transitions
(swap-to-disabled) raise errors.

**DEC-09: Swapping the whitelist source discards the suspended one**
Decision: When sysctl sets a new URL/path, any suspended whitelist is
discarded before the new one is installed.
Rationale: After an explicit swap, a later `on` would have ambiguous
semantics (restore the old suspended one? the new one?). Discarding on swap
makes `on` always mean "resume the most recently active whitelist".

**DEC-10: The `allow-all` policy still fetches and tracks the peer list**
Decision: Under `allow-all`, refreshes still occur; only the admission check
short-circuits to allowed.
Rationale: This lets operators monitor which peers are on the list without
enforcing it, and a remote flip from `allow-all` to `only-whitelisted-peers`
takes effect on the next refresh without any local action.

**DEC-11: Invalid peer-ID lines are skipped, not fatal**
Decision: A line that fails to parse as a peer ID is logged as a warning and
skipped; the rest of the whitelist is still applied.
Rationale: A single typo in a large whitelist must not block the entire
update. Operators can detect the issue via logs.
Alternative rejected: Reject the entire whitelist on any parse error.
Rejected because it makes the system too brittle for operational use.

**DEC-12: The `policy:` directive is written as a comment**
Decision: The policy directive is a commented line (`# policy: <value>`),
not a bare `policy: <value>` line.
Rationale: Older parsers that predate the policy feature must still accept
newer whitelist files without error. A commented directive is ignored by
them (treated as an ordinary comment) while a new parser recognizes it.
Alternative rejected: A bare directive. Rejected because it would cause
older nodes to reject otherwise-valid whitelist content.

**DEC-13: File-vs-URL spec disambiguation by filesystem probe**
Decision: The CLI spec resolver checks whether the value is an existing
file before falling back to URL interpretation. Reserved words (`default`,
`hathorlabs`, `none`, `disabled`) are matched first.
Rationale: Allows operators to pass a plain path without any prefix.
Alternative rejected: Require a `file://` prefix. Rejected for unnecessary
verbosity.

**DEC-14: Mainnet requires HTTPS for URL-based whitelists**
Decision: On mainnet, URL whitelists MUST use `https`.
Rationale: An HTTP whitelist can be MITM'd to inject arbitrary peer IDs,
defeating the security purpose.
Alternative rejected: Allow HTTP everywhere. Rejected for security.

# Open Questions

- Should the grace period have a timeout after which the node falls back to
  DISABLED (or refuses all peers) rather than remaining in bootstrap-only
  mode indefinitely?
- Should the disconnect-on-removal callback be async so the whitelist can
  await graceful disconnect (e.g. draining in-flight sync) before considering
  the update complete?
- There is a second entry point for constructing a URL whitelist that
  bypasses the mainnet HTTPS constraint. Is this intended only for tests,
  or is it a supported production affordance? If the former, consider
  restricting it.
- `CAPABILITY_WHITELIST` shares the "whitelist" name with this feature but
  is a distinct handshake capability. Consider renaming one of them to avoid
  confusion.

# Changelog

| Date | Author | Description |
|------|--------|-------------|
| 2026-04-15 | Hathor Labs | Initial draft. |
| 2026-04-15 | Hathor Labs | Merged authored spec and codebase-bootstrapped draft: fixed step order in the update routine, completed the backoff table, clarified sysctl no-op semantics, added settings table, errback log-level guidance. |
| 2026-04-15 | Hathor Labs | Removed implementation bleed (private field names, function names, file paths, library primitives, exception-class assertions) per review; fixed `# policy:` directive format for backward compatibility (new DEC-12); constants table dropped "Defined in" column. |
