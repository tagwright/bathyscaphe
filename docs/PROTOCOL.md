<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# bathyscaphe <-> airlock wire protocol, v1

This is the human-readable spec of the wire protocol implemented by
`bathyscaphe-proto`. It must match the code in that crate; if the two
disagree, the code is the bug (or this file is, but check the code
first). It is derived from `bathy_protocol_draft.md` (the ratified
field-level authority) with a small number of deliberate spelling
deviations, called out below.

## 1. Framing and transport

Three streams, exactly as spawned by airlock (the same shape as its `ig
run <gadget> -o json` adapter):

| Channel | Direction | Carries |
|---|---|---|
| stdout | bathyscaphe -> airlock | `UpMessage` lines: `hello`, `event`, `stats`, `policy_ack`, `release_ack`, `security`, `error` |
| stdin | airlock -> bathyscaphe | `DownMessage` lines: `start`, `policy`, `release`, `release_all`, `shutdown`, `sync_complete` |
| stderr | bathyscaphe -> operator | free-text human logs, never parsed |

NDJSON: one JSON object per line, UTF-8, `\n`-terminated. Every line has a
required string field `kind`, the message discriminator, on both
directions including `event` lines. A conformant JSON encoder never
emits a raw newline inside a string, so `\n` is an unambiguous message
boundary; `bathyscaphe-proto::codec::encode_line` produces exactly one
compact JSON line with no embedded newline.

Rules the daemon (not this crate) must enforce on the I/O loop:

- Maximum line length `bathyscaphe_proto::codec::MAX_LINE_BYTES` (1 MiB).
  A longer line is a protocol error.
- A malformed line (bad JSON, over-length, missing `kind`, or an
  unrecognized `kind`) is counted and skipped.
  `bathyscaphe_proto::codec::MAX_CONSECUTIVE_MALFORMED_LINES` (3)
  consecutive malformed lines on either stream is a fatal desync: the
  reader terminates the session (airlock kills and respawns bathyscaphe;
  bathyscaphe exits nonzero on its stdin side). Fail loud, never limp
  along on a desynced stream.
- Writers flush promptly (each line, or a small batch with a bounded
  cap) so alert latency stays bounded.

Protocol version is a single integer, `PROTO_VERSION` (currently `1`).
bathyscaphe advertises the versions it speaks as `hello.proto_versions`;
airlock selects one in `start.proto`. A version bump is reserved for a
change that breaks the ignore-unknown rules in section 7; none is
expected. New features within a version arrive as capabilities, not
version bumps.

## 2. Handshake

`hello` (up, first line on stdout, exactly once per process lifetime):
`backend`, `backend_version`, `proto_versions: [u32]`,
`capabilities: [Capability]`, `pinned: [PinnedContainer]` (the
reconciliation input, see section 6; empty on true cold start).

Capability registry (v1): `observe`, `enforce`, `enforce_udp`,
`dns_enrich`, `sni_enrich`, `enforce_fqdn`. The first v1 build shipped
`["observe", "enforce", "enforce_udp"]`; the DNS-observation build chunk
added `dns_enrich`, and the FQDN-enforcement build chunk (`docs/DNS.md`)
added `enforce_fqdn`, both with no wire change, so a current build ships
`["observe", "enforce", "enforce_udp", "dns_enrich", "enforce_fqdn"]`.
`sni_enrich` remains unbuilt. Unknown capability strings decode to
`Capability::Unknown` rather than erroring (forward-compat; airlock's own
Go-side reader independently ignores strings it doesn't recognize).

`start` (down, airlock's reply, exactly once): `proto: u32`,
`stats_interval_s: u32` (default 10 when omitted). If no version overlap
exists airlock does not send `start` at all: it kills the subprocess and
surfaces a fatal backend-incompatible error to the operator. bathyscaphe
emits nothing after `hello` until `start` arrives, except stderr.
Enforcement state after `start` is exactly whatever was pinned; cold
start attaches no enforcement until the first `policy` arrives.

Missing-capability behavior is normative on the airlock side (not
encoded in this crate, since it's airlock's decision, not a wire shape):
asking for `mode: block` on a backend without `enforce` is a sticky
validation error, never a silent downgrade to alert. A `policy` sent
containing rule types this build cannot enforce (name rules without
`enforce_fqdn`, udp matchers without `enforce_udp`, or a `match` this
build has never heard of) is still accepted onto the snapshot; those
rules are marked inert and counted in `policy_ack.inert_rules` rather
than rejected. `policy_ack.inert_rules` is the cross-check that whatever
capabilities promised actually holds at runtime.

## 3. Event schema (up, `kind: "event"`)

One line per observed egress decision. The nouns are IG's: `container.*`
maps 1:1 to `runtime.containerId` / `runtime.containerName` /
`runtime.containerImageName` / `runtimeName`, so airlock's join logic is
backend-neutral.

| Field | Type | Notes |
|---|---|---|
| `ts` | RFC3339 string, UTC, >= microseconds | kernel event time |
| `event` | `connect` \| `accept` \| `close` | v1 emits `connect` only; the others are reserved for additive use |
| `proto` | `tcp` \| `udp` | `udp` live under `enforce_udp` |
| `container.id` / `.name` / `.image` / `.runtime` | string / string? / string? / `docker`\|`podman` | `name`/`image` null only on a lost runtime-API race, never omitted |
| `process.pid` / `.tid` / `.uid` / `.gid` / `.comm` | all `Option`, best-effort | none of it gates a verdict |
| `src.addr` / `.port`, `dst.addr` / `.port` | `IpAddr`, `u16` | `dst` is the policy input, resolved at connect time |
| `verdict` | `allow` \| `deny` \| `would_deny` | `deny` only in `mode: block`; `would_deny` in audit/alert when the lookup says it would have blocked; observe-only always returns allow to the kernel regardless of this field |
| `rule_id` | `Option<String>` | id of the matching rule, null when the default verdict applied or the build doesn't track it |
| `domain.name` / `.source` / `.confidence` | all `Option`, ALWAYS present as an object | all-null until the DNS/SNI layer; the object's presence never changes, only the values do |
| `meta.dropped_since_last` | `u64`, never omitted | events lost since the previous emitted event |

`meta.backend` is deliberately not on the event: backend identity is
established once in `hello`, airlock stamps it downstream.

**Spelling deviation from the draft:** the draft's prose writes
`would-deny` (hyphen). No wire example in the draft actually shows the
literal string, and this crate applies `rename_all = "snake_case")`
uniformly to every enum on the wire, giving `would_deny`. See the FORKS
section below.

## 4. Directive schema (down, `kind: "policy"`)

A full compiled snapshot per container, replacing that container's
entire prior policy atomically. Not a delta: idempotent, re-sendable at
any time, applying it twice is a no-op. bathyscaphe applies it
make-before-break so no connect ever observes a half-applied policy.

`policy`: `container_id`, `generation: u64` (airlock-owned, monotonic
per container, echoed in `policy_ack`/`stats`/`hello.pinned`),
`mode: audit|alert|block`, `default: allow|deny` (explicit, never implied
by `mode`), `rules: [Rule]`.

`Rule`: `id` (opaque, echoed as `rule_id` on events), `action: allow|deny`,
`match` (see below), `expires_at` (RFC3339, nullable, absolute not
relative, so replaying a snapshot after a restart never extends a rule's
life), `source: static|dns`.

`Match`, tagged on `type`:

- `{"type": "cidr", "cidr": <prefix>, "port": <u16 | null>, "proto": <tcp|udp|null>}`
- `{"type": "name", "pattern": <exact-or-*.wildcard>, "port": <u16 | null>, "proto": <tcp|udp|null>}`

Evaluation: most-specific-match on cidr (LPM), `deny` wins over `allow`
at equal specificity. Name rules are evaluated only by builds with the
relevant capability.

### The inert-matcher rule (the one ignore-unknown carve-out)

Everywhere else on the wire, an unknown field is silently ignored and an
unknown `kind` is counted and skipped (section 7). Inside `match`, this
is inverted on purpose: an unrecognized field on a known matcher type,
or an entirely unrecognized `type`, is captured, not dropped, and the
rule is marked **inert**. Silently ignoring an unknown matcher field
could silently widen an `allow` or narrow a `deny`, which is a policy
hole; bathyscaphe never guesses.

Implementation: `Match::Cidr` and `Match::Name` each carry
`#[serde(flatten)] unknown: Map<String, Value>`, capturing any field
neither variant declares. A `type` this build has never heard of at all
decodes to the catch-all `Match::Unknown` variant (via `#[serde(other)]`)
rather than failing to parse the whole `policy` message. `Match::is_inert()`
is `true` whenever `unknown` is non-empty, or the variant is `Unknown`.
The daemon sums `is_inert()` across a snapshot's rules into
`policy_ack.inert_rules`. If a matcher ever needs a genuinely new field
(port ranges, say), it ships as a **new** `type` (e.g. `cidr_range`)
gated behind a new capability; old builds report it inert, and airlock
knows from capabilities not to send it to a build that can't.

`policy_ack` (up, one per `policy`, in order): `container_id`,
`generation`, `status: applied|error`, `inert_rules: u32`,
`error: Option<String>`. On `status: error` the previously applied
generation remains enforced (fail-closed, never partially applied).

`release` (down) / `release_ack` (up): drops enforcement for one
container (detach the deny path, unpin its policy maps and metadata,
egress fully open, observation continues). Idempotent: a late release
for an unknown or already-gone container still acks `released`.

`release_all` (down): host-level emergency variant, releases every
container, acks one `release_ack` per container. Its own message kind on
purpose, not a loop airlock might half-complete.

`shutdown` (down): clean-exit request, equivalent to SIGTERM. bathyscaphe
stops emitting, leaves all pinned enforcement in place, exits 0.

## 5. Stats and health (up, `kind: "stats"`)

Emitted every `stats_interval_s` seconds, ALWAYS, including when fully
idle: this is the heartbeat that lets airlock tell "no traffic" from
"probe wedged" apart.

`ts`, `seq: u64` (monotonic per process, gaps visible if airlock's
reader lags), `uptime_s`, `events_emitted` (cumulative),
`events_dropped_total` (cumulative, the **tamper counter**: ring-buffer
reservation failures plus any userspace shedding), `containers: [ContainerStats]`.

`ContainerStats`: `id`, `mode` (the directive's intent), `generation`,
`enforcing: bool` (the kernel truth: is the deny path actually armed;
distinct from `mode` so "asked for block, not actually armed" is
visible), `rules_active`, `rules_inert`, `dropped_total` (per-container
attribution of the tamper counter), `orphaned: bool` (see section 6).

Normative reader behavior (airlock side, not enforced by this crate):
a nonzero delta in `events_dropped_total` between consecutive stats is a
high-severity alert naming the container(s) whose `dropped_total` moved,
never a debug-level log line; three missing stats intervals means the
probe is wedged and gets killed and respawned (enforcement is unaffected
throughout, it's pinned); a container reporting `mode: block` with
`enforcing: false` for more than one interval gets its snapshot
re-pushed and, if the mismatch survives, an alert; `orphaned: true`
always alerts.

There is no protocol-level flow control on events: the kernel RingBuf is
the buffer, and userspace never blocks its reader on a full stdout pipe,
it sheds and counts instead. Every shed is visible in
`meta.dropped_since_last` and `events_dropped_total`. Events are lossy
with loud accounting; directives and acks are never lossy (their loss is
a fatal protocol error, kill and respawn).

## 6. Fail-closed reconciliation

- airlock is the sole source of truth for **intended** policy.
- Pinned kernel state is the sole source of truth for **enforced**
  policy, and only ever reports it, never invents it.
- Reconciliation is always: report enforced (`hello.pinned`), re-assert
  intended (airlock re-pushes every snapshot, unconditionally, since
  snapshots are idempotent), converge, and surface anything
  enforced-but-unintended for an explicit decision. It is never
  auto-dropped, because auto-dropping enforcement is fail-open in
  disguise.

Sequence, on every bathyscaphe start (crash-restart and cold start
alike): bathyscaphe re-adopts pinned links/programs/maps/metadata (the
kernel programs never stopped running; zero enforcement gap; cold start
has nothing pinned and attaches no enforcement) -> emits `hello` with
`pinned` -> airlock sends `start` -> airlock re-pushes every snapshot it
manages on this host -> airlock sends `sync_complete` -> bathyscaphe
marks anything that was pinned but received neither `policy` nor
`release` in between as **orphaned**, kept enforcing exactly as pinned
(fail-closed), reported in `stats.containers[].orphaned`, until airlock
(or an operator) explicitly adopts (`policy`) or `release`s it.

airlock restarting also restarts bathyscaphe (its child process), and
the identical sequence runs; kernel enforcement rides through both
restarts untouched. There is deliberately one reconciliation path in the
whole system.

Mid-session: a new container gets `policy` when airlock's label
evaluation decides so; observation starts on discovery with no directive
needed. A removed container gets `release`; if the cgroup vanished first,
bathyscaphe unpins on its own and reports the container gone from
`stats`.

## 7. Versioning and extensibility

- **Ignore-unknown is the law**, both directions: unknown fields in any
  known message are silently ignored, unknown top-level `kind` values are
  counted, warned once per kind, and skipped. New kinds and fields are
  free and additive within proto 1.
- **The one carve-out**: unknown matcher `type`s and unknown fields
  inside `match` are captured and marked inert, never ignored (section
  4). This is the single asymmetry in an otherwise uniform
  forward-compat rule, and it exists because ignoring a matcher
  constraint is a policy hole, not a compatibility nicety.
- Enum values follow the same asymmetry: an unrecognized `mode` is a
  protocol error (`policy_ack.status: error`, never guess how to apply
  it), unrecognized values of observational enums (`event`, `verdict`,
  `source`) are skip-with-count.
- Capabilities, not versions, gate features. The DNS layer turns
  `domain.*` non-null and starts honoring `type: "name"` matchers
  (`dns_enrich`, `sni_enrich`, `enforce_fqdn`); UDP events and matchers
  are already in the enums (`enforce_udp`); `accept`/`close` are already
  in the `event` enum; dns-derived rules already have `source` and
  `expires_at`. None of this needs a `proto` bump.

## 8. The security record (refinement R1) and the beacon/bilgeline mapping

`security` (up, `kind: "security"`): a loud, first-class record for
security-relevant conditions — an unenforceable name rule hit in
`mode: block`, sustained event drops, a policy violation, an in-kernel
block — shaped after the OpenTelemetry log data model:

```json
{"kind":"security","timestamp":"2026-08-27T12:00:09.001271Z","severity_text":"ERROR","severity_number":17,"body":"denied connection to unresolved name rule target","attributes":{"container.id":"9f8e...","container.image":"whoami:latest","container.name":"suspicious-1","reason":"policy.unenforceable_name","rule_id":"r-gh-name"}}
```

Fields: `timestamp` (RFC3339), `severity_text` (`INFO`\|`WARN`\|`ERROR`),
`severity_number` (`u8`, OTel severity-number scale), `body` (the
human-readable message), `attributes` (a flat map of OTel-style,
dot-namespaced attribute keys — not a nested object — always including
`reason` and `container.id`/`container.name`/`container.image`, with
`rule_id` and/or `domain` present only when relevant).

**Stable `reason` codes** (`bathyscaphe_proto::security::reason`):
`policy.unenforceable_name` (reserved for a build without `enforce_fqdn`;
never emitted by a build advertising it), `tamper.event_drops`,
`policy.violation` (reserved, not yet emitted by any build),
`enforce.blocked`, and (build chunk #10) `policy.name_unresolved_block` --
a container with an active allow-listed name rule was denied a connection
to a destination this build never observed a DNS answer for at all
(raw-IP egress, or a DoH/DoT/ECH lookup it cannot see). See `docs/DNS.md`
for the full FQDN-enforcement design this reason belongs to.

**Severity mapping**, the trivial part that lets airlock forward a
`security` record to beacon with no remapping:

| `severity_number` | beacon `Level` |
|---|---|
| `< 13` | `Info` |
| `13..=16` | `Warning` |
| `>= 17` | `Error` |

`INFO` = 9, `WARN` = 13, `ERROR` = 17 (`Severity::number()`), matching the
OTel severity-number scale directly, so the comparison above is the
entire mapping, in both directions of intent: airlock reads it to pick a
beacon `Level`, and any future backend or tool emitting these records
just needs to know these three numbers to be beacon-compatible.

**bilgeline compatibility**: the record's shape is exactly the field set
a stock OTel Collector `filelog` receiver expects to find via a plain
JSON parser operator: `timestamp`, `severity_text`, `severity_number`,
`body`, and `attributes` map onto the identically-named OTel log record
fields with no custom parsing logic. bathyscaphe's own stderr operational
logs use this same JSON shape by default for the same reason (a
`--log-format=text` flag exists for interactive human use; that flag and
its behavior live in the daemon, not this crate).

Loud records are token-bucket throttled (the Falco pattern) before they
reach this wire, so a drop or violation storm never floods the pipe;
throttling policy is entirely a daemon-side concern, this crate defines
only the record's shape.

## FORKS FOR NATE (spelling deviations from `bathy_protocol_draft.md`)

Two enum spellings differ from the draft's prose, both because the
build brief for this chunk specified the underscored form explicitly
and no wire JSON *example* in the draft actually shows the hyphenated
literal (only prose does):

1. `verdict: "would-deny"` (draft prose) vs `"would_deny"` (implemented).
2. Capability strings `enforce-udp` / `dns-enrich` / `sni-enrich` /
   `enforce-fqdn` (draft prose) vs `enforce_udp` / `dns_enrich` /
   `sni_enrich` / `enforce_fqdn` (implemented).

Rationale for going with underscores: `#[serde(rename_all = "snake_case")]`
applied once, uniformly, to every enum on the wire is simpler to keep
correct than hand-picking hyphens for five specific values while every
other enum (`mode`, `action`, `source`, `runtime`, ...) is already
underscore/single-word. If Nate prefers the hyphenated spellings to
match the draft literally, it's a one-line `rename_all` override (or a
handful of `#[serde(rename = "...")]` on individual variants) on exactly
these two enums, with no other structural change, and airlock's Go side
would need the matching spelling. Flagging for arbitration rather than
silently picking one, per the build agent brief.

A second documented inference, not a fork: the build brief's own
abbreviated description of `Match` lists only `cidr`/`pattern` and
`port` as fields, omitting `proto`. The draft document's actual JSON
examples (`{"type":"cidr","cidr":"140.82.121.0/24","port":443,"proto":"tcp"}`)
include `proto` throughout, and section 4's field text implies it too.
This crate follows the draft's fuller schema and includes `proto` as a
named, non-flattened field on both `Match::Cidr` and `Match::Name`.
Doing otherwise would have been actively harmful: without a named
`proto` field, any real-world rule specifying a transport would fall
into the flattened `unknown` map and be spuriously marked inert.

A third minor point, not really a fork so much as a documented
inference: the draft's stdout kind table lists `error` alongside
`hello`/`event`/`stats`/`policy_ack`/`release_ack` but never specifies
its fields elsewhere in the document. This crate implements it as a
minimal `{"kind":"error","message":"<string>"}` for backend-level
protocol/operational errors not scoped to one container's policy (which
already has `policy_ack.error` for that). If a richer shape was intended
(a `fatal: bool`, an error code, ...), that's additive later since
`ErrorMsg` isn't otherwise load-bearing anywhere in this chunk.
