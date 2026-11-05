# Manual relay capacity experiment

This internal tool creates real headless `host.Host` sessions, authenticated SSH
or WebSocket guests, PTY shell channels and optional SFTP traffic. It is opt-in;
no test or normal invocation contacts Fly. It changes no production client or
server behavior and supplies no infrastructure credentials.

Build and invoke explicitly:

```sh
go build -o /tmp/upterm-capacity ./internal/capacity/cmd
/tmp/upterm-capacity -manifest /secure/run/manifest.json -phase /secure/run/phase.json -validate
/tmp/upterm-capacity -manifest /secure/run/manifest.json -phase /secure/run/phase.json > /secure/run/events.jsonl
```

Both files are required. JSON decoding rejects unknown fields. Validation is
pure: it checks syntax, limits and authorization without DNS queries or dials.
A load run also resolves every destination immediately before connecting and
rejects the entire DNS answer if any address is outside the target's IP list.
It then dials a literal approved IP, preventing DNS check/dial races. Invalid
configuration and preexisting watchdog stops refuse admission. Workload,
readiness, telemetry, budget or watchdog failures produce a nonzero exit.

All examples below use placeholders, not operational destinations or keys.
Replace `EXPIRES_UTC` with a UTC RFC3339 timestamp within the next 24 hours.

Manifest:

```json
{
  "run_id": "RUN_ID",
  "expires_at": "EXPIRES_UTC",
  "local_only": false,
  "targets": [{
    "app_id": "ISOLATED_APP_ID",
    "machine_id": "RELAY_MACHINE_ID",
    "ssh_url": "ssh://RELAY_MACHINE_ID.vm.ISOLATED_APP_ID.internal:2222",
    "ws_url": "ws://RELAY_MACHINE_ID.vm.ISOLATED_APP_ID.internal:8080",
    "public_ssh_url": "ssh://ISOLATED_APP_ID.fly.dev:22",
    "public_ws_url": "wss://ISOLATED_APP_ID.fly.dev:443",
    "node_addresses": ["RELAY_MACHINE_ID.vm.ISOLATED_APP_ID.internal:2222"],
    "allowed_ips": ["RELAY_6PN_IP", "AUTHORIZED_PUBLIC_IPV4", "AUTHORIZED_PUBLIC_IPV6"],
    "host_keys": ["ssh-ed25519 BASE64_RUN_RELAY_PUBLIC_KEY"],
    "telemetry_url": "http://RELAY_MACHINE_ID.vm.ISOLATED_APP_ID.internal:9091/metrics"
  }]
}
```

There may be one or two target records, with exact machine IDs. `host_target`
and `entry_target` reference these IDs. For crossed-node experiments, list both
nodes and choose different IDs. A guest session node must match a manifest node
exactly, resolve within that node target's IP set, and agree with the node
encoded in an embedded-mode SSH username. Consul-mode usernames must equal the
session ID. This check runs at initial creation, before every guest connection,
and after host restoration. Hosts always redial their original guarded URL.

`host_keys` pins raw relay keys or certificate signing keys. Host certificates
must have the expected hostname principal, valid signature/time and a pinned
signing key. Include the exact private machine hostname and authorized public
hostname in the relay certificate for a run using both. Known production relay
names/apps and the published production relay key are refused. The manifest
is an authorization record supplied by the operator; it cannot independently
prove which Fly resource owns an arbitrary IP.

Phase:

```json
{
  "hosts": 10,
  "guests_per_host": 2,
  "host_target": "RELAY_MACHINE_ID",
  "entry_target": "RELAY_MACHINE_ID",
  "host_public": false,
  "entry_public": false,
  "host_ws_percent": 50,
  "guest_ws_percent": 50,
  "channels_per_guest": 1,
  "duration_seconds": 300,
  "admissions_per_second": 10,
  "payload_budget_bytes": 5368709120,
  "active": true,
  "transfer_concurrency": 0,
  "churn_percent": 0,
  "host_identity_file": "/secure/run/host-identity",
  "watchdog_file": "/secure/run/STOP",
  "watchdog_heartbeat_file": "/secure/run/PERMIT"
}
```

`host_public`/`entry_public` select the optional public URLs; otherwise the
private URLs are used. Both public URLs must be present when selected. Transport
percentages assign exactly `floor(role_count * percentage / 100)` clients of
each role to WS/WSS, the rest to SSH. Hosts select WS/WSS from the beginning of
host order; guests select from the end of guest order (grouped by host), without
changing IDs or host association. Thus a 50/50 workload with an even host count
includes SSH hosts with WS guests and WS hosts with SSH guests. All-SSH and
all-WS phases cover same-transport pairs. JSONL records each role, actual node
and transport.
Idle phases with zero guests per host reserve one extra external connection for
a transient one-channel guest canary at readiness and every 30 seconds. Canary
hosts are sampled round-robin; canary counts, maximum ready latency and RTT
samples are separate from the nominal zero steady guests. Each canary closes
before the next, within this same runner. Channels per steady guest must
be one or four. Only the first channel generates steady input; all channels
drain fan-out and each proves readiness independently. The optional identity
file authenticates host registration only; the runner generates distinct
session host keys and isolated temporary directories. Its private contents and
path are never logged. Without it, each host gets an ephemeral identity.

Bounds apply before any host starts: at most two relay targets, 1,000 external
connections including one telemetry connection per target and the idle host-only canary
slot, 20 new external
connections/second, 24 hours of authorization and 50 GiB of application payload.
Up to twenty admission workers overlap readiness; every external connection
and retry passes the same global limiter, including `Host`'s own reconnect
attempts. Initial hosts reserve a dial slot before `Host.Run`; guests reserve
before their ten-second service attempt, including WS CONNECT/upgrade. Queue
waiting is generator pacing, excluded from `ready_ms`, and reported separately
as `queue_ms` on admission/readiness events. A slow chosen ramp cannot consume
a client's service deadline. A permit remains exclusive until the actual dial
starts, so delayed reservations and cancelled waiters cannot bunch dials.
Admission workers are joined before steady observation or cleanup.
The process rejects nonempty uppercase or lowercase `HTTP_PROXY`, `HTTPS_PROXY`
and `ALL_PROXY`. Its private loopback CONNECT doors enforce destination/IP
allowlists and own the host sockets used for cuts. `local_only: true` is a
separate mode requiring literal loopback endpoints and only loopback allowed
IPs; it does not authorize arbitrary external destinations.

The steady duration starts after all requested hosts, guests and channels are
ready. Setup has a separate `(H + G) / rate + 30 seconds` deadline; manifest
expiry and parent cancellation bound both. Summary `setup_seconds`,
`steady_seconds` and total `duration_seconds` preserve the distinction. A
five-minute hold therefore remains five minutes after admission. Host keepalive
uses the released client's 50-second interval and normal reconnect backoff.
Released host redial budgets include CONNECT waiting: their normal 30-second
service budget gets an explicit allowance of at most five seconds for generator
pacing. The CONNECT door enforces the original 30-second service bound after
dispatch. The released WS dial/upgrade path remains in use. A retry queue that
cannot dispatch within five seconds stops as `generator_admission_backlog`;
this is invalid generator-limited evidence, never a relay capacity ceiling.

## Offered data and measurement

The hosted command is this binary's own `helper` subcommand. It sets its PTY to
raw mode, answers a distinct 128-byte readiness challenge, echoes deterministic
data and never interprets
input as commands. Active guests send exactly 128 bytes once per second,
beginning at steady observation start. Active helpers emit a 1 KiB frame every
ten seconds from helper startup. Idle helpers emit only their startup marker
and readiness challenge/probe responses. A request tagged `R` receives a
helper-generated `A` response, so a PTY kernel echo cannot prove readiness.
This also works after the original startup marker leaves terminal history.
The authenticated `R` challenge may repeat every 100 ms within the same
original ten-second service attempt until a matching live `A` is seen.
`readiness_challenge_retry` events and summary `readiness_challenge_retries`
expose every additional attempt; all requests reserve payload before writing.
Ready/recovery latency includes this work. These retries establish the live
boundary and never retry or waive a steady `I`/`H` delivery failure. Challenges,
barriers and own input replies match their original timestamps, so replayed
responses cannot acknowledge or remeasure a request. The helper resynchronizes
its bounded line frames if a cut truncates a preceding input.
All receivers drain output, track sequence gaps
and reordering, and fail if a requested response remains outstanding for more
than ten seconds. Initial terminal replay is excluded by a fresh helper `Q`/`B` barrier before
its live probe. The barrier reports the helper's emitted host-output sequence
count and establishes each channel's live measurement boundary. Every new
transport clears old barriers so replay cannot activate its live reader. Planned reconnects
reset tracking only for the affected source generation; survivor generations
retain gap/reordering checks.

Steady input has an independent schedule per guest. Expected restoration
pauses only that guest; it does not hold up healthy survivors. A missed
one-second interval fails as `generator_cadence_late`; it is never caught up by
sending active input after the offered interval. At steady end,
new input stops and a separate drain of at most ten seconds retains transports,
telemetry, watchdog and manifest bounds. It first requires every outstanding
own reply, then sends `F`/`B` barriers on every channel. `F` quiesces helper
output; `B` reports its final emitted output count. Every receiver must have
the final active input sequence from every live source and the final host
output sequence. Missing suffixes fail even when no later frame exposes a gap.
Late completed replies retain their original RTT timestamps and enter the RTT
reservoir. After successful completion and cleanup, `input_frames` equals
`rtt_count + canary_rtt_count + interrupted_replies`: each complete input write
is either acknowledged once or explicitly interrupted by a planned cut.
Readiness `I` probes and accepted inputs during churn are included. `R`, `Q`,
and `F` requests count in `handshake_frames`; their `A`/`B` replies do not create
input RTT samples. Idle host-only canaries contribute one `input_frames` and
one `canary_rtt_count` per successful canary, with zero normal `rtt_count`. A successful summary requires `delivery_complete: true`, keeps
`stop_reason: "duration"`, and adds `drain_seconds`; `steady_seconds` continues
to report only the configured offered interval. Inputs interrupted by an
intentional cut are counted explicitly in `interrupted_replies`; the restored
generation must prove delivery again.

Each 128-byte input/echo and 1,024-byte host frame contains a 44-byte ASCII
header (`CAP`, role, eight-digit source and sequence, nineteen-digit Unix
nanoseconds), padding, and one final LF. The 45 framing bytes are included in
those fixed sizes. Readiness challenge and response frames are also 128 bytes; `handshake_frames`
records readiness and barrier requests separately from `input_frames`. The helper startup
marker is ten bytes. SSH, TLS,
WebSocket, TCP, terminal reconstruction and relay forwarding overhead are not
measured as application framing. RTT uses the originating guest's echoed tag;
summary quantiles use a uniform reservoir of at most 100,000 samples and also
report the complete sample count. Every receiver observes all host fan-out. `peak_external_connections` includes
transient canaries, telemetry and admitted in-flight dials; it conservatively
counts a dial until it fails or its connection closes.

The payload budget uses conservative pre-generation reservations: host output
through the maximum bounded lifetime is reserved before hosts start; each
input reserves its echo to all configured fan-out channels before writing;
each transfer reserves upload and download before creating its file.
`reserved_payload_bytes` is the safety bound; `payload_bytes` records observed
input, live received frames and actual SFTP bytes. Unused fan-out/output
reservations are intentionally retained. Preflight rejects a budget too small
for the intended duration/workload. Reconnect probes reserve extra bytes at
runtime. These byte figures are per phase; the operator must also enforce the
approved aggregate budget across attempts.

`transfer_concurrency` can be zero, four or eight. Each transfer concurrently
uploads one deterministic 16 MiB file into its host's temporary directory,
then downloads it and verifies both length and SHA-256. Source/download data
are streamed with bounded memory; at most eight temporary 16 MiB files exist.
Files and host directories are removed during teardown; `cleanup_complete`
requires the owned directory to be absent before return. JSONL contains actual
upload/download bytes, digest and verification outcome. Transfers incomplete
at phase expiry are a failure.

`churn_percent` can be zero, ten or fifty. It requires at least two hosts, two
guests per host and 25 steady seconds. Counts are floored; use enough hosts for
the requested percentage to select a host. Selected host and guest transports
are cut over a ten-second schedule starting one second into steady load.
Selected guests are cut before selected hosts so an overlapping selection
always severs a real guest transport. Actual cutting takes no repair lock;
repairs may serialize independently. `transport_cut` records `planned_at`,
`actual_at`, `schedule_delay_ms`, `actual_transports`, and for host cuts
`already_disrupted_guests`. Already-disrupted guest transports cause failure,
not an extra claimed cut. Summary `actual_host_cuts` and `actual_guest_cuts`
must equal the requested floored counts.
Host restoration uses the original `Host.Run`, host key and session ID;
guests reuse their identities and transport kinds. Reconnect events and
latency are separate from first admissions. Restoration `restoration_ms` is
actual cut-to-usable wall time, including generator pacing and repair waits;
the approved recovery objective continues to use this total. Additive
`queue_ms` separates admission pacing and `service_ms` reports the remaining
elapsed recovery path, including normal retry/backoff and repair waiting.
An overlapping later host cut supersedes guest repair without resetting that
guest's original outage start. A survivor on an unaffected host
keeps its transport and must continue responding. Intentional input pauses are
reported as `paused_active_frames`. Idle churn explicitly probes its survivor.
Churn incomplete at phase expiry is a failure. Combining transfers and churn
may fail a transfer cut in progress; run distinct phases to measure each.

## Telemetry and external stop control

Private relay Prometheus text is collected initially and every five seconds.
Redirects, non-200 responses and responses over 1 MiB fail collection. A
separate one-second watchdog stops the phase once any target has had more than
30 seconds without successful telemetry. JSONL also records generator PID,
Go version, goroutines, heap/runtime memory and, on Linux, `/proc/self/status`
and `/proc/self/stat` for RSS/CPU analysis. Sampling does not diagnose pressure;
the coordinator evaluates Fly metrics/OOM and generator pressure externally.

Before startup and once per second, an existing `watchdog_file` requests a
graceful safety stop. If `watchdog_heartbeat_file` is configured, it must exist
at startup and have an mtime no older than 30 seconds; stale, missing or
future-dated heartbeats stop the run. A coordinator can `touch` the heartbeat
at least every five seconds while continued authorization holds, or create
`STOP` when an OOM, pressure, cost or other limit is reached. SIGINT/SIGTERM
also cancel gracefully. All transports are closed, owned goroutines and host
processes are joined, and temporary directories are removed before the final
summary. The generator requires no Fly API credential.

Library callers use `Run(ctx, Config, io.Writer) (Summary, error)`. Supply the
parsed manifest in `Config.Manifest`. `HelperExecutable` defaults to the running
executable; an embedding program must either dispatch the `helper` subcommand
or supply the path of a built capacity binary. Tests build a dedicated helper
and only use embedded loopback relays.

## Focused checks

```sh
go test -race -count=1 ./internal/capacity/...
go vet ./internal/capacity/...
GOOS=windows go vet ./internal/capacity/...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/upterm-capacity-linux ./internal/capacity/cmd
```

The real integration suite covers SSH, WS and both crossed transport mixes,
four shell channels, deterministic concurrent SFTP, actual host/guest cuts,
cancellation, cleanup, confinement and safety accounting. It runs no external
load and requires no local Consul. The Windows check establishes compilation
and vet compatibility; the manual benchmark targets Linux.
