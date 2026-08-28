# Remote Attached update: stop/restart handoff

> **AI contribution notice:** This draft was written with contributions from an AI coding agent at the explicit request of the project maintainer. It is a design document for human review and iteration, not an approved implementation specification.

## Status

Draft.

## Purpose

Allow a consumer machine to request an Attached binary update on a remote publisher and restart `attached serve` with the new binary without risking permanent loss of Iroh connectivity.

This proposal deliberately chooses a simpler stop/restart handoff instead of running two simultaneous Iroh endpoints. Existing Iroh connections will be interrupted during the handoff, but the interruption should be bounded and the old process should restore service automatically if the candidate process cannot become reachable.

## Terminology

- **Consumer:** the machine requesting the remote update and connecting to published sessions.
- **Publisher:** the remote machine running `attached serve`.
- **Old server:** the currently serving Attached process and binary version.
- **Candidate:** the staged new Attached binary and the child process started from it.
- **Endpoint:** the publisher's Iroh endpoint, identified by its persistent Iroh identity.
- **Watchdog:** the still-running old process while the candidate attempts to take over.
- **Operation ID:** a random identifier binding preparation, cutover, health confirmation, commit, and rollback to one update attempt.

## Goals

- Remotely request an update through an authenticated, fixed operation.
- Install an exact Attached release rather than execute a caller-provided command.
- Never intentionally run two Iroh endpoints with the publisher's identity at the same time.
- Keep the old endpoint available while downloading and validating the candidate.
- Keep the old process alive, but without an Iroh endpoint, during candidate activation.
- Restore the old endpoint if the candidate exits, hangs, cannot bind, or cannot be reached by the consumer.
- Declare success only after the consumer has authenticated to the candidate and observed the requested version.
- Preserve the publisher identity, synchronized record, capability, and serve configuration across the handoff.
- Retain the old binary on disk until the new version has committed successfully.

## Non-goals

- Preserving an existing QUIC connection across process replacement.
- A zero-packet-loss or zero-downtime upgrade.
- Running arbitrary shell commands supplied by the consumer.
- Recovering solely through the old process after that process is killed or the machine loses power.
- Updating publishers whose installed Attached version does not already implement this maintenance protocol.
- Defining irreversible state migrations. Any migration needed by a candidate must remain compatible with rollback or be deferred until commit.

## Why not overlap two endpoints with the same identity?

The current server loads one persistent Iroh identity. The endpoint registry also rejects a second locally active endpoint with that identity. If this guard were bypassed, Iroh Relay would make the newest relay connection active and deactivate the previous connection for the same endpoint ID. Direct and relayed paths could then disagree about which process receives traffic.

The two processes would also generate different process-local capabilities under the current implementation. A consumer holding the old synchronized descriptor could therefore reach the new process while presenting the old capability and be rejected.

The handoff must instead fully close the old endpoint before allowing the candidate to bind the same identity.

## Safety invariants

The implementation should preserve these invariants at every transition:

1. At most one process may own a bound Iroh endpoint for the persistent publisher identity.
2. The old endpoint remains available during download, verification, and candidate preflight.
3. The old process remains alive until the candidate passes an end-to-end consumer health check.
4. The candidate must not bind Iroh while the old endpoint is active.
5. Rollback must not rebind the old endpoint until the candidate has exited and released its endpoint.
6. The stable installed-binary pointer must not move to the candidate before end-to-end confirmation.
7. The old binary must remain available on disk until commit is durable.
8. The handoff reuses the previous capability so consumers with a cached descriptor can authenticate after the restart.
9. Only one update operation may be active for a publisher.
10. Every wait involving a child process, protocol frame, endpoint transition, or consumer confirmation must have a bounded deadline.

## Proposed architecture

### Restartable server supervisor

The current publisher process becomes a small supervisor around a restartable endpoint lifecycle. Configuration, identity, capability, update state, and rollback information live outside the endpoint-serving future.

Conceptually, the old process transitions through:

```text
ServingOld
    -> StagingCandidate
    -> CandidatePrepared
    -> CuttingOver
    -> WaitingForCandidate
    -> Committing
    -> Retired

WaitingForCandidate
    -> RollingBack
    -> ServingOld
```

Closing an endpoint must no longer imply that the entire old process returns from `main`. The supervisor must be able to construct a fresh endpoint and resume the old serving loop.

### Candidate standby mode

The candidate starts in an internal handoff mode rather than immediately running the public `serve` command. In standby it may:

- verify its own exact version;
- parse and validate the supplied serve configuration;
- read required account and identity state without mutating it;
- verify that the configured Herdr executable is available;
- create its local readiness/control channel;
- report `Prepared` to the parent.

It must not bind an Iroh endpoint, publish a catalog snapshot, or perform incompatible state migrations before receiving an `Activate` message from the old process.

This mode should be internal and not presented as a general user-facing remote execution interface.

### Parent/child control channel

Use anonymous pipes, inherited file descriptors, or an equivalently private local IPC channel. Do not place capabilities or handoff tokens in command-line arguments or broadly inherited environment variables.

A minimal local protocol needs messages similar to:

```text
Parent -> candidate: Prepare(config, operation_id, capability)
Candidate -> parent: Prepared(candidate_version)
Parent -> candidate: Activate
Candidate -> parent: EndpointReady(endpoint_address)
Candidate -> parent: ConsumerConfirmed(operation_id)
Parent -> candidate: CommitComplete
Parent -> candidate: Abort
Candidate -> parent: Failed(stage, bounded_reason)
```

The parent retains the child process handle and is responsible for deadlines, termination, and reaping.

### Serve configuration

Capture a typed `ServeConfig` when the old server starts. It should contain resolved values rather than replaying raw process arguments:

- absolute private state directory;
- resolved absolute Herdr executable path;
- stable host label;
- supported logging/verbosity settings;
- an explicit whitelist of any environment-derived behavior that must survive restart.

Relative paths, the original working directory, and the caller's current `PATH` should not silently determine whether the candidate can start.

The persistent Iroh key can continue to come from secure state. The process-local capability must be transferred through private IPC or otherwise deliberately preserved across the handoff.

## Binary staging and installation

The updater should separate staging from commit.

A possible layout is:

```text
<managed-root>/versions/0.2.0/attached
<managed-root>/versions/0.3.0/attached
<install-dir>/attached -> <managed-root>/versions/0.2.0/attached
```

The exact layout remains an implementation decision, but it must support:

1. downloading without modifying the currently selected executable;
2. verifying release metadata, checksum or signature, and exact version;
3. executing the candidate directly from its staged absolute path;
4. atomically selecting the candidate after health confirmation;
5. retaining the previous version for rollback and crash recovery;
6. syncing the relevant file and directory changes before reporting commit.

The consumer should request an exact target version. A request for “latest” can race with a release published during the operation and makes end-to-end verification ambiguous.

The remote protocol must not accept an installer URL, artifact URL, shell fragment, install directory, or arbitrary installer arguments from the consumer.

## End-to-end handoff

### Phase 1: authenticate and admit the operation

1. The consumer connects using a dedicated, versioned maintenance ALPN.
2. The publisher verifies the authorized consumer Iroh identity and an update-specific capability or policy.
3. The publisher rejects concurrent operations, unsupported targets, downgrades, and requests for the already-installed version as appropriate.
4. The publisher allocates an operation ID and records the initial state.

No endpoint interruption occurs in this phase.

### Phase 2: stage and preflight

1. The old server downloads the exact candidate to a new versioned path.
2. It verifies release authenticity and the candidate's reported version.
3. It spawns the candidate in standby mode.
4. The candidate validates configuration and reports `Prepared` over private IPC.
5. The old server sends the consumer a `ReconnectExpected` response containing the operation ID and bounded handoff deadline.

Any failure before `Prepared` leaves the old endpoint and installed-binary pointer unchanged.

### Phase 3: close the old endpoint

1. Stop the old periodic publisher so it cannot race candidate publication.
2. Stop accepting new connections and notify or cancel existing connection tasks.
3. Close the old Iroh endpoint and await shutdown.
4. Release the endpoint registry guard.
5. Preserve the old process, identity, capability, configuration, publisher state, and rollback journal in the watchdog.
6. Send `Activate` to the candidate.

The consumer now expects temporary unavailability and begins bounded reconnect attempts with backoff.

### Phase 4: activate the candidate

1. The candidate acquires the endpoint registry guard.
2. It binds an endpoint using the same persistent Iroh identity and supported ALPNs.
3. It reuses the old capability.
4. It ensures the required Herdr session state is available.
5. It publishes an initial snapshot with its current endpoint address.
6. It reports local `EndpointReady` to the watchdog.
7. It accepts maintenance and normal tunnel connections.

Local readiness is necessary but insufficient. In particular, Iroh endpoint `online` status must not be treated as proof that the initiating consumer can reach and authenticate to the candidate.

### Phase 5: consumer verification

The consumer retries the same endpoint identity using the known relay information and, when useful, refreshes the synchronized descriptor for updated direct addresses.

After connecting, it requests update status using the operation ID. Success requires all of the following:

- the candidate authenticates the consumer;
- the candidate recognizes the operation ID;
- the candidate reports the exact requested Attached version;
- a normal maintenance request/response round trip succeeds.

The consumer then sends `ConfirmCandidate`. The candidate forwards this fact to the watchdog through private IPC.

The ordinary unavailable-host pruning path must not run during this expected reconnect window. A temporary handoff failure must not delete the synchronized record from the consumer catalog.

### Phase 6: commit

After receiving consumer confirmation, the watchdog:

1. atomically selects the candidate as the installed Attached binary;
2. persists the committed update state;
3. tells the candidate that commit completed;
4. receives or otherwise ensures the final consumer-visible success response;
5. retires without closing the candidate endpoint.

The process-launch model must explicitly define how the candidate remains managed after the original process exits. A systemd or launchd unit may kill remaining child processes when its original main process exits unless the unit and handoff are designed for this behavior.

### Phase 7: rollback

Rollback begins if, before commit:

- the candidate exits;
- candidate preparation or activation times out;
- endpoint binding fails;
- initial publication fails under the selected readiness policy;
- no consumer can confirm end-to-end reachability before the deadline;
- the staged binary cannot be selected atomically;
- either side reports an explicit handoff failure.

The watchdog then:

1. sends `Abort` when the candidate control channel remains available;
2. terminates the candidate process group if necessary;
3. waits for and reaps the candidate;
4. ensures the candidate endpoint and endpoint registry guard are released;
5. leaves or restores the stable installed-binary pointer to the old version;
6. binds a fresh endpoint with the old identity;
7. resumes serving with the old capability and configuration;
8. republishes the old server's new endpoint address;
9. records `RolledBack` for the operation ID so the consumer can distinguish rollback from an unknown outage.

There may be relay propagation delay after either activation or rollback. Consumer retries must account for this without allowing an unbounded outage.

## Maintenance protocol sketch

Use a dedicated ALPN, for example:

```text
attached-maintenance/1
```

It should remain independent of the interactive tunnel ALPN so that maintenance and compatibility behavior stay explicit.

Potential fixed operations and responses are:

```text
PrepareUpdate {
    operation_id,
    target_version,
}

UpdateStatus {
    operation_id,
}

ConfirmCandidate {
    operation_id,
    observed_version,
}

Status =
    Current { version }
  | Preparing { target_version }
  | ReconnectExpected { target_version, deadline }
  | CandidateRunning { version }
  | Committed { version }
  | RolledBack { retained_version, bounded_reason }
  | Failed { bounded_reason }
  | Busy
```

The final framing, version representation, deadlines, and replay behavior belong in the protocol design. Responses must be bounded and must not expose filesystem paths, installer output, credentials, URLs containing secrets, or internal error chains.

An operation should be idempotent: reconnecting and asking for the same operation ID must return its current or terminal state rather than starting another update.

## Failure analysis

| Failure | Expected behavior |
| --- | --- |
| Download, verification, or preflight fails | Old endpoint remains active; no cutover occurs. |
| Candidate cannot be spawned | Old endpoint remains active; staged files may be cleaned later. |
| Old endpoint cannot shut down cleanly | Do not activate the candidate; abort or rebuild the old endpoint under a bounded policy. |
| Candidate cannot acquire the endpoint guard | Candidate exits; watchdog rolls back. |
| Candidate cannot bind Iroh | Candidate reports failure or exits; watchdog rolls back. |
| Candidate reports local readiness but is externally unreachable | Consumer never confirms; watchdog rolls back at the deadline. |
| Candidate crashes before commit | Watchdog observes child exit and rolls back. |
| Consumer exits during handoff | Safe default is rollback after the confirmation deadline. |
| Relay transition is delayed | Consumer retries with bounded backoff; rollback occurs only at the handoff deadline. |
| Candidate modifies state the old binary cannot read | Rollback may be impossible; pre-commit mutations must therefore be backward-compatible or forbidden. |
| Watchdog crashes or host loses power during cutover | In-process rollback is unavailable; recovery requires durable installation state and an external process manager. |
| Candidate crashes after the watchdog exits | Recovery requires an external process manager or a persistent supervisor. |
| Atomic installed-binary selection fails | Candidate is not committed; stop it and roll back while the old binary remains selected. |

## Durable update state

A PID file is not a correctness mechanism because PIDs can become stale or be reused. The parent already has the authoritative child process handle during a live handoff.

A private, atomically replaced update journal may still be useful for crash diagnosis and startup recovery. It can contain non-secret fields such as:

- operation ID;
- old and target versions;
- old and candidate managed paths;
- current phase;
- whether the installed-binary pointer committed;
- timestamps and bounded public failure category.

The journal and update lock must use owner-only state handling. Secrets and raw installer diagnostics must not be written to it.

On startup, Attached should be able to identify and clean an abandoned staged version without mistaking it for a committed release. The stable installed-binary pointer remains the source of truth unless a future persistent supervisor defines a stronger model.

## External process supervision

The old-process watchdog protects failures while the old process remains alive. It cannot protect against:

- host reboot or power loss;
- the watchdog being killed or crashing;
- an out-of-memory kill affecting both processes;
- the candidate failing after the watchdog retires.

A production deployment should therefore use systemd, launchd, or a dedicated minimal supervisor with an explicit restart policy. Integration needs to be designed rather than assumed: some service managers consider the service stopped when the original main PID exits and may terminate the candidate's process group.

The first implementation may document a narrower supported launch model, but it must not claim crash-safe remote access until that model has been tested.

## Security requirements

- Require the authorized consumer Iroh identity before dispatching maintenance operations.
- Consider a separate update authorization capability or an explicit publisher opt-in policy.
- Never expose a generic remote command primitive.
- Pin and verify an exact release version.
- Reject unauthorized downgrade requests by default.
- Serialize update operations with an exclusive lock.
- Bound downloads, child execution, output capture, frame sizes, and all deadlines.
- Keep capabilities and handoff tokens out of process listings and ordinary logs.
- Sanitize wire errors while retaining useful private diagnostics.
- Preserve owner-only permissions for binaries, journals, locks, and state.
- Ensure a failed or malformed request cannot stop the active endpoint.

## Observability

Useful structured events include:

- update requested and admitted;
- candidate download and verification completed;
- candidate prepared;
- endpoint cutover started;
- candidate locally ready;
- consumer confirmation received;
- update committed;
- rollback started and completed;
- recovery deadline exceeded.

Logs should include the operation ID and non-secret version information, but not capabilities, account material, private paths, installer output, or consumer secrets.

## Implementation outline

A possible incremental implementation order is:

1. Extract endpoint construction and serving into a restartable lifecycle controlled by a supervisor state machine.
2. Preserve one capability and typed `ServeConfig` outside that endpoint lifecycle.
3. Add the bounded maintenance protocol and authentication without enabling self-update.
4. Add versioned artifact staging and exact-version verification.
5. Add candidate standby mode and private parent/child IPC.
6. Add endpoint cutover and local rollback on candidate bind/exit failure.
7. Add consumer reconnect behavior and prevent expected handoffs from pruning the catalog.
8. Add end-to-end candidate confirmation and atomic commit.
9. Add the durable update journal and startup cleanup.
10. Define and test supported systemd/launchd or supervisor behavior.

Each stage should preserve the existing normal `serve` and `attach` behavior before the next stage begins.

## Test plan

### State-machine tests

Inject failure at every transition and verify:

- no cutover occurs before candidate preparation;
- no two same-identity endpoints are active simultaneously;
- every pre-commit failure returns to `ServingOld`;
- commit is terminal and cannot be rolled back accidentally;
- duplicate operation IDs are idempotent;
- concurrent operation IDs receive `Busy`.

### Process integration tests

Use synthetic old and candidate executables to cover:

- candidate spawn failure;
- malformed readiness messages;
- candidate preflight failure;
- candidate hang and timeout;
- candidate exit before and after endpoint readiness;
- process-group termination and complete reaping;
- capability transfer without command-line or log exposure;
- atomic installed-binary selection failure.

### Iroh integration tests

With live local endpoints, verify:

- the old endpoint remains reachable during staging;
- the candidate does not bind before activation;
- the old endpoint is fully closed before candidate binding;
- a consumer can reconnect to the same endpoint identity after activation;
- the old capability authenticates to the candidate;
- consumer confirmation reaches the watchdog;
- candidate failure causes the old process to rebind and become reachable again;
- relay/direct address changes are republished;
- expected handoff unavailability does not prune the synchronized record.

### Crash-recovery tests

Where a supported process manager exists, kill processes or reboot the test environment at each durable phase and verify that either the committed candidate or the retained old version returns to service.

## Acceptance criteria

Before enabling remote updates by default, all of the following should hold:

- A failed download or preflight causes no connectivity interruption.
- Candidate spawn, bind, readiness, and external reachability failures restore the old endpoint within a documented bound.
- The implementation never deliberately overlaps two endpoints using the persistent publisher identity.
- The consumer never reports success before authenticating to the requested candidate version.
- A cached synchronized descriptor remains usable through a successful handoff.
- Expected handoff downtime never triggers unavailable-host catalog pruning.
- The previous executable remains recoverable until commit is durable.
- Unauthorized and malformed requests cannot stage a binary or interrupt serving.
- Update and rollback behavior is covered by deterministic failure-injection tests.
- The supported process-manager behavior is documented and tested.

## Open questions

1. What maximum interruption and rollback deadline are acceptable?
2. Should the candidate require successful initial catalog publication before local readiness?
3. Should missing consumer confirmation always roll back, even when the candidate appears healthy locally?
4. How should active interactive sessions communicate that a publisher restart is expected?
5. Should consumers automatically reconnect their local Herdr client, or only the maintenance operation?
6. Which release verification mechanism and exact-version download API should be authoritative?
7. Is remote update enabled by default for every authorized consumer, or explicitly enabled per publisher?
8. Which launch environments are supported initially: foreground shell, systemd, launchd, containers, or a dedicated supervisor?
9. How is the candidate detached or adopted safely after the watchdog exits in each supported environment?
10. Which state changes, if any, may the candidate perform before commit?
11. How long should old versions and abandoned staged versions remain on disk?
12. Does the maintenance protocol need a separate capability from ordinary session attachment?
13. What compatibility promise should `attached-maintenance/1` provide across Attached releases?
