# Remote session management and live notifications

> **Status:** Working discussion notes, not a finalized design.
>
> **AI contribution notice:** This document was written with assistance from an AI coding agent based on a discussion with the project maintainer.

## Context

Attached currently discovers remote Herdr sessions through its synchronization service and connects to them over Iroh. Two related developments motivate reconsidering the project boundary:

- Herdr supports attaching to a known remote host over SSH.
- Tailcat provides a control-plane-free encrypted data plane with connection metadata exchanged out of band, similarly to how Attached distributes Iroh endpoint metadata.

If Attached is defined mainly as an Iroh tunnel, these alternatives overlap with much of its apparent value. A stronger boundary may be for Attached to manage a user's remote Herdr sessions while treating Iroh, Herdr-over-SSH, and Tailcat as alternative ways to reach them.

The resulting product promise would be:

> Discover, monitor, receive notifications from, and attach to all Herdr sessions from one place, using whichever connection method is available.

Iroh should remain the default zero-configuration route. Supporting other routes should not weaken the existing “no networking setup required” experience.

## Proposed project boundary

Attached would act as a Herdr-specific management or control plane. It would own:

- host enrollment and identity;
- a unified session catalog;
- host and session presence, health, and metadata;
- semantic Herdr event and notification delivery;
- route selection and explicit fallback policy;
- desktop, terminal, and browser integrations; and
- optional lifecycle operations supported by a route, such as a remote Herdr update.

Iroh, SSH, and Tailcat should be described as **connection routes** or **connection backends**, rather than as identical network transports. They operate at different levels:

- Attached's Iroh implementation owns endpoint creation, authentication, application framing, and stream proxying.
- Herdr-over-SSH includes OpenSSH authentication, remote binary discovery or installation, version handling, and launching the Herdr thin client.
- Tailcat provides an encrypted userspace network path and NAT traversal, but Attached would still need to provide the Herdr-facing protocol and authorization above it.

A route abstraction should therefore be defined around Herdr operations, not merely around obtaining an `AsyncRead + AsyncWrite` byte stream.

## Goals

- Present local and remote Herdr sessions in one catalog.
- Allow one remote host or session to have multiple possible connection routes.
- Keep display labels separate from durable host identity.
- Attach through Iroh, Herdr-over-SSH, or Tailcat without duplicating session entries.
- Receive remote notifications while no interactive Herdr client is attached, provided the receiving Attached process is online.
- Preserve route-specific authentication and trust semantics.
- Allow routes to advertise different capabilities instead of requiring every route to implement every operation.

## Non-goals

- Durable delivery while the receiving device is offline.
- A cloud notification mailbox, mobile push queue, or replay across receiver restarts.
- Producing notifications after the remote Herdr server or session has stopped.
- Becoming a generic VPN, SSH host manager, or arbitrary remote-command runner.
- A dynamically loadable third-party transport ABI in the first implementation.
- Silently falling back to a route with weaker authentication.

## Current Iroh coupling

The current implementation is not separated at a single transport boundary:

- `crates/session-sync-protocol/src/canonical.rs` stores an Iroh endpoint ticket and attach capability directly in each session access descriptor.
- `crates/session-sync-protocol/src/account.rs` includes a consumer identity used as the Iroh endpoint identity.
- `crates/cli/src/server.rs` creates and serves the Iroh endpoint.
- `crates/cli/src/sync/attach.rs` parses the Iroh endpoint ticket and selects the current tunnel implementation.
- `crates/cli/src/tunnel.rs` implements Iroh connection setup, authentication, upgrade requests, and TUI stream forwarding.
- Synchronized record identity is derived partly from the Iroh endpoint identity.

Consequently, adding another backend is more than placing a trait around `tunnel::connect`. A transport-independent host identity and a versioned route representation will eventually be needed.

## Domain model

A possible transport-independent model is:

```text
RemoteHost
  id: HostId
  label: DisplayLabel
  sessions: [RemoteSession]
  routes: [ConnectionRoute]
  capabilities: [Capability]

RemoteSession
  host_id: HostId
  name: SessionName
  metadata: SessionMetadata

ConnectionRoute
  Iroh(...)
  Ssh(...)
  Tailcat(...)

Capability
  Attach
  Events
  RemoteUpdate
```

Important properties of this model are:

1. `HostId` is stable and independent of an Iroh endpoint, SSH alias, or Tailcat key.
2. A label such as `office` is presentation data and is not the durable identity.
3. A session can be deduplicated even when multiple routes reach it.
4. A route advertises what it can do. An SSH route might support attach and events but not Attached's remote-update protocol, for example.
5. Host-advertised routes and receiver-local route bindings are distinct. Iroh and Tailcat connection metadata can be published by the host, while an SSH alias, username, agent, and `known_hosts` policy are commonly local to a receiving machine.

A synchronized descriptor version could eventually contain a tagged list of host-advertised routes. Existing Iroh-only descriptors should remain readable during migration.

## Suggested internal boundaries

Instead of one universal network trait, use small operation-level boundaries:

- **Session source:** discovers hosts and sessions and refreshes metadata.
- **Attach route:** performs an interactive attachment.
- **Event source:** provides a stream of bounded semantic events.
- **Remote administration:** optionally performs operations such as a version update.

The first implementation can use a closed tagged enum with exhaustive handling. A plugin ABI would add compatibility and secret-handling concerns before a second backend has established the real abstraction boundary.

The SSH attach route should delegate to Herdr's existing remote behavior where practical, for example:

```sh
herdr --remote HOST --session SESSION
```

Attached should not independently recreate Herdr's SSH bootstrap, binary installation, keybinding transfer, and version-management behavior.

## Live notification scope

The planned notification mode is **receiver online only**.

This means:

- the remote Herdr server and session are running;
- an Attached host process or remotely invoked Attached helper can access the local Herdr API socket;
- an Attached receiver daemon or foreground watcher is running on the receiving device; and
- a live authenticated path exists between the receiver and the remote host.

No service-side event queue is required. If the receiver is stopped or disconnected when an event occurs, the event may be lost. A small in-memory replay window could later cover transient reconnects while both processes remain alive, but durable offline semantics are explicitly outside the initial scope.

If “the remote session is not active” means that no interactive client is attached, notifications can still work. If the Herdr server or named session itself is stopped, it has no new events to emit.

## Proposed live notification flow

The receiver should initiate and maintain event subscriptions to its remote hosts. This avoids requiring every receiving device to publish a reachable endpoint and naturally matches the receiver-online requirement.

```text
Remote Herdr local API
        |
        v
Attached host event adapter
        |
        | authenticated live event protocol
        v
Attached receiver daemon or watcher
        |
        v
Local desktop/terminal notification provider
```

A possible flow is:

1. The host-side Attached process discovers running Herdr sessions and their local API sockets.
2. It establishes race-free Herdr API subscriptions, using a subscription plus snapshot bootstrap where needed.
3. It observes relevant semantic state, such as `pane.agent_status_changed`, including sessions without an attached TUI client.
4. It converts Herdr-specific messages into a bounded, versioned Attached event envelope.
5. The receiver maintains one authenticated host-level subscription, optionally filtered by session or event kind.
6. The receiver deduplicates events seen during route reconnection or route changes.
7. The receiver applies local notification policy and invokes the operating system or terminal notification provider.
8. Interactive attachment remains independent. Closing an attached terminal does not close the event subscription.

The event protocol should carry semantic events rather than proxying the entire Herdr TUI wire protocol. The experimental TUI protocol parser demonstrates that notifications exist in the TUI stream, but that stream is foreground-client-oriented and tightly coupled to exact Herdr protocol versions. Herdr's local socket API is the more appropriate integration surface for a host event adapter.

## Notification event shape

An initial event envelope could contain only bounded, presentation-ready semantic data:

```text
NotificationEvent
  event_id
  host_id
  session_name
  kind: Finished | NeedsAttention | Custom
  title
  body
  agent
  workspace_id
  pane_id
  occurred_at
```

`event_id` should be stable enough to suppress duplicates after a live reconnect or after switching between two routes. It does not need to support replay after both processes restart.

Notification text must be treated as potentially sensitive and untrusted:

- encrypt it end to end on routes where route encryption alone does not establish the required application identity;
- bound and sanitize titles and bodies before display;
- remove control characters;
- never include notification content in normal diagnostics;
- keep identifiers and payloads out of route-selection logs; and
- make notification subscriptions independently revocable.

Herdr currently sanitizes notification titles and bodies to bounded lengths. Reusing compatible limits would keep behavior consistent.

## Authorization

Notification access should not automatically grant interactive shell access.

The current Attached download credential is effectively remote-shell-equivalent because it contains the consumer identity and synchronized attach capability. A multi-capability design should introduce a distinct event-read capability or derive separately scoped capabilities from an account root. The host must authenticate the receiver before resolving session details or opening an event stream.

Trust differs by route:

- Iroh currently combines a preauthorized consumer endpoint identity with an application capability.
- SSH relies on OpenSSH authentication and host verification.
- A Tailcat connection token identifies the server, and Tailcat can additionally restrict allowed client keys.

Route selection must preserve these differences. Automatic fallback must not turn failure of a pinned, strongly authenticated route into an unnoticed bearer-token connection.

## Route-specific event adapters

### Iroh

The first notification prototype can retain Iroh and add a separate, non-interactive protocol, for example a new event ALPN. It should not overload the existing interactive-only tunnel protocol.

The event connection would:

- authenticate a read-only event capability;
- subscribe at host scope with optional filters;
- carry bounded semantic frames;
- use heartbeat and reconnect behavior suitable for a daemon; and
- enforce independent connection and subscription limits.

This allows notification work to proceed without waiting for the complete multi-route refactor.

### SSH

An SSH event route could execute a narrow remote Attached helper over command standard input/output. That helper would subscribe to the remote Herdr API and emit the same Attached event protocol.

This avoids parsing an interactive TUI and lets OpenSSH retain responsibility for authentication and host verification. An SSH route may be configured only on the receiver and mapped to a stable Attached host identity during enrollment.

### Tailcat

Tailcat is a natural conceptual fit because its connection token is intended to be distributed out of band. Attached's encrypted catalog could carry the token and allowed-client metadata.

Tailcat should initially be experimental because it currently makes no API, CLI, or wire-stability promises, and its Go implementation does not fit directly into the Rust workspace. Isolating it behind a subprocess or sidecar would limit the effect of upstream churn.

## Delivery semantics

The initial contract should be explicit and modest:

- live, best-effort delivery while the receiver is running;
- automatic reconnection with backoff;
- no service-side storage;
- no guarantee for events produced during a disconnect;
- in-memory duplicate suppression; and
- no acknowledgement that survives process restart.

A later bounded in-memory replay buffer could improve transient-network behavior without becoming an offline mailbox. If added, the protocol would need a per-host boot identifier, monotonically increasing sequence number, and a clearly bounded replay limit.

## Notification policy questions

Several policy details remain open:

1. Should Attached reproduce Herdr's finished/needs-attention transition policy, or should Herdr expose a semantic notification event through its socket API?
2. Are only agent state notifications required, or must explicit `notification.show` calls also be forwarded?
3. Should notifications be suppressed when that exact remote session is actively attached on the receiving device?
4. Should policy be configured per host, session, agent, or event kind?
5. Can several receiving devices subscribe concurrently, and should each receive the event?
6. Should a receiver reconnect through another route automatically, or only after an explicit route policy allows it?
7. Is a remotely invoked helper sufficient for SSH notifications, or must `attached serve` always run on the host?

The distinction between agent state events and explicit custom notifications is especially important. The existing Herdr API exposes agent status changes, while foreground-client notification delivery may not itself be represented as a subscribable API event.

## Incremental implementation path

A possible sequence is:

1. Define a bounded Attached notification event and protocol independently of the TUI tunnel.
2. Add a host-side Herdr API subscriber for all running named sessions.
3. Add a foreground `attached watch` command over Iroh to validate live semantics without daemon packaging.
4. Test authentication, multi-session behavior, reconnect handling, and operation without an interactive Herdr client.
5. Add a persistent receiver daemon and desktop notification integration.
6. Introduce the transport-independent host, session, route, and capability model internally while preserving existing Iroh descriptors.
7. Add Herdr-over-SSH as the second attach and event route, allowing the real abstraction boundary to be validated.
8. Introduce a versioned synchronized route descriptor and stable route-independent host identity.
9. Add Tailcat as an experimental backend.

Notifications should not be blocked on implementing every route. A separate Iroh event protocol can establish the event model first, and subsequent adapters can reuse it.

## Test areas for a future implementation

- A remote agent state transition produces one bounded semantic event without an attached TUI client.
- Unauthorized identities and incorrect event capabilities are rejected before session information is exposed.
- Attach and notification capabilities cannot substitute for each other.
- Multiple named Herdr sessions are discovered, subscribed, and cleaned up independently.
- New sessions and stopped sessions update host subscription tasks safely.
- Disconnect and reconnect behavior matches the documented best-effort contract.
- Duplicate events are suppressed when a live route reconnects or changes.
- Notification payloads are sanitized and excluded from diagnostics.
- An interactive attachment can stop while the receiver's event stream remains active.
- Route preference never silently downgrades authentication.

## Current direction

The discussion currently favors the following direction:

- Position Attached as the manager for remote Herdr sessions rather than as an Iroh-only tunnel.
- Keep Iroh as the default and first implementation.
- Model Iroh, SSH, and Tailcat as capability-bearing connection routes.
- Build notifications as an independent semantic event plane.
- Support live notifications only while the receiving Attached process is online.
- Defer durable queues, offline push, and full plugin extensibility.
