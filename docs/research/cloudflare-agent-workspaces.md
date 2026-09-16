# Cloudflare stack research: ephemeral development machines for AI agents

> Research prepared on **16 September 2026 (UTC)** against the supplied PID.
> **AI contribution:** This document was researched and written by an AI assistant at the human operator's explicit request.
> This is a design assessment, not an implementation. No Cloudflare resources were deployed and no runtime compatibility tests were performed.

## Executive recommendation

**Cloudflare is a credible backend for a Linux-first MVP, with important qualifications.** Use **Workers + Durable Objects + Workflows + Sandbox SDK on Containers + R2**, while keeping **Herdr, the coding agent, and the Attached publisher inside one isolated workspace**. Keep the existing Attached discovery service and Iroh transport; do not replace them with a web terminal or Cloudflare Tunnel.

This is no longer a proposal dependent on the original Containers beta: **Containers and Sandboxes became generally available on 13 April 2026**.[C01]

However, the PID is **not fully achievable by assembling the existing Attached release and Cloudflare services without additional product work**:

1. **Attached credentials are publisher-only today, but not workspace-scoped or individually revocable.** This is a security/lifecycle gap in Attached, not something Cloudflare IAM solves.
2. **Iroh relay connectivity under Cloudflare's restrictive outbound policy needs a real deployed test.** The protocols appear compatible, but HTTPS support alone is insufficient: WebSocket upgrades, TLS trust, and reconnect behavior matter.
3. **Keeping a workspace running preserves its live Herdr session; restoring files does not restore that session's processes or memory.** Cloudflare can replace a container and explicitly does not guarantee a minimum uninterrupted lifetime.[C02], [C03]

**Decision:** proceed to a small compatibility/security validation phase before committing to this compute backend. If those tests pass, Cloudflare is a reasonable first provider. If exact process-preserving suspension or a more conventional long-lived machine is essential, use a VM-oriented backend instead, while retaining Cloudflare for orchestration and durable storage.

**Do not base the MVP on `@cloudflare/computer` yet.** It is remarkably close to the product's language and worth tracking, but its current repository explicitly says **preview only, unstable APIs, not suitable for production**.[C10], [C11]

## 1. Research scope and evidence

Sources were retrieved live on 16 September 2026, including Cloudflare's current documentation, product-specific changelog feeds, the April and August product announcements relevant to this PID, September updates, SDK package metadata, Iroh documentation, and alternative providers' documentation.

Attached was inspected at `main` commit **`d334f7d75eb2b58059e9deeaaa73a61e799a476c`**, version **0.2.14**. Open PRs are not treated as shipped functionality.

The distinctions used throughout are:

- **Documented:** the vendor or repository currently describes the capability.
- **Proposed:** application behavior that this product would have to implement.
- **Unverified:** requires a deployed experiment; not established by this research.

“Cloudflare-based” here means Cloudflare hosts the control plane, workspaces, and work storage. Git hosting, model providers, and the default Iroh relay infrastructure can still be external dependencies. The PID does not require replacing those services.

## 2. Latest relevant Cloudflare releases

These are the recent releases that materially affect this product, rather than a catalogue of unrelated Cloudflare products.

| Release / verified status | What changed | Implication for this PID |
| --- | --- | --- |
| **Containers + Sandbox GA — 13 Apr 2026** | Full Linux execution, VM-backed isolation, background processes, files, and SDK management on Workers Paid. | The primary execution backend is available now, not merely announced.[C01], [C04] |
| **Sandbox outbound policy and credential injection — 13 Apr 2026** | Trusted Worker handlers can filter HTTP(S), inject credentials outside the sandbox, and change policies dynamically. | A particularly strong fit for “the repository requests; the user authorizes.” Still requires application authorization and abuse controls.[C05], [C06] |
| **Docker-in-Docker — 17 Feb; directory backups — 23 Feb 2026** | Rootless nested Docker and directory backup/restore to R2 are documented. | Older assessments saying “no Docker” or “no persistence” are too broad. Neither feature gives unrestricted VM administration or memory snapshots.[C07], [C08] |
| **Dynamic Workers — 24 Mar 2026, open beta** | Workers can instantiate isolated Worker-compatible code at runtime, with controlled bindings and egress. | Good for small generated tools, not a substitute for the Linux workspace required by Herdr and Attached.[C49] |
| **Native Containers `exec()` — 18 Jun 2026** | Containers can launch and observe additional processes directly. | Raw Containers are now a viable lower-level alternative to Sandbox SDK, not just an HTTP-server runtime.[C09] |
| **`@cloudflare/computer` — 3 Aug 2026, early preview** | SQLite-backed durable virtual filesystem; container/FUSE and Dynamic Worker execution backends. | Very relevant future persistence/runtime abstraction, but not a drop-in durable Herdr machine and explicitly not production-ready.[C10], [C11] |
| **Inbound TCP / Socket Workers / gRPC — 3 Aug 2026, private beta** | Spectrum can pass inbound TCP to Workers and Containers. | Do not rely on old blanket claims that Cloudflare never accepts TCP. Equally, do not assume GA or UDP support. The MVP should not need this feature.[C12] |
| **Artifacts + CI SDK integration — 4 Aug 2026** | Git-compatible versioned storage can trigger Workflows; `@cloudflare/ci` runs isolated build/test steps. Artifacts documentation still labels access **closed beta**. | Attractive future internal repository/result store. Do not make obtaining beta access a prerequisite for the MVP.[C13], [C14] |
| **Cloudflare Agents — 4 Aug 2026** | Agent-aware traces and a dashboard for instrumented harnesses; session “replay” displays recorded data. | Optional observability, not restoration of a Herdr process and not a reason to replace the user's coding agent.[C15] |
| **Kitesurf — 6 Aug 2026, beta** | Agent-oriented browser in Workers, alongside Browser Run. | Optional web-research capability, not a Linux development machine. Do not assume browser-test fidelity equivalent to Chromium.[C16] |
| **Sandbox SDK 1.0 preview — 7 Aug 2026** | `exec(argv)` returns a process handle; first-class PTYs; RPC-only SDK transport; no old shell-session execution model. | Cloudflare recommends `@next` for new projects. Pin and validate one release line; do not mix stable examples with preview APIs.[C17] |
| **Workers AI / AI Gateway convergence — 7 Aug 2026** | Shared entry points and unified billing for Workers AI and external providers. | Optional model-access/spend layer. Model-first and automatic smart routing were described as future work, not baseline available capabilities.[C18] |
| **Cursor self-hosted machines — 2 Sep; OpenAI Agents API executor — 10 Sep 2026** | Official examples run these providers' execution environments on Cloudflare. Devin Outposts documentation also exists. | Strong evidence of coding-workload fit, but these integrations are not the same as an arbitrary agent running under Herdr over Attached.[C19], [C20], [C21] |
| **Workflow retention — 10 Sep; event subscriptions — 15 Sep 2026** | New paid Workflows default to seven-day completed/errored state retention; `.subscribe()` streams historical and new execution events. | Useful CLI progress without polling. Workflow history must not be the durable repository/result store.[C22], [C23] |
| **Per-Worker authorization — 15 Sep 2026** | Metadata Read-Only, Content Read-Only, Editor, and Admin roles can target selected Workers. | Narrow deployment/operator permissions. These are not per-workspace execution credentials; never give an agent Editor on its own orchestrator.[C24] |
| **Browser Run hostname guardrails — 14 Sep 2026** | Allow/deny browser destinations. | Useful if browser access is added, but browser guardrails do not control arbitrary shell network traffic.[C25] |

### SDK version caveat

The npm registry returned these tags during research:

| Package | Tag / version observed |
| --- | --- |
| `@cloudflare/sandbox` | `latest`: `0.12.9`; `next`: `0.13.0-next.751.1` |
| `@cloudflare/containers` | `latest`: `0.3.7`.[C45] |
| `@cloudflare/computer` | `latest`: `0.3.0`.[C46] |
| `@cloudflare/ci` | `latest`: `0.2.0`.[C47] |

The **“1.0 preview” product name does not mean the npm package is already version 1.0**. Likewise, npm's `latest` tag is not a production-readiness guarantee for Computer. Recheck these tags at implementation time and pin the SDK and corresponding container image together.[C17], [C26]

For an exploratory implementation, evaluate the Sandbox preview first, following Cloudflare's recommendation. For a release that must avoid preview APIs, use the stable line behind a small backend adapter, or use raw Containers. Do not copy deprecated `exposePort()` or old default-session patterns into new work.[C27]

## 3. Recommended stack

### Core services

| Component | Choice | Responsibility / boundary |
| --- | --- | --- |
| Local control surface | Small CLI; Rust is a natural fit beside Attached | Inspect Git, present approvals, create/connect/stop/destroy, download results. No local agent execution or directory sharing. |
| Public control API | **Cloudflare Worker, TypeScript** | Authenticate the developer, validate requests, enforce ownership and quotas, initiate lifecycle operations. TypeScript fits the first-party Sandbox/Containers SDKs. |
| Workspace state | **SQLite-backed Durable Object** | One authoritative workspace state machine; generation, lease, approvals, image/revision, artifact manifest and revocation. Keep this separate from the SDK-owned Sandbox DO so sandbox destruction cannot erase grants or tombstones. |
| User workspace index | Small account Durable Object | List workspace IDs and ownership. No D1 database is required for a one-developer MVP. |
| Durable orchestration | **Cloudflare Workflows** | Idempotent provisioning, preparation, checkpoint/stop, cleanup, retries, and compensation after partial failure. Not the agent's execution environment. |
| Isolated machine | **Sandbox SDK on Containers** | One sandbox per workspace; full Linux userspace with Herdr, Attached, agent, shells, tooling, and all their children inside the boundary. |
| Work and result storage | **R2 Standard** | Initial Git bundles, immutable checkpoints, output bundles/patches, selected agent state and artifacts. Keep build caches disposable. |
| Credential broker / egress | Trusted Worker handlers + Worker secrets | Mint/refresh constrained external credentials and enforce workspace capabilities outside untrusted execution. |
| Existing discovery | **Attached's existing Rust Worker + account Durable Objects** | Retain encrypted session discovery; extend credentials/lifecycle deliberately rather than replacing the service. |
| Interactive transport | **Attached + Iroh** | End-to-end encrypted Herdr connectivity. Prefer a tested relay-capable path; no user-configured IP, inbound port, or SSH. |
| Operations | Workers/Containers logs, alarms, scheduled reconciliation | Lifecycle health, checkpoint freshness, expiry and cleanup. Redact secrets and avoid collecting terminal/model payloads by default. |

Use **one prebuilt, pinned Linux/amd64 workspace image** initially. Include the chosen agent runtime, Git, Herdr, Attached, a supervisor, and the project's required toolchain. For this Rust-oriented repository, include Rust plus the runtime needed by the selected agent; do not promise universal devcontainer compatibility.

Start evaluation around **`standard-3`: 2 vCPU, 8 GiB RAM, 16 GB disk**, then benchmark the actual build. Large Rust dependency trees can exhaust that disk. This is a proposed starting point, not a measured sizing recommendation.[C28]

### Optional, deferred, or inappropriate services

- **Secrets Store:** optional centralized secret management; currently open beta. Ordinary Worker secrets suffice for the MVP's broker root credentials. Neither service automatically issues GitHub tokens or revokes credentials copied elsewhere.[C29]
- **Artifacts:** excellent future Git-native store if access is granted. See section 8.
- **AI Gateway / Workers AI:** optional model proxy, attribution, rate limiting, and approved inference capabilities. Keep provider credentials behind the broker where the agent supports it. Confirm streaming, tools, and provider-specific API compatibility. Disable unnecessary prompt/response logging.[C18]
- **Cloudflare Access:** optionally protect the control API/operator tools. It does not provide workspace isolation or Attached publication credentials. Do not require a new enterprise identity setup for the single-user experience.
- **Queues:** useful later for larger cleanup/export fan-out; not required alongside Workflows and DO alarms for one workspace.
- **D1:** useful later for cross-workspace queries. **KV is not the authoritative revocation/state store**: authorization needs current, strongly coordinated state, not an eventually propagated cache.[C50]
- **Dynamic Workers / Workers for Platforms:** appropriate for isolated Worker-compatible code, not running the unchanged native Herdr/Attached binaries and arbitrary Linux tools. Workers' Node compatibility is not a full Linux host.[C30], [C31]
- **Agents SDK / Think / Computer:** do not move the coding-agent loop into a DO just to follow a Cloudflare example. The PID explicitly places the agent inside the workspace and does not require a new framework.
- **Browser Run / Kitesurf / Agent Memory / AI Search / Vectorize:** adjacent capabilities, not prerequisites for this MVP. An optional external browser is a separately authorized capability, not a substitute for local project tests.
- **Tunnel, Spectrum, Realtime/TURN:** not replacements for Iroh. Cloudflare's HTTP preview URLs or browser terminal APIs would create a second interaction/transport path unnecessarily.

## 4. Target architecture and trust boundaries

```text
Developer laptop
  Git repository + approval CLI + existing Attached/Herdr client
       |
       | authenticated lifecycle requests / artifact retrieval
       v
Cloudflare Worker: control API
       |
       +-- Account index / Workspace Durable Object
       |      approvals, generation, lease, lifecycle, revocation
       +-- Workflows: provision / checkpoint / stop / destroy
       +-- R2: input bundles, immutable checkpoints, results
       +-- Trusted egress/credential broker
       |
       v
One Cloudflare Sandbox / Container VM boundary per workspace
  local scratch filesystem + checked-out approved repositories
  supervisor -> Herdr server -> coding agent / shells / children
  Attached publisher
       |                        |
       | encrypted descriptors  | outbound Iroh relay connection
       v                        v
Existing Attached sync     Iroh relay / optional direct path
Worker + account DO             |
       ^                        | encrypted Herdr traffic
       |                        v
       +----------------- Local Attached -> local Herdr client
```

**The control plane must not evaluate repository scripts.** Repository setup and hooks execute only after provisioning the isolated machine and applying its approved network/credential policy.

**One workspace is one trust domain.** Separate shell sessions or Unix users inside a sandbox are not a replacement for separate sandbox boundaries. Assume a compromised workspace can read any credential delivered to it and tamper with its Herdr server, agent, and publisher.[C04]

Cloudflare and the orchestrator remain trusted infrastructure: they control the machine running the plaintext endpoints. Attached's end-to-end transport does not conceal endpoint memory, repository files, or brokered API traffic from the compute provider/orchestrator. It protects the transport, not the machine operator.

## 5. Mapping the PID to feasibility

| MVP requirement | Assessment | Required work / caveat |
| --- | --- | --- |
| 1. Create from a clean local Git revision | Feasible | Support exact-SHA remote checkout and a bundle upload for local-only/unpushed commits. A clean tree does not mean the commit exists on GitHub. |
| 2. Repository-owned configuration | Feasible, application code | Versioned declarative schema; validation and explicit user approval. No automatic privilege grants. |
| 3. Additional repositories/capabilities | Feasible, application code | Record approvals and enforce repository-, operation-, and workspace-scoped broker rules. |
| 4. Start Herdr and coding agent | Plausible, unverified combination | Full Linux, processes and PTYs are documented. Test this exact image, native binaries, Unix sockets, and agent. |
| 5. Start `attached serve` | Plausible, bootstrap work needed | Bundle injection exists; fully unattended encryption-password setup is not shipped on inspected `main`. |
| 6. Existing Attached account discovery | Existing foundation | Publish into that account, not a newly created account per workspace. New scoped credentials must remain compatible with owner discovery. |
| 7. Herdr over Attached | Conditional | Validate Iroh relay WebSockets and TLS with production egress restrictions. No need for direct UDP as a prerequisite. |
| 8. Continue while laptop is disconnected | Feasible while container survives | Provider-side keep-alive and a bounded lease; no dependence on a live CLI request. |
| 9. Reconnect to the same Herdr session | Yes while original processes survive | After replacement, only application/file-level recovery is available; not the identical live session. |
| 10. Retrieve and review changes | Feasible | Continuous durable checkpoints plus Git bundle/patch export, including uncommitted and approved untracked results. |
| 11. Destroy and revoke workspace credentials | Not supported by current Attached as-is | Add selective publish revocation, discovery invalidation, generation fencing, and external credential cleanup. Terminating a VM alone does not revoke a stolen token. |

### Two different promises

The practical MVP can promise:

> Closing the laptop does not stop the remote workspace. Reconnect to its live Herdr session while it remains running. If infrastructure replaces it, recover durable work and clearly report that the runtime was restarted.

It cannot honestly promise:

> Any arbitrary failure or sleep will transparently resume the identical Herdr process, terminal state, open sockets, and running agent from memory.

The PID's “machines may disappear; useful work must not” supports checkpoint-based recovery. But if “the same Herdr session” must hold even after infrastructure replacement, this is an unresolved requirement, not a detail to hide behind a stable sandbox ID.[C03], [C32]

## 6. What Attached already provides, and what it does not

These findings are based on code, not just the README.

### Existing foundations

- `crates/session-sync-worker/wrangler.toml` already deploys an Attached Worker with **SQLite-backed account Durable Objects**. There is no need to invent a new discovery infrastructure.[A01]
- `attached serve` accepts publisher credentials through **`ATTACHED_PUBLISH_BUNDLE` or `--bundle-file`**. Do not copy the owner's download bundle or whole local Attached state directory into a workspace.[A02]
- The server checks the **authorized consumer's Iroh public identity** after the handshake. A publisher does not receive that consumer's private key.[A03]
- Publishers refresh descriptors every **30 seconds**, with a **90-second descriptor lifetime**. This helps dead hosts disappear from discovery, but is not revocation of the publisher's credential.[A04]
- A reusable application-runtime Docker image already installs Herdr and Attached. At the inspected commit it pins **Attached 0.2.9 / Herdr 0.8.2**, not the repository's latest Attached version. Reuse the packaging approach, not those versions blindly; a Sandbox image also needs the matching SDK runtime.[A05]

### Security and automation gaps

**Publisher-only is not workspace-only.** `StoredAccount` holds one publish-token hash and one download-token hash per account. The request handler authorizes record writes by account-level publish scope, rather than a grant restricted to a particular workspace/record. The API inspected exposes account creation and record read/write operations, not per-publisher issuance/revocation.[A06], [A08]

The publisher also receives account encryption material.[A10] Current consumer-identity checks improve protection against a publisher connecting elsewhere, but do not turn that account-wide publish authority and shared encryption material into per-workspace isolation. A compromised workspace must not be able to publish arbitrary replacement records under the owner's account.

**Unattended initialization needs finishing.** Bundle injection does not eliminate the separate local encryption-password requirement. Inspected `main` uses terminal prompts or 1Password integration.[A09] [PR #88][A07], adding unattended passwords through environment configuration, was still open during research. Do not describe its behavior as shipped. Do not solve this by giving a malicious workspace the developer's 1Password credentials.

### Proposed Attached changes before a security-compliant MVP

1. Owner-authorized issuance of **short-lived, workspace/generation-scoped publish grants** under the existing account.
2. Bind each grant to the permitted publisher identity/record; deny list/download and all other record mutations.
3. Separate each publisher's encryption authority from the account root. For example, a reviewed protocol extension could distribute only a derived per-record key while the owner derives the matching key locally. This requires protocol/client changes, not just a new token string.
4. Add authoritative revoke/expire operations and discovery tombstones or equivalent invalidation; verify tokens fail from outside the destroyed machine too. Account for cached descriptors and already-open Iroh tunnels: revoking a sync API token alone does not close a connection. Terminate the original runtime and have clients reject revoked/expired workspace identities, including a copied publisher identity running elsewhere.
5. Support safe unattended bootstrap with a fresh workspace-specific encryption secret. Exclude credential state from reusable images and general backups.
6. Ensure deletion cannot be undone by a delayed provisioning retry or stale publisher. Lease/generation checks must exist outside the sandbox.

Keep the sync service's encrypted-data design intact. The orchestrator should not casually collect the owner's account root or consumer private key just to make provisioning easier. Enrollment needs an explicit, authenticated association between the control-plane owner, Attached account, and authorized consumer identity; accepting an arbitrary account ID from a request is not proof of ownership.

A one-off demo using the current account-wide publish bundle is possible **only as an explicitly reduced-security experiment**. It does not satisfy selective workspace revocation and should not be presented as the PID-compliant design.

## 7. How the product could work

The lifecycle and policy behavior below is proposed product functionality; `attached serve` and `attached attach` already exist.

### 7.1 Create from the repository

1. The CLI reads the repository root, exact commit SHA, and configuration **from that revision**. Reject tracked modifications and non-ignored untracked input for the clean-repository MVP; do not upload ignored secrets.
2. Resolve requested repositories, setup commands, network destinations, model access, resource profile, maximum lifetime, and output paths.
3. Show an approval summary. Approval binds to the revision, configuration digest, image digest, repositories and capability policy. A later changed config requires new approval.
4. Use an exact-revision remote checkout when available. Otherwise upload a revision-scoped **Git bundle/object transfer** to R2. Do not tar the working directory, `.git/config`, hooks, credential helpers, SSH agent sockets, or the user's home directory. Git history itself can contain secrets; disclose and minimize the history being transferred.
5. Allocate an opaque workspace ID and generation, record the approved policy, and start a provisioning Workflow. Return a durable operation ID so the CLI can disconnect immediately after acceptance.

For the MVP, explicitly reject or require separate approval for submodules, Git LFS dependencies, nested repositories and extra remotes. Never silently traverse them or forward credentials to URLs supplied by a repository.

### 7.2 Prepare and start

The Workflow would:

1. Create the sandbox with the pinned image, resource size, **deny-by-default egress**, and a hard lease, for example 12 hours approved by the user.
2. Establish scoped input/checkpoint access and the credential broker policy before running untrusted setup.
3. Restore the approved source, verify the SHA, and create a workspace branch. Clone extra repositories with read-only access unless writes were separately approved.
4. Execute setup inside the sandbox with time/output limits. Prefer prebuilt toolchains and dependency caches over privileged package installation at every start.
5. Bootstrap a scoped Attached publisher, start Herdr and the chosen agent, and supervise them independently of the initiating HTTP request.
6. Wait for real readiness: correct Herdr session/socket, publisher healthy, initial checkpoint recorded, and publication acknowledged. Distinguish “published” from “client connection verified.”
7. Mark the workspace ready and return its display label. The user's existing Attached client can discover it normally.

On the preview SDK, `exec(argv)` yields a supervised process handle when launch succeeds; it does not wait for process completion. Store process references **and the runtime generation**, but never mistake them for persistent process identity after a restart.[C17], [C33]

The prebuilt image's supervisor must forward shutdown signals and reap children. Herdr should own the agent's interactive PTY/session; the product should not create a competing browser terminal.

### 7.3 Disconnect and reconnect

- `attached attach` remains the normal interaction path into local Herdr.
- Ending the local connection does **not** end the workspace lease or agent work.
- Keep the container alive from Cloudflare, not with a laptop heartbeat. Sandbox documents `keepAlive: true`; raw Containers can use explicit activity-expiry handling. A background process or outbound Iroh connection must not be assumed to reset the SDK's idle timer automatically.[C03], [C34]
- On reconnect, route to the same workspace/generation if alive. If its container was replaced, show **interrupted / recovered**, restore files and supported agent state, and start a new runtime rather than pretending the old PTY survived.
- Refresh external credentials from the broker while the lease is valid, even if the laptop is offline. The agent cannot extend its own lease or approve more access.

### 7.4 State and retries

A minimal state machine:

```text
requested -> provisioning -> preparing -> running
                                  |          |
                                  v          v
                                failed   checkpointing -> stopped
                                             |
                                             v
                                          running

any non-final state -> destroying -> destroyed
runtime loss        -> interrupted -> explicit recovery / destroy
```

Persist the approved policy, desired state, generation, lease deadline, latest completed artifact manifest and outstanding cleanup actions. Use idempotency keys for create and each external side effect. Workflow retries must not start a second agent, duplicate a branch push, or revive a destroyed workspace.

Use DO alarms plus a scheduled reconciler as independent expiry/cleanup mechanisms. Keep a tombstone after destruction so an old request cannot lazily instantiate the same sandbox again. Do not depend on a final callback from potentially malicious code.

### 7.5 Stop and destroy are different operations

**Disconnect:** keep executing.

**Stop:** quiesce work, produce and verify a final checkpoint, terminate compute, and revoke its runtime grants. Retain results. On Cloudflare, restarting from this state is file/application recovery, not RAM resume.

**Destroy:** terminate compute and invalidate the workspace permanently, including its grants and publication; keep completed results for a separately approved retention period, such as seven days. Offer a distinct purge action for deleting results.

For an orderly stop, allow a tightly scoped, time-bounded final checkpoint. For a suspected compromise, revoke access and force termination immediately, retaining the last externally committed checkpoint instead of waiting for the agent's cooperation.

Mark destruction complete only when compute termination and required credential revocation have succeeded. If an external revocation API is unavailable, report cleanup as pending, deny new broker requests immediately, retry durably, and expose any remaining token-expiry window.

## 8. Durable work, not just a persistent ID

### Recommended MVP storage strategy

Use **local scratch disk for the active repository and toolchain operations**, with **R2 for immutable checkpoints and result export**.

A checkpoint should include:

- Base revision and repository identity.
- New commits in a retrievable Git bundle, or equivalent complete Git data.
- Tracked working-tree/index changes, including binary changes.
- Explicitly selected untracked outputs; a plain `git diff` alone misses these.
- Selected agent transcripts/state needed for supported resume, excluding authentication stores.
- A manifest with workspace/generation, sequence, timestamp, file sizes and checksums.

Upload new checkpoint objects first, verify completion, then atomically advance the manifest reference in the workspace DO. Keep the previous valid checkpoint until the new one is committed. The workspace must not be able to overwrite/delete older checkpoints or write outside its own output namespace.

Proposed initial recovery target: **at most five minutes of unsaved work under healthy checkpointing**, with immediate checkpoints after meaningful completed work. This is a target to test, not a Cloudflare guarantee. Pause writers or use a consistent staging snapshot; a tar of a tree being modified can be internally inconsistent. If checkpoints fail, report degraded durability and stop/pause further work according to policy rather than claiming it is saved.

**No periodic backup promises zero loss of the most recent writes.** If the product requires every acknowledged filesystem write to survive immediate machine loss, a durable write-through filesystem or a stronger persistence backend is required. Also, malicious code can corrupt its *current* work; immutable external history limits the damage but cannot guarantee that an agent produces useful output.

### Cloudflare persistence options compared

| Option | Actual semantics | Recommendation |
| --- | --- | --- |
| Container local disk | Ephemeral; lost on stop/sleep/replacement. | Active scratch only.[C02], [C03] |
| Sandbox directory backup to R2 | Filesystem snapshot, not process/memory snapshot. Production restore uses a copy-on-write overlay; some directory renames can fail with `EXDEV`. | Evaluate for environment acceleration/checkpoints. Test Git and build-tool behavior on restored trees.[C08] |
| R2 bucket mount | Object storage through filesystem tooling; network latency and filesystem-semantics trade-offs. Production mount overlays the target path. | Use for artifacts/datasets, not assume it is a durable SSD suitable for `.git`, SQLite, or `node_modules` without tests.[C35] |
| `@cloudflare/computer` | DO/SQLite-authoritative filesystem projected into a container by FUSE, or used by isolate backends. | Promising future write-through workspace option; still preview-only, with filesystem compatibility, performance and limits to validate. It does not preserve Herdr RAM.[C10], [C11] |
| Artifacts | Durable versioned Git-compatible repository store; imports/forks, repo-scoped expiring/revocable read/write tokens. | Best Cloudflare-native Git option if closed-beta access is obtained. Keep uncommitted changes checkpointed separately.[C14], [C36] |

Important operational details:

- Sandbox backups default to a **three-day TTL**; the SDK rejects expired handles, but TTL expiry **does not delete the R2 objects**. Set retention explicitly and implement R2 lifecycle cleanup.[C08]
- Credential-less R2 binding mounts and `credentialProxy` support now exist. Avoid copying broad S3 credentials into a container. A mount prefix is not, by itself, proof that a malicious process cannot access other object keys; test the broker's authorization directly.[C35]
- Keep recovery metadata in your DO/R2, not solely in Workflow history. New paid Workflow instances default to seven-day retention, despite some older pricing/limits prose still saying 30 days.[C22]
- Current Artifacts limits include **10 GB per repository**.[C48] Listed pricing is **$0.50/GB-month** beyond its included storage, compared with **$0.015/GB-month** for R2 Standard. These are different abstractions, not interchangeable storage prices.[C37], [C38]

### Retrieving results safely

Prefer read-only upstream repository access initially. Download the output bundle and changes to a **separate local review worktree**, validate the manifest, inspect the diff, and let the developer decide what to apply/push.

Treat exported content as untrusted: reject archive traversal and unsafe symlink extraction, do not import remote Git hooks/configuration, do not execute project scripts during retrieval, and do not automatically merge into the developer's current working tree.

A direct push/PR workflow can follow later with explicit write approval. GitHub App tokens are repository- and permission-scoped, **not automatically restricted to one branch**. Use protected branches/rulesets or a broker enforcing the allowed write operation; never describe a repo-wide write token as branch-scoped.[C39]

## 9. Connectivity and least privilege: the highest-risk integration

### Iroh can work without inbound ports or direct UDP

Iroh documents outbound **HTTPS upgraded to WebSocket on TCP 443** for relay connections. Direct UDP is optional: when unavailable, encrypted traffic stays on the relay. Address publication/lookup can add DNS and `dns.iroh.link` dependencies, depending on the configured discovery stack.[N01]

Cloudflare's restrictive mode, `enableInternet = false`, allows only explicitly permitted destinations through its outbound policy; its documentation describes ports 80/443 and Cloudflare DNS in this mode. Outbound handlers operate on HTTP(S), not arbitrary non-HTTP protocols.[C05]

**Inference:** a relay-only Attached connection is a plausible fit. **Not yet proven:** that the exact Attached/Iroh version works with Cloudflare's production forwarding, WebSocket upgrades, long-lived connection behavior, and selected TLS policy.

Validation should specifically cover:

- Establishing and reconnecting relay WebSockets with UDP unavailable.
- Explicit allowlisting of the actual relay, Attached sync and required discovery destinations, without allowing all Internet access.
- TLS interception: Iroh documents that its default relay certificate roots are built into the application. Installing Cloudflare's interception CA into the OS store alone may not suffice. Prefer avoiding relay TLS interception where supported; otherwise use a deliberate trusted-CA integration. **Never disable certificate verification.**[N01]
- A laptop changing networks, relay reconnection, prolonged idle connections, and an entire night without client traffic.
- Measuring interactive latency under mandatory relaying, not advertising direct-P2P latency.

Cloudflare's August inbound TCP announcement is **private beta**, and does not establish general inbound UDP/QUIC support. It is neither a required dependency nor a shortcut to “Iroh works.” Ordinary Cloudflare proxying, Cloudflare Tunnel and TURN are not Iroh relay services.[C12]

The current default public Iroh relays are documented for development/hobby use, with rate limits and no SLA. Budget for suitable managed or self-hosted relays if this becomes a production product. Review relay authentication before putting any project-wide relay signing key into a hostile workspace.[N02]

### Capabilities should be mediated outside the workspace

| Capability | Safe starting design |
| --- | --- |
| Read approved Git repositories | GitHub App installation token limited to explicit repositories and read permissions; broker refreshes it. Tokens expire after one hour.[C39] |
| Write results | Workspace-specific append-only checkpoint endpoint, authorized using provider-supplied container identity plus current generation/lease. No general R2 write credential. |
| Call a model | Broker a specific provider/model set, with concurrency/request/token budgets. Provider root key stays outside the workspace. |
| Publish Attached session | New workspace-bound publish grant; no owner/download credentials. |
| Install dependencies | Approved registries/mirrors and required artifact hosts. Setup scripts remain untrusted; approving a registry does not make package code safe. |
| Deploy infrastructure | Not granted by default. If added, mediate a named deployment target and an explicit permission set; never grant editor access to the orchestrator/broker itself. |

For every broker request, derive workspace identity from trusted context, not a user-controlled `workspace-id` header. Recheck live grants; strip supplied authorization headers; validate normalized destination, path and method; constrain redirects; apply quotas; deny private/link-local/metadata destinations and routes into other workspaces.

**Credential hiding is not authority removal.** A compromised agent can still abuse whatever authenticated actions the broker allows. Filtering only `github.com` is insufficient to restrict which repository is accessed. URL/path checks alone are also insufficient for branch-level Git push restrictions.

**A host allowlist is not a no-exfiltration proof.** Git hosts, package registries, model APIs, relays, and DNS can all carry attacker-controlled data. Cloudflare forcing DNS through its own resolvers does not by itself prevent exfiltration through attacker-controlled query names. Document this residual risk and test it; strict data confinement may require a more restrictive external network/proxy design.

Avoid long-lived secrets in images, build arguments, logged command lines, inherited agent environments, reusable caches, and R2 backups. Short-lived signed upload/download URLs are bearer capabilities too: use narrow scope and short expiry, and do not assume they can all be individually revoked immediately. For sensitive runtime writes, prefer broker-mediated authorization checked on every operation.

## 10. Limits and cases where Cloudflare is not the right machine

### Current execution limits

The documented largest standard instance is **4 vCPU / 12 GiB RAM / 20 GB disk**. Custom types do not currently exceed those maxima. The platform requires **Linux/amd64** images. The image-size limit is tied to instance disk size; aggregate image storage is separately limited.[C02], [C28]

Container shutdown and image rollouts can terminate a live session. The platform documents `SIGTERM`, with up to 15 minutes before `SIGKILL` for a process that does not exit, but sudden failures/OOM are still possible. Keep periodic checkpoints; do not treat graceful shutdown as a durability guarantee.[C02], [C03]

### Unsuitable or conditional scenarios

| Requirement | Why the proposed Cloudflare stack falls short | Alternative |
| --- | --- | --- |
| Unchanged native binaries in Workers alone | Worker isolates are not a Linux process host. | Containers/Sandbox, or an external VM. |
| Exact RAM/PTY/process restore after sleep | No documented general process-memory checkpoint/restore in Containers/Sandbox; directory backups only restore files. | E2B persistence, a suitable Daytona VM sandbox, or supported EC2 hibernation. Network sessions still need reconnection. |
| Builds exceeding 4 cores, 12 GiB or 20 GB | Above documented self-service instance maxima. | Larger VM or another sandbox provider; request higher Cloudflare capacity but do not assume approval. |
| Privileged Docker, kernel modules, arbitrary host networking | Cloudflare nested Docker is rootless; iptables manipulation is unsupported. | Dedicated VM with carefully isolated host privileges. |
| Full arbitrary devcontainer / Docker Compose compatibility | Supported nested Docker does not imply all networking, volume, privileged or architecture features work. | Constrain the MVP image, or use a VM backend. |
| macOS, Windows or native ARM development | Outside documented Linux/amd64 runtime. | OS/architecture-specific VM or hosted development provider. |
| Local GPU execution | Listed Containers sizes do not supply a GPU; Workers AI is a remote inference API, not a CUDA device in this machine. | GPU-capable provider such as Modal or a GPU VM. |
| Strong arbitrary-protocol egress enforcement plus direct QUIC | Documented trusted interception is HTTP(S)-focused; restrictive mode conflicts with arbitrary UDP paths. | Relay-only connectivity if validated, or a VM with an externally enforced firewall/proxy. |
| Guaranteed uninterrupted overnight runtime | Cloudflare explicitly guarantees no fixed uninterrupted instance lifetime. | A conventional non-preemptible VM may better fit operational expectations, but still needs failure recovery. |
| Production dependency on Computer or Artifacts without qualification | Computer says not production-ready; Artifacts requires closed-beta access. | R2 + ordinary Git hosting now; reconsider later. |

**Raw Containers are a useful fallback within Cloudflare**, particularly if Sandbox API churn is the problem. They do not remove the same underlying resource, disk, network, or runtime-replacement constraints.

Rollouts deserve particular care: deploys can replace active workspaces, and Worker/image rollout is not transactional. Use versioned workspace image deployments and drain existing sessions rather than updating every active machine in place. The `rollout_active_grace_period` is not a guarantee that all long-running agent tasks finish before replacement.[C40]

## 11. Indicative costs

Prices below were checked on 16 September 2026, in USD. These are arithmetic estimates, **not measurements or quotes**.

### Cloudflare Containers

Workers Paid starts at **$5/month**. Containers are billed in 10 ms increments:

- Provisioned memory: **$0.0000025/GiB-second = $0.009/GiB-hour**.
- Active CPU usage: **$0.000020/vCPU-second = $0.072/active-vCPU-hour**.
- Provisioned disk: **$0.00000007/GB-second = $0.000252/GB-hour**.
- Included monthly container usage: **25 GiB-hours memory, 375 vCPU-minutes, 200 GB-hours disk**, shared at account level.[C41]

```text
container cost = running seconds ×
  (provisioned GiB × 0.0000025
   + average active vCPUs × 0.000020
   + provisioned disk GB × 0.00000007)
```

The following excludes included usage, the plan fee, network, control-plane services and models. “25% CPU” means 25% of the selected instance's total vCPU capacity, averaged over the run.

| Size | Resources | Idle CPU, per running hour | Full CPU, per hour | 8 hours at 25% CPU | 8 hours at full CPU |
| --- | --- | --- | --- | --- | --- |
| `standard-2` | 1 vCPU / 6 GiB / 12 GB | $0.057 | $0.129 | $0.60 | $1.03 |
| **`standard-3`** | **2 vCPU / 8 GiB / 16 GB** | **$0.076** | **$0.220** | **$0.90** | **$1.76** |
| `standard-4` | 4 vCPU / 12 GiB / 20 GB | $0.113 | $0.401 | $1.48 | $3.21 |

For example, 22 eight-hour runs on `standard-3` at 25% average CPU are approximately **$19.72 in container resource usage before included allowances**, plus the $5 plan and other charges. A kept-alive machine still incurs provisioned RAM/disk charges while waiting for model responses.

### Other costs and controls

- **R2 Standard:** $0.015/GB-month, $4.50/million Class A operations, $0.36/million Class B operations; 10 GB-month, 1 million Class A and 10 million Class B operations included. R2 egress is free, but that does **not** mean Containers egress is free.[C38]
- **Containers egress:** listed overage rates are $0.025/GB in North America/Europe, $0.05/GB in Oceania/Korea/Taiwan and $0.04/GB elsewhere, with regional included allotments. Relay traffic contributes to the relevant network usage.[C41]
- **Workers and Durable Objects:** billed separately from container resources. Keep-alive/control activity can incur DO duration; do not assume it is always hibernated or free.[C42]
- **Workflows:** step/storage billing took effect on **10 August 2026**. Paid includes 500,000 steps/month and 1 GB-month; overage is $0.80/100,000 steps and $0.20/GB-month, plus Workers request/CPU pricing. Avoid returning bundles or secrets as workflow step state.[C43]
- **Models and relays:** provider inference charges and production Iroh relay capacity are additional. Actual agent/model usage can dominate compute cost.
- **Observability:** budget separately for logs/traces and retention; payload logging can expose source code or credentials. August's agent-tracing announcement schedules billing changes for 1 October 2026.[C15]

Use a hard workspace TTL, one-workspace concurrency cap for the MVP, bounded disk/output, retry limits, broker spend controls and cleanup reconciliation. The **Billable Usage API**, announced 3 August, is useful for reporting, but its data was documented as updated daily, so it is not a real-time kill switch.[C44]

## 12. Alternatives and a fallback recommendation

All alternatives below can keep **Herdr + agent + Attached publisher inside the remote workspace**. The developer still does not need to manage inbound ports or SSH; the orchestrator uses provider APIs and Attached remains the interaction path.

| Backend | Why consider it | Important caveats |
| --- | --- | --- |
| **Fly Machines + per-workspace Fly Volume** | Straightforward VM lifecycle API; container-image packaging; conventional Linux environment and persistent working disk. A strong first fallback for this PID. | Volumes are host-local, not automatically replicated; use R2/Git checkpoints. Root filesystem is ephemeral. Independently secure private networking and egress so malicious machines cannot reach other applications.[N03], [N04] |
| **E2B** | Purpose-built isolated Linux agent machines; documented pause/resume preserves filesystem **and memory**. Particularly relevant if true suspended-session recovery matters. | Current documented continuous runtime: **1 hour Base / 24 hours Pro**. Pause/resume can reset the window but interrupts execution; a paused agent is not working. Validate Iroh, credentials, pricing and network policy rather than assuming drop-in compatibility.[N05], [N06] |
| **Daytona VM sandboxes** | Documented Linux VM boundary, persistent filesystem, and VM-specific pause/resume/hot snapshots. Also offers container sandboxes. | Choose the **VM class** deliberately: container-class stop/start does not preserve RAM. Network policies vary by tier; confirm relay destinations are permitted. Validate provisioning, snapshot APIs and quotas for the chosen plan.[N07], [N08] |
| **Conventional VM: EC2 or equivalent** | Most control over size, disks, Linux tools and externally enforced network policy. Suitable when builds or privileges exceed sandbox limits. EC2 offers process-preserving hibernation on supported configurations. | More provisioning/IAM/patching/cleanup work; hibernation has prerequisites and incurs storage charges. No agent progress while hibernated. Block cloud metadata credentials and lateral network access; never attach a broad instance role.[N09] |
| **Modal Sandboxes** | Useful when GPU or specialized compute is a real requirement. | Current documentation gives a 24-hour maximum sandbox timeout and recommends filesystem snapshots for longer workflows; do not assume that preserves a live Herdr process.[N10] |

Memory snapshots also preserve secrets. Protect them as credentials, renew/revoke grants across resume, and expect expired network connections to reconnect. Never run two restored machines with the same Attached/Iroh endpoint private identity simultaneously.

### Preferred hybrid if Cloudflare compute fails validation

Keep **Workers + Workflows + DO + R2** as the control plane and use **Fly Machines** as the sole MVP compute backend. Start one machine per workspace, give it only scoped input/broker/publication capabilities, and retain the same Attached/Herdr experience. If preserving memory across deliberate suspension is decisive, evaluate E2B or Daytona's VM class first instead.

This remains a **one-backend MVP**. A narrow internal backend interface is sensible, but there is no need to ship provider selection or implement multiple providers now.

Changing compute providers does **not** fix Attached's account-wide publisher credential and revocation gaps. Those require the same protocol/lifecycle work in every architecture.

## 13. Proposed validation gates before implementation commitment

These are proposed tests for a future approved spike. **They were not run as part of this research.**

| Gate | Experiment and acceptance condition |
| --- | --- |
| **1. Exact runtime compatibility** | Run pinned Herdr, Attached and the chosen coding agent in a deployed Linux/amd64 sandbox. Verify PTY behavior, Unix sockets, signals, child cleanup and a representative repository build within resource limits. |
| **2. Attached relay under least privilege** | Connect from the existing account with UDP unavailable and deny-by-default egress. Prove WebSocket upgrade/TLS operation and reconnection without enabling general Internet access. |
| **3. Overnight independence** | Run at least 12 hours with the laptop offline and no client requests. Check keep-alive, external credential renewal, checkpoint timestamps and reconnect to the same surviving Herdr process. Repeat; one run is not a reliability guarantee. |
| **4. Destructive recovery** | Force idle stop, restart, OOM/kill and a deployment replacement. Retrieve the last complete checkpoint, identify the lost runtime accurately, and relaunch from durable data without claiming memory continuity. |
| **5. Publisher isolation/revocation** | A workspace cannot enumerate another session, mutate another publisher record, or connect as the owner. After destroy, replay its stolen token from a different machine and require rejection. |
| **6. Hostile network behavior** | Attempt unauthorized repos, redirects, raw IPs, alternate ports, IPv6, DNS tunneling, metadata/private destinations and direct broker requests. Test the effective policy, not just configuration values. |
| **7. Artifact durability and safety** | Include committed, uncommitted, binary, renamed and untracked files. Kill during upload; the previous manifest must remain valid. Test disk-full, unsafe archives and retrieval into a clean review worktree. |
| **8. Retry/cleanup faults** | Drop API responses during create/destroy; replay workflow steps; revoke during execution. No duplicate live agent, leaked indefinite resource or resurrected tombstoned workspace. |
| **9. Cost and UX** | Measure time-to-ready, actual CPU/disk consumption, relay latency and overnight cost. Verify the developer never enters an IP address, opens a port or sets up SSH. |

### Go / no-go

**Go with Cloudflare compute** if relay connectivity works under the accepted policy, representative projects fit the limits, durable recovery meets the agreed loss window, and workspace-scoped Attached revocation is designed and validated.

**Choose a VM backend** if session-memory preservation, larger disks/compute, unrestricted development tooling, or stronger network controls are necessary for the first target projects.

**Do not proceed to a security-compliant MVP** with shared non-revocable publisher credentials, laptop-driven keep-alives, final-export-only persistence, or an unsupported promise that “sleep resumes the same machine.”

## 14. Suggested reading order

For a quick independent review:

1. [Containers/Sandboxes GA][C01] and [current Containers limitations/lifetime][C03].
2. [Sandbox SDK 1.0 preview][C17] and [process/container lifetime semantics][C32].
3. [Cloudflare outbound traffic enforcement][C05] and [Iroh firewall/TLS requirements][N01].
4. [Sandbox backups][C08] versus [Computer's current production-readiness warning][C11].
5. [Artifacts availability][C14] and [repo token scope/revocation][C36].
6. [Current Attached authorization code][A06] and [unmerged unattended-bootstrap PR][A07].

Linked sources were consulted on **16 September 2026**. Announcement dates indicate release announcements; they are not assumed to supersede current availability warnings or prove compatibility with Attached.

[C01]: https://developers.cloudflare.com/changelog/post/2026-04-13-containers-sandbox-ga/
[C02]: https://developers.cloudflare.com/containers/concepts/architecture/
[C03]: https://developers.cloudflare.com/containers/faq/
[C04]: https://developers.cloudflare.com/sandbox/concepts/security/
[C05]: https://developers.cloudflare.com/containers/guides/outbound-traffic/
[C06]: https://blog.cloudflare.com/sandbox-auth/
[C07]: https://developers.cloudflare.com/sandbox/guides/docker-in-docker/
[C08]: https://developers.cloudflare.com/sandbox/guides/backup-restore/
[C09]: https://developers.cloudflare.com/containers/guides/execute-commands/
[C10]: https://blog.cloudflare.com/cloudflare-computer/
[C11]: https://github.com/cloudflare/computer/blob/main/README.md
[C12]: https://blog.cloudflare.com/grpc-workers/
[C13]: https://blog.cloudflare.com/ci-workflows/
[C14]: https://developers.cloudflare.com/artifacts/
[C15]: https://blog.cloudflare.com/agents-on-cloudflare/
[C16]: https://blog.cloudflare.com/kitesurf/
[C17]: https://developers.cloudflare.com/sandbox/1-0-preview/
[C18]: https://blog.cloudflare.com/workers-ai-gateway-unification/
[C19]: https://developers.cloudflare.com/sandbox/tutorials/cursor-cloud-agents/
[C20]: https://developers.cloudflare.com/sandbox/tutorials/openai-agents-api/
[C21]: https://developers.cloudflare.com/sandbox/tutorials/devin-outposts/
[C22]: https://developers.cloudflare.com/changelog/post/2026-09-10-paid-retention-default/
[C23]: https://developers.cloudflare.com/changelog/post/2026-09-15-instance-event-subscriptions/
[C24]: https://developers.cloudflare.com/workers/authorization/workers/
[C25]: https://developers.cloudflare.com/changelog/post/2026-09-14-guardrails/
[C26]: https://registry.npmjs.org/@cloudflare%2Fsandbox
[C27]: https://developers.cloudflare.com/sandbox/guides/2026-deprecation/
[C28]: https://developers.cloudflare.com/containers/platform/limits/
[C29]: https://developers.cloudflare.com/secrets-store/
[C30]: https://developers.cloudflare.com/dynamic-workers/
[C31]: https://developers.cloudflare.com/workers/runtime-apis/nodejs/
[C32]: https://developers.cloudflare.com/sandbox/1-0-preview/lifecycle/
[C33]: https://developers.cloudflare.com/sandbox/1-0-preview/processes/
[C34]: https://developers.cloudflare.com/sandbox/api/lifecycle/
[C35]: https://developers.cloudflare.com/sandbox/guides/mount-buckets/
[C36]: https://developers.cloudflare.com/artifacts/api/rest-api/
[C37]: https://developers.cloudflare.com/artifacts/platform/pricing/
[C38]: https://developers.cloudflare.com/r2/pricing/
[C39]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
[C40]: https://developers.cloudflare.com/containers/configuration/rollouts/
[C41]: https://developers.cloudflare.com/containers/platform/pricing/
[C42]: https://developers.cloudflare.com/durable-objects/platform/pricing/
[C43]: https://developers.cloudflare.com/workflows/reference/pricing/
[C44]: https://blog.cloudflare.com/billable-usage-api/
[C45]: https://registry.npmjs.org/@cloudflare%2Fcontainers
[C46]: https://registry.npmjs.org/@cloudflare%2Fcomputer
[C47]: https://registry.npmjs.org/@cloudflare%2Fci
[C48]: https://developers.cloudflare.com/artifacts/platform/limits/
[C49]: https://developers.cloudflare.com/changelog/post/2026-03-24-dynamic-workers-open-beta/
[C50]: https://developers.cloudflare.com/kv/concepts/how-kv-works/
[A01]: https://github.com/pvalletbo/attached/blob/d334f7d75eb2b58059e9deeaaa73a61e799a476c/crates/session-sync-worker/wrangler.toml
[A02]: https://github.com/pvalletbo/attached/blob/d334f7d75eb2b58059e9deeaaa73a61e799a476c/crates/cli/src/publish_account.rs
[A03]: https://github.com/pvalletbo/attached/blob/d334f7d75eb2b58059e9deeaaa73a61e799a476c/crates/cli/src/server.rs
[A04]: https://github.com/pvalletbo/attached/blob/d334f7d75eb2b58059e9deeaaa73a61e799a476c/crates/cli/src/sync/publisher.rs
[A05]: https://github.com/pvalletbo/attached/blob/d334f7d75eb2b58059e9deeaaa73a61e799a476c/images/application-runtime/Dockerfile
[A06]: https://github.com/pvalletbo/attached/blob/d334f7d75eb2b58059e9deeaaa73a61e799a476c/crates/session-sync-worker/src/api.rs
[A07]: https://github.com/pvalletbo/attached/pull/88
[A08]: https://github.com/pvalletbo/attached/blob/d334f7d75eb2b58059e9deeaaa73a61e799a476c/crates/session-sync-worker/src/model.rs
[A09]: https://github.com/pvalletbo/attached/blob/d334f7d75eb2b58059e9deeaaa73a61e799a476c/crates/cli/src/local_encryption.rs
[A10]: https://github.com/pvalletbo/attached/blob/d334f7d75eb2b58059e9deeaaa73a61e799a476c/crates/session-sync-protocol/src/account.rs
[N01]: https://docs.iroh.computer/configuring-networks
[N02]: https://docs.iroh.computer/concepts/relays
[N03]: https://fly.io/docs/machines/overview/
[N04]: https://fly.io/docs/volumes/overview/
[N05]: https://e2b.dev/docs/sandbox
[N06]: https://e2b.dev/docs/sandbox/persistence
[N07]: https://www.daytona.io/docs/en/persistence/
[N08]: https://www.daytona.io/docs/en/isolation/
[N09]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Hibernate.html
[N10]: https://modal.com/docs/guide/sandbox
