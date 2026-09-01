# AGENTS.md

## Project documentation

The .md files of these documents are written by humans only, unless specifically stated in the document itself. 
Any collaboration from an AI agent must no result in updating, or creating, .md documents unless
explicitly told by the human operator. In that case, the document must state that an AI agent has
contributed to the document. 

## Agentic contributions

Whenever you implement a new change you should do the following. 

1. create a new worktree for that new feature using a new branch
2. make sure that the new feature/fix has the corresponding tests to verify it works as expected
3. commit using conventional commits and push to the new branch
4. create a new PR against main. The PR description must contain a brief explanation about what has been
done, and all the required details if the feature is complex. A human will review the PR so leave 
any required information for them.

## Performance verification with tracing flamegraphs

> AI contribution notice: This section was added by an AI agent at the explicit request of the human operator.

When investigating or verifying a performance issue, capture a tracing flamegraph rather than relying only
on total elapsed time. Profile an optimized build first; use a debug build only when reproducing a debug-only
installation or regression.

1. Build the exact revision under test and create a temporary output directory:

   ```bash
   cargo build --release -p attached --locked
   profile_dir=$(mktemp -d)
   ```

2. Run the exact slow command with `--flamegraph` and `-vv`. Keep command output and timing diagnostics
   separate. For example:

   ```bash
   target/release/attached -vv \
     --flamegraph "$profile_dir/attached.folded" \
     sessions list --use-1password \
     >/dev/null 2>"$profile_dir/timings.log"
   ```

   Substitute the command being investigated, such as `sessions --json --use-1password` or
   `attach HOST/SESSION --use-1password`. An `attach` profile is flushed only after the command exits, so
   end the attached session normally. If the binary does not recognize `--flamegraph`, use a revision that
   contains the tracing support before drawing conclusions about CPU, network, or idle time.

3. Render both an aggregate flamegraph and, for short CLI operations, a chronological flamechart:

   ```bash
   command -v inferno-flamegraph >/dev/null || \
     cargo install inferno --version 0.12.4 --locked
   inferno-flamegraph "$profile_dir/attached.folded" >"$profile_dir/attached.svg"
   inferno-flamegraph --flamechart "$profile_dir/attached.folded" \
     >"$profile_dir/attached-chart.svg"
   xdg-open "$profile_dir/attached.svg"
   ```

4. Inspect `timings.log` alongside the image. `time.busy` identifies work while a span was entered and
   `time.idle` exposes asynchronous waiting. Time shown under `all-threads` in the folded output is commonly
   async idle time; use the enclosing HTTP or connection span's close timing before labeling it as network
   latency.

5. Compare at least three equivalent before/after runs. Report the build profile, cold and warm behavior,
   wall-time range, dominant spans, invocation counts, and whether time is CPU work, synchronous subprocess
   waiting, or async idle/network waiting. Keep the state, account, service, and network conditions equivalent.

The folded output records application span names rather than span fields, but inspect all generated artifacts
before sharing them. Do not publish session output, credentials, item metadata, account or record identifiers,
or machine-specific paths. Do not commit generated profiles unless the human operator explicitly requests it.
