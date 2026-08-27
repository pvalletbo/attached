# Attached

Attach to remote Herdr session no matter where they run. No networking setup required!

## Demo

[![Attached terminal demo showing a consumer connected to a Herdr session running in Docker](demo/attached-demo.gif)](demo/attached-demo.mp4)

[Watch the full terminal demo (MP4)](demo/attached-demo.mp4) · [View the VHS tape](demo/attached-demo.tape)

## Synchronized session liveness

A serving host republishes its synchronized-session descriptor every 30 seconds. Descriptors
expire after 90 seconds, so a host that stops publishing disappears from refreshed clients
within a minute and a half while healthy hosts retain two retry windows.

When `attached attach HOST/SESSION` cannot reach or authenticate the selected remote endpoint,
Attached removes that exact descriptor revision from its local catalog. A concurrently
republished, newer revision is retained. Run the normal session refresh again to restore a
session after its publisher comes back.
