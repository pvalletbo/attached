# Record an Attached demo in a single terminal.
#
# Assumptions:
#   - Run this tape from the repository root.
#   - A Docker-compatible daemon is running.
#   - The local `ubuntu-herdr` image was built from
#     `demo/Dockerfile.ubuntu-herdr`.
#   - Network access is available while installing Attached in the running demo
#     container.
#   - The local Attached account is configured.
#   - Both the local account and the container use `1234` for local encryption.
#   - The host has attached, herdr, fzf, pbpaste, and pbcopy on PATH.
#
# The publish bundle is exported to the clipboard and passed to Docker through
# ATTACHED_PUBLISH_BUNDLE. Password and bundle values are never rendered. The
# environment variable and clipboard are cleared during cleanup.

Output demo/attached-demo.mp4

Require docker
Require attached
Require herdr
Require fzf
Require pbpaste
Require pbcopy

Set Shell "bash"
Set Width 1920
Set Height 1080
Set FontSize 28
Set Framerate 30
Set TypingSpeed 25ms
Set WaitTimeout 8m
Set Theme "Dracula"
Set Padding 24
Set WindowBar Colorful
Set WindowBarSize 40
Set BorderRadius 10

# Start from one clean local prompt while capture is paused. Attached itself is
# deliberately installed later, on screen, inside the running demo container.
# Cleanup is registered for failed runs.
Hide
Type `docker rm -f attached-demo >/dev/null 2>&1 || true; export PS1='local$ '; trap 'docker stop attached-demo >/dev/null 2>&1 || true; unset ATTACHED_PUBLISH_BUNDLE; printf "" | pbcopy' EXIT; clear`
Enter
Wait+Line /local[$]/
Show
Sleep 1s

# Export a publish-only bundle. Attached keeps the secret out of the terminal and
# places it on the clipboard temporarily.
Type `attached account export --type publish`
Sleep 300ms
Enter
Sleep 500ms
Wait+Screen /Attached encryption password:/
Sleep 300ms
Type "1234"
Enter
Sleep 1s
Wait+Screen /Account bundle copied to the clipboard/
Wait+Line /local[$]/
Sleep 1s

# Read the bundle from the clipboard without displaying it, then pass it into
# one foreground Docker shell.
Type `export ATTACHED_PUBLISH_BUNDLE="$(pbpaste)"`
Sleep 300ms
Enter
Wait+Line /local[$]/
Sleep 700ms

Type `docker run --rm -it --name attached-demo -e ATTACHED_PUBLISH_BUNDLE ubuntu-herdr`
Sleep 300ms
Enter
Sleep 500ms
Wait+Line /root@.*#/
Sleep 700ms

# Herdr is already installed in the image, so its version is the first command
# run in the container.
Type `herdr --version`
Sleep 300ms
Enter
Sleep 300ms
Wait+Line /root@.*#/
Sleep 700ms

# Install Attached in the container.
Type `curl --proto '=https' --tlsv1.2 -LsSf https://install.attached.sh | sh`
Sleep 300ms
Enter
Sleep 500ms
Wait+Line /root@.*#/
Sleep 1s

# Start serving with the publish bundle inherited from Docker. This fresh
# container creates encrypted local state with the same demo password.
Type `attached serve --host-label "docker-$HOSTNAME"`
Sleep 300ms
Enter
Sleep 500ms
Wait+Screen /Create Attached encryption password:/
Sleep 300ms
Type "1234"
Enter
Sleep 500ms
Wait+Screen /Confirm Attached encryption password:/
Sleep 300ms
Type "1234"
Enter
Sleep 1s
Wait+Screen /Serving synchronized Herdr sessions as/
Sleep 2s

# Keep Attached running as a background job in the container shell.
Ctrl+Z
Sleep 700ms
Wait+Line /root@.*#/
Type "bg"
Sleep 300ms
Enter
Sleep 500ms
Wait+Line /root@.*#/
Sleep 1s

# Create Herdr's default session and leave recognizable output in its shell pane.
Type "herdr"
Sleep 300ms
Enter
Sleep 1s
Wait+Screen /(agents[ ]+grouped|tab[ ]+1)/
Sleep 1s

Type `echo "hello from inside Docker"`
Sleep 300ms
Enter
Sleep 3s

# Detach the Herdr client while its session keeps running in the container.
Ctrl+B
Sleep 150ms
Type "q"
Sleep 1s
Wait+Line /root@.*#/
Sleep 700ms

# Detach from Docker without stopping its shell, Attached server, or Herdr
# session. Exiting the shell here would stop the container.
Ctrl+P
Sleep 150ms
Ctrl+Q
Sleep 700ms
Wait+Line /local[$]/
Sleep 1s

# Discover the synchronized Docker session from the local computer.
Type "attached attach"
Sleep 300ms
Enter
Sleep 500ms
Wait+Screen /Attached encryption password:/
Sleep 300ms
Type "1234"
Enter
Sleep 1s
Wait+Screen /Herdr session>/
Sleep 700ms
Type "docker"
Sleep 2s
Enter
Sleep 5s
Wait+Screen /hello from inside Docker/
Sleep 3s

Type `echo "now attached from the local computer"`
Sleep 300ms
Enter
Sleep 4s

# Detach and remove only resources created by this tape. Cleanup is not recorded.
Hide
Ctrl+B
Sleep 150ms
Type "q"
Sleep 1s
Wait+Line /local[$]/
Type `docker stop attached-demo >/dev/null 2>&1 || true; unset ATTACHED_PUBLISH_BUNDLE; printf '' | pbcopy; trap - EXIT`
Enter
Sleep 1s
