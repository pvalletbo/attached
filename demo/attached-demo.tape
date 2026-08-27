# Record a two-pane Attached demo.
#
# Assumptions:
#   - Run this tape from the repository root.
#   - Docker Desktop is running.
#   - publish.bundle exists in the repository root.
#   - The host has attached, herdr, fzf, tmux, and pbcopy on PATH.
#
# The publish bundle is pasted with terminal echo disabled so the credential is
# never rendered into the recording. The clipboard is cleared during cleanup.

Output demo/attached-demo.mp4

Require docker
Require attached
Require herdr
Require fzf
Require tmux
Require pbcopy

Set Shell "bash"
Set Width 1920
Set Height 1080
Set FontSize 24
Set Framerate 30
Set TypingSpeed 25ms
Set WaitTimeout 8m
Set Theme "TokyoNightStorm"
Set Padding 24
Set WindowBar Colorful
Set WindowBarSize 40
Set BorderRadius 10

# Prepare a private tmux server while capture is paused. Recording starts only
# after both vertical panes exist, so every captured frame has the split layout.
# Named ANSI colors keep tmux's labels and borders tied to the VHS theme.
Hide
Type `test -r publish.bundle || { printf 'publish.bundle is missing\n' >&2; exit 1; }; printf 'onboarding = false\n\n[theme]\nname = "tokyo-night"\n' > /tmp/attached-vhs-herdr.toml; tmux -L attached-vhs kill-server >/dev/null 2>&1 || true; tmux -L attached-vhs -f /dev/null new-session -d -s attached-demo -c "$PWD" "env BASH_SILENCE_DEPRECATION_WARNING=1 HERDR_CONFIG_PATH=/tmp/attached-vhs-herdr.toml PS1='consumer$ ' bash --noprofile --norc -i"; tmux -L attached-vhs -f /dev/null split-window -h -t attached-demo:0 -c "$PWD" "env BASH_SILENCE_DEPRECATION_WARNING=1 PS1='publisher$ ' bash --noprofile --norc -i"; tmux -L attached-vhs set-option -t attached-demo status off; tmux -L attached-vhs set-window-option -t attached-demo:0 pane-border-status top; tmux -L attached-vhs set-window-option -t attached-demo:0 pane-border-format " #[fg=brightblack]#{?pane_active,●,○} #{pane_title} #[default]"; tmux -L attached-vhs set-window-option -t attached-demo:0 pane-active-border-style "fg=blue"; tmux -L attached-vhs set-window-option -t attached-demo:0 pane-border-style "fg=black"; tmux -L attached-vhs set-window-option -t attached-demo:0 allow-rename off; tmux -L attached-vhs select-pane -t attached-demo:0.0 -T CONSUMER; tmux -L attached-vhs select-pane -t attached-demo:0.1 -T PUBLISHER; tmux -L attached-vhs select-pane -t attached-demo:0.1; tmux -L attached-vhs attach-session -t attached-demo`
Enter
Wait+Line /publisher[$]/
Show
Sleep 1s

# Publisher: start a stock Ubuntu container. Package and Herdr setup execute
# while capture is paused; only Attached's installation is shown to viewers.
Type `docker run --rm -it --name attached-demo ubuntu:24.04`
Sleep 300ms
Enter
Sleep 500ms
Hide
Wait+Line /root@.*#/

Type "apt update"
Enter
Sleep 300ms
Wait+Line /root@.*#/

Type "apt-get install -y curl ca-certificates xz-utils"
Enter
Sleep 300ms
Wait+Line /root@.*#/

Type "curl -fsSL https://herdr.dev/install.sh | sh"
Enter
Sleep 300ms
Wait+Line /root@.*#/

Type `export PATH="/root/.local/bin:$PATH"`
Enter
Sleep 300ms
Wait+Line /root@.*#/

Type `mkdir -p "$HOME/.config/herdr" && printf 'onboarding = false\n\n[theme]\nname = "tokyo-night"\n' > "$HOME/.config/herdr/config.toml"`
Enter
Sleep 300ms
Wait+Line /root@.*#/

Type "clear"
Enter
Sleep 300ms
Wait+Line /root@.*#/
Show
Sleep 700ms

Type "herdr --version"
Sleep 300ms
Enter
Sleep 300ms
Wait+Line /root@.*#/
Sleep 700ms

Type `curl --proto '=https' --tlsv1.2 -LsSf https://install.attached.sh | sh`
Sleep 300ms
Enter
Sleep 500ms
Wait+Line /root@.*#/
Sleep 700ms

Type "source $HOME/.cargo/env"
Sleep 300ms
Enter
Sleep 300ms
Wait+Line /root@.*#/
Sleep 700ms

# Consumer: place the publisher-scoped bundle on the macOS clipboard.
Ctrl+B
Left
Wait+Line /consumer[$]/
Sleep 700ms
Type "cat publish.bundle | pbcopy"
Sleep 300ms
Enter
Sleep 300ms
Wait+Line /consumer[$]/
Sleep 700ms

# Publisher: import the bundle. stty disables echo only while Attached reads it.
Ctrl+B
Right
Wait+Line /root@.*#/
Sleep 700ms
Type "stty -echo; attached account import --bundle-stdin"
Sleep 300ms
Enter
Sleep 500ms
Paste
Sleep 500ms
Enter
Sleep 500ms
Wait+Line /root@.*#/
Type `stty echo; printf '\n'`
Enter
Sleep 300ms
Wait+Line /root@.*#/
Sleep 700ms

# Create Herdr's default session interactively and leave recognizable output in
# its shell pane. That same pane will later appear on the consumer unchanged.
Type "herdr"
Sleep 300ms
Enter
Sleep 1s
Wait+Screen /(agents[ ]+grouped|tab[ ]+1)/
Sleep 1s

Type `echo "hello from inside the Docker publisher"`
Sleep 300ms
Enter
Sleep 2s

# Herdr is nested inside the recording's outer tmux. The first two Ctrl+B keys
# make tmux forward one Ctrl+B to Herdr; q then detaches the Herdr client while
# its default session keeps running in the container.
Ctrl+B
Sleep 150ms
Ctrl+B
Sleep 150ms
Type "q"
Sleep 1s
Wait+Line /root@.*#/
Sleep 700ms

# Give the publisher pane a distinct prompt so readiness checks cannot match
# the prompt inside the remote Herdr pane.
Type "export PS1='publisher# '"
Sleep 300ms
Enter
Sleep 300ms
Wait+Line /publisher#/
Sleep 700ms

Type `attached serve --host-label "docker-demo-video-$HOSTNAME"`
Sleep 300ms
Enter
Sleep 1s
Wait+Screen /Serving synchronized Herdr sessions as/
Sleep 2s

# Consumer: discover the synchronized session and select it by typing `video`.
Ctrl+B
Left
Wait+Line /consumer[$]/
Sleep 700ms
Type "attached attach"
Sleep 300ms
Enter
Sleep 1s
Wait+Screen /Herdr session>/
Sleep 700ms
Type "video"
Sleep 2s
Enter
Sleep 1s
Wait+Screen /(agents[ ]+grouped|tab[ ]+1)/
Sleep 3s

Type `echo "now typing from the consumer"`
Sleep 300ms
Enter
Sleep 4s

# Tear down only resources created by this tape. Cleanup is not recorded.
Hide
Ctrl+B
Right
Sleep 300ms
Ctrl+C
Sleep 500ms
Wait+Line /publisher#/
Type "exit"
Enter
Sleep 500ms
Wait+Line /publisher[$]/
Type `printf '' | pbcopy; rm -f /tmp/attached-vhs-herdr.toml; tmux -L attached-vhs kill-session -t attached-demo`
Enter
Sleep 1s
