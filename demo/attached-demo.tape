# Run from the repository root via: python3 demo/record.py
# Client: installed macOS/Linux binaries, fresh isolated account on hosted service.
# Remote: Docker with latest Herdr; Attached is installed below, not in the image.
# 1234 is only for this disposable demo. Neither bundle nor password is echoed.
# The file transfer uses Docker because this demo has no preexisting SSH access.
# With a real remote, securely transfer publish.bundle to that machine instead.
# tmux is only the recording's terminal-tab switcher (Ctrl+A, window number).

Output demo/attached-demo.gif
Output demo/.artifacts/attached-demo.mp4
Output demo/.artifacts/attached-demo.txt

Require tmux
Require attached
Require herdr
Require docker

Set Shell "bash"
Set Width 1600
Set Height 960
Set FontSize 24
Set LineHeight 1.15
Set Framerate 15
Set TypingSpeed 25ms
Set WaitTimeout 90s
Set Theme "Catppuccin Mocha"
Set Padding 24
Set Margin 24
Set MarginFill "#16161e"
Set WindowBar Rings
Set BorderRadius 16
Set CursorBlink false

Hide
Type@1ms `tmux -S "$DEMO_TMUX_SOCKET" attach-session -t demo`
Enter
Wait+Line /client.*[$]/
Show
Sleep 1s
Type "# 1. Client: create your Attached account"
Enter
Type "attached account create"
Enter
Wait+Line /Create Attached encryption password:/
Sleep 500ms
Type "1234"
Enter
Wait+Line /Confirm Attached encryption password:/
Type "1234"
Enter
Wait+Screen /Account created and saved in encrypted local state/
Wait+Line /client.*[$]/
Sleep 4s

Type "attached account export --type publish --output publish.bundle"
Enter
Wait+Line /Attached encryption password:/
Type "1234"
Enter
Wait+Screen /Account bundle written to publish.bundle/
Wait+Line /client.*[$]/
Sleep 2s
Type "# Transfer only the publish bundle to the remote machine"
Enter
Type "docker cp publish.bundle attached-demo-office:/root/publish.bundle"
Enter
Wait+Line /client.*[$]/
Sleep 1s
Screenshot demo/.artifacts/01-account.png
Sleep 1s

Ctrl+A
Type "2"
Wait+Line /office.*[$]/
Sleep 500ms
Type "# 2. Remote: install Attached (Herdr is already installed)"
Enter
Type "herdr --version"
Enter
Wait+Line /office.*[$]/
Type `curl --proto '=https' --tlsv1.2 -LsSf https://install.attached.sh | sh`
Enter
Sleep 1s
# Cut only unbounded download time, not any setup commands or their results.
Hide
Wait+Line /office.*[$]/
Show
Sleep 2s
Type "attached serve --host-label office --bundle-file publish.bundle"
Enter
Wait+Line /Create Attached encryption password:/
Type "1234"
Enter
Wait+Line /Confirm Attached encryption password:/
Type "1234"
Enter
Wait+Screen /Serving Attached SSH tunnels as/
Sleep 3s
Screenshot demo/.artifacts/02-serving.png
Sleep 1s

# Leave serve running in the remote terminal. Open another client terminal.
Ctrl+A
Type "3"
Wait+Line /client.*[$]/
Type "# 3. Client: expose SSH, and keep this terminal running"
Enter
Type "attached export-ssh-config"
Enter
Wait+Line /Attached encryption password:/
Type "1234"
Enter
Wait+Screen /Ready: ssh attached-office/
Sleep 4s
Screenshot demo/.artifacts/03-forwarding.png
Sleep 1s

Ctrl+A
Type "1"
Wait+Line /client.*[$]/
Ctrl+L
Type "# 4. Client: add the remote machine to Herdr"
Enter
Type "herdr machine add attached-office --label Office"
Enter
Wait+Screen /Remote server is ready/
Wait+Line /client.*[$]/
Sleep 3s
Screenshot demo/.artifacts/04-machine-added.png
Sleep 1s
Type "herdr"
Enter
Wait+Screen /machines/
Wait+Screen /Office/
Sleep 4s
Screenshot demo/.artifacts/05-machines.png
Sleep 1s

# Use Herdr's real session navigator to select the remote workspace.
Ctrl+B
Type "g"
Sleep 500ms
Type "/Office"
Sleep 1s
Enter
Wait+Screen /office.*[$]/
Sleep 1s
Type `printf 'Hello from %s!\n' "$(hostname)"`
Enter
Wait+Screen /Hello from office!/
Sleep 6s
Screenshot demo/.artifacts/06-remote-terminal.png
Sleep 1s

# Leave cleanup to record.py; it also runs after any failed wait.
