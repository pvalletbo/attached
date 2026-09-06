import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "SessionModel.js" as SessionModel

Item {
  id: root

  // Omarchy injects these host objects for third-party panels. User-initiated
  // dismissal routes through shell.hide so the host's toggle state remains in sync.
  property var shell: null
  property var manifest: null

  property bool opened: false
  property bool loading: false
  property bool awaitingPassword: false
  property bool requestActive: false
  property bool refreshPending: false
  property bool catalogStarted: false
  property bool catalogExited: false
  property bool catalogCollected: false
  property bool catalogErrorCollected: false
  property bool catalogResponseTooLarge: false
  property int catalogExitCode: -1
  property string catalogOutput: ""
  property string catalogErrorOutput: ""
  readonly property int maxCatalogOutputCharacters: 4 * 1024 * 1024
  readonly property int maxCatalogErrorCharacters: 64 * 1024
  property string pendingPassword: ""
  property string errorText: ""
  property string encryptionPasswordProvider: "password"
  property string configHome: {
    var configured = String(Quickshell.env("XDG_CONFIG_HOME") || "")
    return configured.length > 0 ? configured : String(Quickshell.env("HOME")) + "/.config"
  }
  property var sessions: []
  property var filteredSessions: []
  property int selectedIndex: 0

  // Omarchy calls open(payloadJson) when `omarchy-shell shell summon` or
  // `toggle` loads this overlay. The payload is unused, but keeping the standard
  // signature makes the plugin fit the same lifecycle as built-in overlays.
  function open(payloadJson) {
    root.opened = true
    searchInput.text = ""
    root.pendingPassword = ""
    root.clearCatalog()
    root.refreshConfiguredCatalog()
    Qt.callLater(function() { searchInput.forceActiveFocus() })
  }

  // Host-initiated close. It stops the bounded refresh and resets transient UI;
  // user actions call dismiss(), which updates Omarchy's open-panel set first.
  function close() {
    root.opened = false
    root.requestActive = false
    root.refreshPending = false
    root.catalogStarted = false
    root.loading = false
    root.awaitingPassword = false
    root.pendingPassword = ""
    root.clearCatalog()
    searchInput.text = ""
    refreshDeadline.stop()
    if (catalogProcess.running)
      catalogProcess.running = false
  }

  function clearCatalog() {
    root.sessions = []
    root.filteredSessions = []
    root.selectedIndex = 0
  }

  function dismiss() {
    if (root.shell && typeof root.shell.hide === "function")
      root.shell.hide((root.manifest && root.manifest.id) || "pvalletbo.attached")
    else
      root.close()
  }

  function toggle() {
    if (root.opened)
      root.dismiss()
    else
      root.open("{}")
  }

  function refreshConfiguredCatalog() {
    try {
      root.encryptionPasswordProvider = SessionModel.encryptionPasswordProvider(configFile.text())
    } catch (error) {
      root.loading = false
      root.awaitingPassword = false
      root.clearCatalog()
      root.errorText = String(error) + ". Fix " + configFile.path + " and press Ctrl+R."
      console.warn("attached-picker event=config_invalid")
      return
    }
    root.refreshCatalog()
  }

  function refreshCatalog() {
    // One Process instance means refreshes cannot overlap. Cancel an older
    // request and wait for both of its collectors before starting the pending
    // refresh, so stale output cannot replace a newer catalog after reopen.
    if (catalogProcess.running) {
      root.requestActive = false
      root.refreshPending = true
      root.loading = true
      root.awaitingPassword = false
      root.pendingPassword = ""
      root.clearCatalog()
      refreshDeadline.stop()
      catalogProcess.running = false
      return
    }
    root.refreshPending = false
    searchInput.text = ""
    root.pendingPassword = ""
    root.clearCatalog()
    root.loading = root.encryptionPasswordProvider === "1password"
    root.awaitingPassword = root.encryptionPasswordProvider === "password"
    root.requestActive = true
    root.catalogStarted = false
    root.catalogExited = false
    root.catalogCollected = false
    root.catalogErrorCollected = false
    root.catalogResponseTooLarge = false
    root.catalogExitCode = -1
    root.catalogOutput = ""
    root.catalogErrorOutput = ""
    root.errorText = ""
    catalogProcess.running = true
    if (root.encryptionPasswordProvider === "1password")
      refreshDeadline.restart()
    Qt.callLater(function() { searchInput.forceActiveFocus() })
  }

  function submitEncryptionPassword() {
    if (!root.awaitingPassword || !catalogProcess.running || searchInput.text.length === 0)
      return
    root.pendingPassword = searchInput.text
    searchInput.text = ""
    root.awaitingPassword = false
    root.loading = true
    root.sendPendingPassword()
    refreshDeadline.restart()
  }

  function sendPendingPassword() {
    if (!root.catalogStarted || root.pendingPassword.length === 0)
      return
    // A second copy satisfies Attached's confirmation read if this catalog load
    // is also migrating legacy plaintext state to password encryption.
    catalogProcess.write(root.pendingPassword + "\n" + root.pendingPassword + "\n")
    root.pendingPassword = ""
  }

  function openOnePassword() {
    Quickshell.execDetached(["omarchy-launch-1password"])
    console.info("attached-picker event=one_password_open_requested")
  }

  function rejectOversizedCatalogResponse() {
    if (root.catalogResponseTooLarge)
      return
    root.catalogResponseTooLarge = true
    root.pendingPassword = ""
    if (catalogProcess.running)
      catalogProcess.running = false
  }

  function finishCatalogLoad() {
    if (!root.catalogExited || !root.catalogCollected || !root.catalogErrorCollected)
      return
    if (root.refreshPending) {
      root.refreshPending = false
      root.catalogOutput = ""
      root.catalogErrorOutput = ""
      Qt.callLater(function() {
        if (root.opened)
          root.refreshCatalog()
      })
      return
    }
    if (!root.requestActive)
      return

    root.requestActive = false
    root.loading = false
    root.awaitingPassword = false
    root.pendingPassword = ""
    searchInput.text = ""
    refreshDeadline.stop()
    if (root.catalogResponseTooLarge) {
      root.errorText = "Attached returned too much output. Run `attached sessions` in a terminal for details, then press Ctrl+R."
      root.catalogOutput = ""
      root.catalogErrorOutput = ""
      console.warn("attached-picker event=catalog_output_too_large")
      return
    }
    if (root.catalogExitCode !== 0) {
      root.errorText = SessionModel.catalogErrorMessage(
        root.catalogErrorOutput,
        root.catalogExitCode,
        root.encryptionPasswordProvider
      )
      root.catalogErrorOutput = ""
      console.warn("attached-picker event=catalog_failed exit_code=" + root.catalogExitCode)
      return
    }

    try {
      root.sessions = SessionModel.parseCatalog(root.catalogOutput)
      root.rebuildResults()
      console.info("attached-picker event=catalog_loaded count=" + root.sessions.length)
    } catch (error) {
      root.sessions = []
      root.filteredSessions = []
      root.selectedIndex = 0
      root.errorText = String(error) + ". Press Ctrl+R to retry."
      console.warn("attached-picker event=catalog_invalid")
    }
  }

  function rebuildResults() {
    root.filteredSessions = SessionModel.filterSessions(root.sessions, searchInput.text)
    if (root.filteredSessions.length === 0)
      root.selectedIndex = 0
    else
      root.selectedIndex = Math.max(0, Math.min(root.selectedIndex, root.filteredSessions.length - 1))
    Qt.callLater(function() {
      if (root.filteredSessions.length > 0)
        sessionList.positionViewAtIndex(root.selectedIndex, ListView.Contain)
    })
  }

  function moveSelection(delta) {
    if (root.filteredSessions.length === 0)
      return
    root.selectedIndex = (root.selectedIndex + delta + root.filteredSessions.length)
                         % root.filteredSessions.length
    sessionList.positionViewAtIndex(root.selectedIndex, ListView.Contain)
  }

  function activate(index) {
    if (!root.opened || root.requestActive || root.loading || root.awaitingPassword
        || root.errorText.length > 0 || index < 0 || index >= root.filteredSessions.length)
      return
    var row = root.filteredSessions[index]
    // execDetached receives an argv array. No shell parses the remote session
    // label, so spaces and metacharacters remain ordinary target characters.
    var command = SessionModel.terminalCommand(row, root.encryptionPasswordProvider)
    Quickshell.execDetached(command)
    console.info("attached-picker event=session_launch_requested")
    root.dismiss()
  }

  FileView {
    id: configFile
    path: root.configHome + "/attached/omarchy.json"
    blockLoading: true
    printErrors: false
  }

  Process {
    id: catalogProcess
    // Passwords travel over an anonymous stdin pipe and are cleared from the
    // overlay immediately. They never appear in process arguments or environment.
    command: SessionModel.catalogCommand(root.encryptionPasswordProvider)
    stdinEnabled: true
    stdout: StdioCollector {
      waitForEnd: false
      onDataChanged: {
        if (text.length > root.maxCatalogOutputCharacters)
          root.rejectOversizedCatalogResponse()
      }
      onStreamFinished: {
        root.catalogOutput = root.catalogResponseTooLarge ? "" : text
        root.catalogCollected = true
        root.finishCatalogLoad()
      }
    }
    stderr: StdioCollector {
      waitForEnd: false
      onDataChanged: {
        if (text.length > root.maxCatalogErrorCharacters)
          root.rejectOversizedCatalogResponse()
      }
      onStreamFinished: {
        root.catalogErrorOutput = root.catalogResponseTooLarge ? "" : text
        root.catalogErrorCollected = true
        root.finishCatalogLoad()
      }
    }
    onStarted: {
      root.catalogStarted = true
      root.sendPendingPassword()
    }
    onExited: function(exitCode, exitStatus) {
      root.catalogStarted = false
      if (!root.requestActive && !root.refreshPending)
        return
      root.catalogExitCode = exitCode
      root.catalogExited = true
      root.finishCatalogLoad()
    }
  }

  Timer {
    id: refreshDeadline
    interval: 20000
    repeat: false
    onTriggered: {
      if (!root.requestActive)
        return
      root.requestActive = false
      root.loading = false
      root.awaitingPassword = false
      root.pendingPassword = ""
      root.errorText = root.encryptionPasswordProvider === "1password"
        ? "Attached took too long to refresh sessions. Unlock 1Password (Ctrl+O to open it), then press Ctrl+R."
        : "Attached took too long to refresh sessions. Press Ctrl+R to re-enter the encryption password."
      if (catalogProcess.running)
        catalogProcess.running = false
      console.warn("attached-picker event=catalog_timeout")
    }
  }

  PanelWindow {
    id: panel
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    exclusionMode: ExclusionMode.Ignore
    WlrLayershell.namespace: "attached-session-picker"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive

    Rectangle {
      anchors.fill: parent
      color: Color.menu.scrim
    }

    MouseArea {
      anchors.fill: parent
      onClicked: root.dismiss()
    }

    BorderSurface {
      id: card
      anchors.centerIn: parent
      width: Math.min(Style.space(720), parent.width - Style.gapsOut * 2)
      height: Math.min(Style.space(560), parent.height - Style.gapsOut * 2)
      radius: Style.cornerRadius
      color: Color.menu.background
      borderSpec: Border.surfaceSpec("menu", "border", Color.menu.border, Math.max(1, Style.space(2)))
      padding: Style.spacing.panelPadding

      // The fullscreen layer provides reliable keyboard focus and outside-click
      // dismissal; this centered card is the always-open command palette.
      MouseArea { anchors.fill: parent; onClicked: {} }

      Column {
        anchors.fill: parent
        anchors.topMargin: card.contentTopInset
        anchors.rightMargin: card.contentRightInset
        anchors.bottomMargin: card.contentBottomInset
        anchors.leftMargin: card.contentLeftInset
        spacing: Style.spacing.panelGap

        Rectangle {
          width: parent.width
          height: Math.max(Style.space(46), Style.font.body + Style.spacing.inputPaddingY * 2)
          radius: Style.cornerRadius
          color: Color.menu.selectedBackground

          TextInput {
            id: searchInput
            anchors.fill: parent
            anchors.leftMargin: Style.spacing.controlPaddingX
            anchors.rightMargin: Style.spacing.controlPaddingX
            color: Color.menu.text
            selectionColor: Color.accent
            selectedTextColor: Color.background
            font.family: Style.font.menuFamily
            font.pixelSize: Style.font.heading
            verticalAlignment: TextInput.AlignVCenter
            clip: true
            focus: true
            echoMode: root.awaitingPassword ? TextInput.Password : TextInput.Normal
            inputMethodHints: root.awaitingPassword
              ? Qt.ImhSensitiveData | Qt.ImhNoPredictiveText
              : Qt.ImhNone
            onTextChanged: {
              if (!root.awaitingPassword) {
                root.selectedIndex = 0
                root.rebuildResults()
              }
            }

            Keys.priority: Keys.BeforeItem
            Keys.onPressed: function(event) {
              if (event.key === Qt.Key_Escape) {
                if (searchInput.text.length > 0)
                  searchInput.text = ""
                else
                  root.dismiss()
                event.accepted = true
              } else if (root.awaitingPassword
                         && (event.key === Qt.Key_Return || event.key === Qt.Key_Enter)) {
                root.submitEncryptionPassword()
                event.accepted = true
              } else if (!root.awaitingPassword
                         && (event.key === Qt.Key_Up
                             || (event.key === Qt.Key_P
                                 && (event.modifiers & Qt.ControlModifier)))) {
                root.moveSelection(-1)
                event.accepted = true
              } else if (!root.awaitingPassword
                         && (event.key === Qt.Key_Down
                             || (event.key === Qt.Key_N
                                 && (event.modifiers & Qt.ControlModifier)))) {
                root.moveSelection(1)
                event.accepted = true
              } else if (!root.awaitingPassword
                         && (event.key === Qt.Key_Return || event.key === Qt.Key_Enter)) {
                root.activate(root.selectedIndex)
                event.accepted = true
              } else if (!root.awaitingPassword && event.key === Qt.Key_R
                         && (event.modifiers & Qt.ControlModifier)) {
                root.refreshConfiguredCatalog()
                event.accepted = true
              } else if (!root.awaitingPassword && root.encryptionPasswordProvider === "1password"
                         && event.key === Qt.Key_O
                         && (event.modifiers & Qt.ControlModifier)) {
                root.openOnePassword()
                event.accepted = true
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: searchInput.text.length === 0
              anchors.fill: parent
              text: root.awaitingPassword
                ? "Attached encryption password…"
                : "Search hosts and sessions…"
              color: Color.menu.text
              opacity: 0.55
              font: searchInput.font
              verticalAlignment: Text.AlignVCenter
            }
          }
        }

        Item {
          width: parent.width
          height: parent.height - searchInput.height - parent.spacing

          ListView {
            id: sessionList
            anchors.fill: parent
            visible: !root.loading && !root.awaitingPassword && !root.errorText
              && root.filteredSessions.length > 0
            model: root.filteredSessions
            spacing: Style.space(4)
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            delegate: Rectangle {
              id: row
              required property int index
              required property var modelData
              width: ListView.view.width
              height: Math.max(
                Style.space(86),
                Style.font.heading + Style.font.body + Style.font.caption
                  + Style.spacing.rowPaddingX * 2 + Style.space(6)
              )
              radius: Style.cornerRadius
              color: index === root.selectedIndex ? Color.menu.selectedBackground : "transparent"

              Column {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.spacing.rowPaddingX
                anchors.rightMargin: Style.spacing.rowPaddingX
                spacing: Style.space(3)

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: row.modelData.host
                  color: row.index === root.selectedIndex ? Color.menu.selectedText : Color.menu.text
                  font.family: Style.font.menuFamily
                  font.pixelSize: Style.font.heading
                  font.weight: Font.Medium
                  elide: Text.ElideRight
                }
                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: row.modelData.session
                  color: row.index === root.selectedIndex ? Color.menu.selectedText : Color.menu.text
                  opacity: 0.78
                  font.family: Style.font.menuFamily
                  font.pixelSize: Style.font.body
                  elide: Text.ElideRight
                }
                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: SessionModel.metadataSummary(row.modelData)
                  color: row.index === root.selectedIndex ? Color.menu.selectedText : Color.menu.text
                  opacity: 0.55
                  font.family: Style.font.menuFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }
              }

              MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onEntered: root.selectedIndex = row.index
                onClicked: root.activate(row.index)
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            anchors.centerIn: parent
            width: parent.width - Style.spacing.panelPadding * 2
            visible: root.awaitingPassword || root.loading || root.errorText
              || root.filteredSessions.length === 0
            text: root.awaitingPassword ? "Enter your Attached encryption password and press Enter."
                 : root.loading ? "Refreshing Attached sessions…"
                 : root.errorText ? root.errorText
                 : root.sessions.length === 0 ? "No synchronized sessions are available."
                 : "No sessions match “" + searchInput.text + "”."
            color: Color.menu.text
            opacity: 0.72
            font.family: Style.font.menuFamily
            font.pixelSize: Style.font.title
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
          }
        }
      }
    }
  }
}
