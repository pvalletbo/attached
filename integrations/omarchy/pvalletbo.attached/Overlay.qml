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
  property bool requestActive: false
  property bool catalogExited: false
  property bool catalogCollected: false
  property int catalogExitCode: -1
  property string catalogOutput: ""
  property string errorText: ""
  property var sessions: []
  property var filteredSessions: []
  property int selectedIndex: 0

  // Omarchy calls open(payloadJson) when `omarchy-shell shell summon` or
  // `toggle` loads this overlay. The payload is unused, but keeping the standard
  // signature makes the plugin fit the same lifecycle as built-in overlays.
  function open(payloadJson) {
    root.opened = true
    searchInput.text = ""
    root.selectedIndex = 0
    root.refreshCatalog()
    Qt.callLater(function() { searchInput.forceActiveFocus() })
  }

  // Host-initiated close. It stops the bounded refresh and resets transient UI;
  // user actions call dismiss(), which updates Omarchy's open-panel set first.
  function close() {
    root.opened = false
    root.requestActive = false
    root.loading = false
    refreshDeadline.stop()
    if (catalogProcess.running)
      catalogProcess.running = false
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

  function refreshCatalog() {
    // One Process instance means refreshes cannot overlap. This prevents a slow
    // older request from replacing a newer catalog after the overlay reopens.
    if (catalogProcess.running)
      return
    root.loading = true
    root.requestActive = true
    root.catalogExited = false
    root.catalogCollected = false
    root.catalogExitCode = -1
    root.catalogOutput = ""
    root.errorText = ""
    catalogProcess.running = true
    refreshDeadline.restart()
  }

  function finishCatalogLoad() {
    if (!root.requestActive || !root.catalogExited || !root.catalogCollected)
      return

    root.requestActive = false
    root.loading = false
    refreshDeadline.stop()
    if (root.catalogExitCode !== 0) {
      root.errorText = "Attached could not refresh sessions (exit " + root.catalogExitCode + "). Press Ctrl+R to retry."
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
    if (index < 0 || index >= root.filteredSessions.length)
      return
    var row = root.filteredSessions[index]
    // execDetached receives an argv array. No shell parses the remote session
    // label, so spaces and metacharacters remain ordinary target characters.
    var command = SessionModel.terminalCommand(row)
    Quickshell.execDetached(command)
    console.info("attached-picker event=session_launch_requested")
    root.dismiss()
  }

  Process {
    id: catalogProcess
    command: ["attached", "sessions", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.catalogOutput = text
        root.catalogCollected = true
        root.finishCatalogLoad()
      }
    }
    onExited: function(exitCode, exitStatus) {
      if (!root.requestActive)
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
      root.errorText = "Attached took too long to refresh sessions. Press Ctrl+R to retry."
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
      id: drawer
      anchors.top: parent.top
      anchors.bottom: parent.bottom
      anchors.right: parent.right
      width: Math.min(Style.space(520), parent.width)
      color: Color.menu.background
      borderSpec: Border.surfaceSpec("menu", "border", Color.menu.border, Math.max(1, Style.space(2)))
      padding: Style.spacing.panelPadding

      // Consume clicks inside the drawer so the fullscreen dismiss area only
      // closes the overlay when the user clicks outside it.
      MouseArea { anchors.fill: parent; onClicked: {} }

      Column {
        anchors.fill: parent
        anchors.topMargin: drawer.contentTopInset
        anchors.rightMargin: drawer.contentRightInset
        anchors.bottomMargin: drawer.contentBottomInset
        anchors.leftMargin: drawer.contentLeftInset
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
            onTextChanged: {
              root.selectedIndex = 0
              root.rebuildResults()
            }

            Keys.priority: Keys.BeforeItem
            Keys.onPressed: function(event) {
              if (event.key === Qt.Key_Escape) {
                if (searchInput.text.length > 0)
                  searchInput.text = ""
                else
                  root.dismiss()
                event.accepted = true
              } else if (event.key === Qt.Key_Up) {
                root.moveSelection(-1)
                event.accepted = true
              } else if (event.key === Qt.Key_Down) {
                root.moveSelection(1)
                event.accepted = true
              } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                root.activate(root.selectedIndex)
                event.accepted = true
              } else if (event.key === Qt.Key_R && (event.modifiers & Qt.ControlModifier)) {
                root.refreshCatalog()
                event.accepted = true
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: searchInput.text.length === 0
              anchors.fill: parent
              text: "Search Attached sessions…"
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
            visible: !root.loading && !root.errorText && root.filteredSessions.length > 0
            model: root.filteredSessions
            spacing: Style.space(4)
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            delegate: Rectangle {
              id: row
              required property int index
              required property var modelData
              width: ListView.view.width
              height: Math.max(Style.space(62), Style.font.title + Style.font.caption + Style.spacing.rowPaddingX * 2)
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
                  text: row.modelData.session
                  color: row.index === root.selectedIndex ? Color.menu.selectedText : Color.menu.text
                  font.family: Style.font.menuFamily
                  font.pixelSize: Style.font.title
                  elide: Text.ElideRight
                }
                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: row.modelData.host
                  color: row.index === root.selectedIndex ? Color.menu.selectedText : Color.menu.text
                  opacity: 0.65
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
            visible: root.loading || root.errorText || root.filteredSessions.length === 0
            text: root.loading ? "Refreshing Attached sessions…"
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
