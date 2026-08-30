import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "pages"
import PreScan

ApplicationWindow {
    id: appWindow
    width: 960
    height: 660
    visible: true
    title: qsTr("PreScan")
    color: th.bg

    // ---- Theme (dark / light / system) --------------------------------- //
    property string mode: Bridge.theme            // "dark" | "light" | "system"
    property bool systemDark: Application.styleHints.colorScheme === Qt.ColorScheme.Dark
    property bool dark: mode === "dark" || (mode === "system" && systemDark)

    property QtObject th: QtObject {
        readonly property color bg: appWindow.dark ? "#1B1B1F" : "#F5F5F7"
        readonly property color card: appWindow.dark ? "#25252A" : "#FFFFFF"
        readonly property color border: appWindow.dark ? "#33333A" : "#E0E0E5"
        readonly property color text: appWindow.dark ? "#F2F2F5" : "#1B1B1F"
        readonly property color subtext: appWindow.dark ? "#9A9AA5" : "#6E6E78"
        readonly property color accent: "#0A84FF"
        readonly property color safe: appWindow.dark ? "#2ECC71" : "#1E9E57"
        readonly property color suspicious: appWindow.dark ? "#F5A623" : "#C77700"
        readonly property color dangerous: appWindow.dark ? "#E5484D" : "#C62A2E"
        readonly property color unknown: appWindow.dark ? "#6E6E78" : "#8A8A94"
    }

    property int page: 0

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // ---- Navigation rail ------------------------------------------- //
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: 200
            color: appWindow.dark ? "#202024" : "#ECECEF"
            border.color: appWindow.th.border

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 8
                spacing: 4

                Label {
                    text: "🛡  PreScan"
                    color: appWindow.th.text
                    font.pixelSize: 18
                    font.bold: true
                    Layout.margins: 8
                }

                Repeater {
                    model: [qsTr("Scan"), qsTr("History"), qsTr("Quarantine"),
                            qsTr("Settings"), qsTr("About")]
                    delegate: Button {
                        required property int index
                        required property string modelData
                        Layout.fillWidth: true
                        flat: true
                        text: modelData
                        highlighted: appWindow.page === index
                        onClicked: {
                            appWindow.page = index
                            if (index === 1) Bridge.loadHistory()
                            if (index === 2) Bridge.loadQuarantine()
                        }
                        contentItem: Label {
                            text: parent.text
                            color: parent.highlighted ? appWindow.th.accent : appWindow.th.text
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }
                Item { Layout.fillHeight: true }
            }
        }

        // ---- Page host ------------------------------------------------- //
        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: appWindow.page

            ScanPage { theme: appWindow.th; win: appWindow }
            HistoryPage { theme: appWindow.th }
            QuarantinePage { theme: appWindow.th }
            SettingsPage { theme: appWindow.th; win: appWindow }
            AboutPage { theme: appWindow.th }
        }
    }
}
