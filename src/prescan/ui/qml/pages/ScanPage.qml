import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import "../components"
import PreScan

Item {
    id: root
    property var theme
    property var win
    // "input" | "progress" | "result"
    property string phase: "input"

    Connections {
        target: Bridge
        function onScanStarted() { root.phase = "progress" }
        function onScanFinished() { root.phase = "result" }
    }

    FileDialog {
        id: fileDialog
        title: qsTr("Choose a file to scan")
        onAccepted: Bridge.scanFile(selectedFile.toString())
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 16

        RowLayout {
            Layout.fillWidth: true
            Label {
                text: qsTr("PreScan"); color: theme.text
                font.pixelSize: 22; font.bold: true
            }
            Item { Layout.fillWidth: true }
            Button {
                text: Bridge.language === "ru" ? "EN" : "RU"
                onClicked: Bridge.setLanguage(Bridge.language === "ru" ? "en" : "ru")
            }
            Button {
                text: win.dark ? "☀" : "🌙"
                onClicked: Bridge.setTheme(win.dark ? "light" : "dark")
            }
        }

        // ---- INPUT ----------------------------------------------------- //
        ColumnLayout {
            visible: root.phase === "input"
            Layout.fillWidth: true
            spacing: 12

            TabBar {
                id: kindTabs
                Layout.fillWidth: true
                TabButton { text: qsTr("File") }
                TabButton { text: qsTr("Link") }
            }

            StackLayout {
                Layout.fillWidth: true
                currentIndex: kindTabs.currentIndex

                // FILE
                ColumnLayout {
                    spacing: 12
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 160
                        radius: 12
                        color: dropArea.containsDrag ? Qt.rgba(0.04, 0.52, 1, 0.08) : theme.card
                        border.color: dropArea.containsDrag ? theme.accent : theme.border
                        border.width: dropArea.containsDrag ? 2 : 1
                        Label {
                            anchors.centerIn: parent
                            horizontalAlignment: Text.AlignHCenter
                            color: theme.subtext
                            text: qsTr("Drop a file here\nor use the button below\n\nexe · msi · dll · apk · pdf · docx · zip · 7z …")
                        }
                        DropArea {
                            id: dropArea
                            anchors.fill: parent
                            onDropped: (drop) => {
                                if (drop.hasUrls) Bridge.scanFile(drop.urls[0].toString())
                            }
                        }
                    }
                    Button {
                        Layout.alignment: Qt.AlignHCenter
                        highlighted: true
                        text: qsTr("Choose a file from the computer")
                        onClicked: fileDialog.open()
                    }
                    Label {
                        Layout.alignment: Qt.AlignHCenter
                        color: theme.subtext
                        text: qsTr("No size limit · local analysis")
                    }
                }

                // LINK
                ColumnLayout {
                    spacing: 12
                    TextField {
                        id: urlField
                        Layout.fillWidth: true
                        placeholderText: "https://…"
                    }
                    CheckBox { id: dlCheck; text: qsTr("Download and scan the file (into a temp folder)") }
                    CheckBox { id: redirCheck; text: qsTr("Follow the redirect chain"); checked: true }
                    Button {
                        text: qsTr("Scan the link"); highlighted: true
                        enabled: urlField.text.length > 0
                        onClicked: Bridge.scanUrl(urlField.text, dlCheck.checked, redirCheck.checked)
                    }
                }
            }

            EngineStatusCard { theme: root.theme }
        }

        // ---- PROGRESS -------------------------------------------------- //
        ColumnLayout {
            visible: root.phase === "progress"
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 12

            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                BusyIndicator { running: Bridge.busy }
                Label { text: qsTr("Analysing…"); color: theme.text; font.pixelSize: 18 }
            }
            StageList { theme: root.theme; Layout.fillWidth: true; Layout.fillHeight: true }
            Button {
                Layout.alignment: Qt.AlignRight
                text: qsTr("Cancel")
                onClicked: Bridge.cancel()
            }
        }

        // ---- RESULT ---------------------------------------------------- //
        ColumnLayout {
            visible: root.phase === "result"
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 12

            RowLayout {
                spacing: 16
                VerdictGauge { theme: root.theme }
                ColumnLayout {
                    Label {
                        text: Bridge.verdict.toUpperCase()
                        color: Bridge.verdictColor
                        font.pixelSize: 24; font.bold: true
                    }
                    Label { text: Bridge.reasonText; color: theme.text; wrapMode: Text.WordWrap
                            Layout.maximumWidth: 520 }
                    Label { text: Bridge.target; color: theme.subtext }
                }
            }

            Label {
                visible: Bridge.incomplete
                text: qsTr("Incomplete scan — some sources were unavailable")
                color: theme.suspicious
            }

            Label { text: qsTr("WHY THIS VERDICT"); color: theme.subtext; font.pixelSize: 12 }
            ListView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                spacing: 8
                model: Bridge.signalsModel
                delegate: SignalCard { theme: root.theme }
            }

            RowLayout {
                Layout.fillWidth: true
                Button { text: qsTr("Save report…")
                    onClicked: saveDialog.open() }
                Button { text: qsTr("Quarantine"); onClicked: Bridge.quarantineCurrent() }
                Item { Layout.fillWidth: true }
                Button { text: qsTr("New scan"); highlighted: true
                    onClicked: root.phase = "input" }
            }
            FileDialog {
                id: saveDialog
                fileMode: FileDialog.SaveFile
                defaultSuffix: "html"
                onAccepted: Bridge.saveReport(selectedFile.toString())
            }
        }
    }
}
