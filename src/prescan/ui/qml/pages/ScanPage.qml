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
    property string phase: "input"  // "input" | "progress" | "result"

    Connections {
        target: Bridge
        function onScanStarted() { root.phase = "progress" }
        function onScanFinished() { root.phase = "result" }
        function onShowResult() { win.page = 0; root.phase = "result" }
    }

    FileDialog {
        id: fileDialog
        title: qsTr("Choose a file to scan")
        onAccepted: Bridge.scanFile(selectedFile.toString())
    }

    // Top bar: language + theme toggles only (title lives in the nav rail).
    RowLayout {
        id: topBar
        anchors { top: parent.top; left: parent.left; right: parent.right; margins: 16 }
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

    // ---- INPUT (centered) --------------------------------------------- //
    ColumnLayout {
        visible: root.phase === "input"
        anchors.centerIn: parent
        width: Math.min(700, root.width - 48)
        spacing: 16

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
                Item {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 180
                    DropArea {
                        id: dropArea
                        anchors.fill: parent
                        onDropped: (drop) => {
                            if (drop.hasUrls) Bridge.scanFile(drop.urls[0].toString())
                        }
                    }
                    Rectangle {
                        id: dropCard
                        anchors.fill: parent
                        radius: 12
                        color: dropArea.containsDrag ? Qt.rgba(0.04, 0.52, 1, 0.08) : theme.card
                        // Solid accent border only while a file hovers; dashed otherwise.
                        border.width: dropArea.containsDrag ? 2 : 0
                        border.color: theme.accent
                        Canvas {
                            anchors.fill: parent
                            anchors.margins: 1
                            visible: !dropArea.containsDrag
                            onPaint: {
                                var ctx = getContext("2d")
                                ctx.clearRect(0, 0, width, height)
                                ctx.strokeStyle = theme.border
                                ctx.lineWidth = 1.5
                                ctx.setLineDash([6, 4])
                                var r = 12
                                ctx.beginPath()
                                ctx.moveTo(r, 1)
                                ctx.lineTo(width - r, 1); ctx.arcTo(width - 1, 1, width - 1, r, r)
                                ctx.lineTo(width - 1, height - r); ctx.arcTo(width - 1, height - 1, width - r, height - 1, r)
                                ctx.lineTo(r, height - 1); ctx.arcTo(1, height - 1, 1, height - r, r)
                                ctx.lineTo(1, r); ctx.arcTo(1, 1, r, 1, r)
                                ctx.stroke()
                            }
                        }
                        Label {
                            anchors.centerIn: parent
                            horizontalAlignment: Text.AlignHCenter
                            color: theme.subtext
                            text: qsTr("⬇\n\nDrop a file here, or use the button below\n\nexe · msi · dll · apk · pdf · docx · zip · 7z …")
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
                TextField { id: urlField; Layout.fillWidth: true; placeholderText: "https://…" }
                CheckBox { id: dlCheck; text: qsTr("Download and scan the file (into a temp folder)") }
                CheckBox { id: redirCheck; text: qsTr("Follow the redirect chain"); checked: true }
                Button {
                    Layout.alignment: Qt.AlignHCenter
                    text: qsTr("Scan the link"); highlighted: true
                    enabled: urlField.text.length > 0
                    onClicked: Bridge.scanUrl(urlField.text, dlCheck.checked, redirCheck.checked)
                }
            }
        }

        // Engine badges sit directly under the input area (§9.4).
        EngineStatusCard { theme: root.theme; Layout.fillWidth: true }
    }

    // ---- PROGRESS ----------------------------------------------------- //
    ColumnLayout {
        visible: root.phase === "progress"
        anchors { fill: parent; topMargin: 60; margins: 24 }
        spacing: 12
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            BusyIndicator { running: Bridge.busy }
            Label { text: qsTr("Analysing…"); color: theme.text; font.pixelSize: 18 }
        }
        StageList { theme: root.theme; Layout.fillWidth: true; Layout.fillHeight: true }
        Button { Layout.alignment: Qt.AlignRight; text: qsTr("Cancel"); onClicked: Bridge.cancel() }
    }

    // ---- RESULT ------------------------------------------------------- //
    ColumnLayout {
        visible: root.phase === "result"
        anchors { fill: parent; topMargin: 60; margins: 24 }
        spacing: 12
        RowLayout {
            spacing: 16
            VerdictGauge { theme: root.theme }
            ColumnLayout {
                Label {
                    text: Bridge.verdict.toUpperCase(); color: Bridge.verdictColor
                    font.pixelSize: 24; font.bold: true
                }
                Label {
                    text: Bridge.reasonText; color: theme.text; wrapMode: Text.WordWrap
                    Layout.maximumWidth: 560
                }
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
            Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 8
            model: Bridge.signalsModel
            delegate: SignalCard { theme: root.theme }
        }
        // Stage 13: the cloud-upload offer. Shown only when it could add something
        // (verdict not dangerous, file unknown to the cloud); kept visible but
        // disabled when the master lock is on, so the third layer is never hidden.
        ColumnLayout {
            Layout.fillWidth: true
            visible: Bridge.canOfferUpload
            spacing: 4
            Button {
                objectName: "cloudUploadButton"
                text: qsTr("Send file to the cloud for scanning")
                enabled: !Bridge.uploadLocked
                onClicked: cloudUploadDialog.open()
            }
            Label {
                visible: Bridge.uploadLocked
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: theme.subtext
                text: qsTr("Turn off “Never upload files to the cloud” in Settings to enable this.")
            }
        }
        RowLayout {
            Layout.fillWidth: true
            Button { text: qsTr("Save report…"); onClicked: saveDialog.open() }
            Button { text: qsTr("Quarantine"); onClicked: Bridge.quarantineCurrent() }
            Item { Layout.fillWidth: true }
            Button { text: qsTr("New scan"); highlighted: true; onClicked: root.phase = "input" }
        }

        // §10.5 consent modal. Cancel is the focused, default action so a stray key
        // never uploads; Esc cancels; there are no pre-ticked toggles. It shows
        // exactly what will leave the machine and does not soften the disclosure.
        Dialog {
            id: cloudUploadDialog
            objectName: "cloudUploadDialog"
            anchors.centerIn: parent
            width: Math.min(parent.width - 48, 560)
            modal: true
            closePolicy: Popup.CloseOnEscape
            title: qsTr("Send this file to the cloud?")
            onAccepted: Bridge.uploadCurrentToCloud()
            footer: DialogButtonBox {
                Button {
                    text: qsTr("Send file to the cloud")
                    DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
                }
                Button {
                    objectName: "cloudCancelButton"
                    text: qsTr("Cancel")
                    focus: true  // the default, focused action: Enter/Esc both cancel
                    DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
                }
            }
            ColumnLayout {
                width: parent.width
                spacing: 8
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: theme.text
                    text: qsTr("These exact details will be sent to %1:").arg(Bridge.uploadService)
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: theme.text
                    text: qsTr("File: %1").arg(Bridge.uploadFileName)
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: theme.text
                    text: qsTr("Size: %1").arg(Bridge.uploadFileSize)
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WrapAnywhere
                    color: theme.subtext
                    text: qsTr("SHA-256: %1").arg(Bridge.uploadFileSha256)
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: theme.dangerous
                    text: qsTr("The file will leave your machine in full. Once it is sent, it cannot be recalled.")
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: theme.dangerous
                    text: qsTr("Files you submit may be shared with premium %1 customers, and the scan report is shared with the public %1 community.").arg(Bridge.uploadService)
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: theme.subtext
                    text: qsTr("If you cancel after sending starts, PreScan stops waiting for the result, but the file has already left your machine.")
                }
            }
        }
        FileDialog {
            id: saveDialog
            objectName: "saveReportDialog"
            fileMode: FileDialog.SaveFile
            nameFilters: [qsTr("HTML report (*.html)"), qsTr("PDF report (*.pdf)")]
            // Suffix follows the selected filter, so a name typed without an
            // extension is saved in the format the user actually picked (PDF is
            // index 1); HTML stays the default when the dialog opens (index 0).
            defaultSuffix: selectedNameFilter.index === 1 ? "pdf" : "html"
            onAccepted: Bridge.saveReport(selectedFile.toString())
        }
    }
}
