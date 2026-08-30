import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import PreScan

Item {
    id: page
    property var theme
    property string pendingEntry: ""

    FolderDialog {
        id: folderDialog
        title: qsTr("Restore to folder")
        onAccepted: Bridge.restoreQuarantine(page.pendingEntry, selectedFolder.toString())
    }

    Dialog {
        id: restoreConfirm
        anchors.centerIn: parent
        modal: true
        title: qsTr("Restore this file?")
        standardButtons: Dialog.Yes | Dialog.No
        onAccepted: folderDialog.open()
        Label {
            width: parent.width
            wrapMode: Text.WordWrap
            text: qsTr("Warning: this file was quarantined as dangerous. Restoring it puts "
                + "the original malware back on disk. Continue only if you are sure.")
        }
    }

    Dialog {
        id: deleteConfirm
        anchors.centerIn: parent
        modal: true
        title: qsTr("Delete permanently?")
        standardButtons: Dialog.Yes | Dialog.No
        onAccepted: Bridge.deleteQuarantine(page.pendingEntry)
        Label { text: qsTr("This permanently deletes the quarantined file.") }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 12
        Label { text: qsTr("Quarantine"); color: theme.text; font.pixelSize: 22; font.bold: true }
        Label {
            visible: Bridge.quarantineModel.rowCount === 0
            text: qsTr("Quarantine is empty.")
            color: theme.subtext
        }
        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: Bridge.quarantineModel
            spacing: 6
            delegate: Rectangle {
                width: ListView.view.width
                height: 48
                radius: 8
                color: theme.card
                border.color: theme.border
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 10
                    anchors.rightMargin: 10
                    spacing: 8
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0
                        Label { text: model.name; color: theme.text }
                        Label { text: model.verdict; color: theme.subtext; font.pixelSize: 11 }
                    }
                    Button {
                        text: qsTr("Restore")
                        onClicked: { page.pendingEntry = model.entryId; restoreConfirm.open() }
                    }
                    Button {
                        text: qsTr("Re-scan")
                        onClicked: Bridge.rescanQuarantine(model.entryId)
                    }
                    Button {
                        text: qsTr("Delete")
                        onClicked: { page.pendingEntry = model.entryId; deleteConfirm.open() }
                    }
                }
            }
        }
    }
}
