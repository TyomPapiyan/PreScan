import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import PreScan

Item {
    id: page
    property var theme

    function verdictColor(v) {
        if (v === "dangerous") return theme.dangerous
        if (v === "suspicious") return theme.suspicious
        if (v === "safe") return theme.safe
        return theme.unknown
    }
    function reload() { Bridge.filterHistory(filterBox.currentText, searchField.text) }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 12

        RowLayout {
            Layout.fillWidth: true
            Label { text: qsTr("History"); color: theme.text; font.pixelSize: 22; font.bold: true }
            Item { Layout.fillWidth: true }
            Button {
                text: qsTr("Clear history")
                onClicked: clearConfirm.open()
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Label { text: qsTr("Verdict:"); color: theme.subtext }
            ComboBox {
                id: filterBox
                model: ["all", "dangerous", "suspicious", "safe", "unknown"]
                onActivated: page.reload()
            }
            TextField {
                id: searchField
                Layout.fillWidth: true
                placeholderText: qsTr("Search by name or SHA-256…")
                onTextChanged: page.reload()
            }
        }

        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: Bridge.historyModel
            spacing: 4
            delegate: ItemDelegate {
                width: ListView.view.width
                height: 40
                onClicked: Bridge.openReport(model.sha256)
                enabled: model.sha256.length > 0
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 8
                    anchors.rightMargin: 8
                    spacing: 12
                    Label { text: model.stamp; color: theme.subtext; Layout.preferredWidth: 130 }
                    Rectangle {
                        radius: 6; height: 22; width: badge.implicitWidth + 16
                        color: page.verdictColor(model.verdict)
                        Label {
                            id: badge; anchors.centerIn: parent
                            text: model.verdict.toUpperCase(); color: "#FFFFFF"; font.pixelSize: 11
                        }
                    }
                    Label {
                        text: model.target; color: theme.text
                        Layout.fillWidth: true; elide: Text.ElideRight
                    }
                }
            }
        }
    }

    Dialog {
        id: clearConfirm
        anchors.centerIn: parent
        width: Math.min(parent.width - 48, 460)
        modal: true
        title: qsTr("Clear history?")
        standardButtons: Dialog.Yes | Dialog.No
        onAccepted: { Bridge.clearHistory() }
        Label { text: qsTr("This permanently deletes all scan history entries.") }
    }
}
