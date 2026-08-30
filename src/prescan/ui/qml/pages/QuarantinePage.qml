import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import PreScan

Item {
    property var theme
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
                height: 40
                radius: 8
                color: theme.card
                border.color: theme.border
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 8
                    Label { text: model.name; color: theme.text; Layout.fillWidth: true }
                    Label { text: model.verdict; color: theme.subtext }
                }
            }
        }
    }
}
