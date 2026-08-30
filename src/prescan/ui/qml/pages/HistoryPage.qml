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
        Label { text: qsTr("History"); color: theme.text; font.pixelSize: 22; font.bold: true }
        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: Bridge.historyModel
            delegate: RowLayout {
                width: ListView.view.width
                spacing: 12
                Label { text: model.stamp; color: theme.subtext; Layout.preferredWidth: 130 }
                Label { text: model.verdict; color: theme.text; Layout.preferredWidth: 100 }
                Label { text: model.target; color: theme.text; Layout.fillWidth: true; elide: Text.ElideRight }
            }
        }
    }
}
