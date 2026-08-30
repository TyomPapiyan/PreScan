import QtQuick
import QtQuick.Controls
import PreScan

Item {
    property var theme
    width: 108
    height: 108

    Rectangle {
        anchors.fill: parent
        radius: width / 2
        color: "transparent"
        border.width: 8
        border.color: Bridge.verdictColor
    }
    Column {
        anchors.centerIn: parent
        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            text: Bridge.gauge
            color: theme.text
            font.pixelSize: 28
            font.bold: true
        }
        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            text: Bridge.gauge === "—" ? "" : "/100"
            color: theme.subtext
            font.pixelSize: 12
        }
    }
}
