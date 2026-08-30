import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: card
    property var theme
    width: ListView.view ? ListView.view.width : 400
    height: col.implicitHeight + 20
    radius: 12
    color: theme.card
    border.color: theme.border

    function sevColor(s) {
        if (s === "critical" || s === "high") return theme.dangerous
        if (s === "medium") return theme.suspicious
        if (s === "low") return theme.subtext
        return theme.subtext
    }

    ColumnLayout {
        id: col
        anchors.fill: parent
        anchors.margins: 10
        spacing: 2
        RowLayout {
            spacing: 8
            Rectangle { width: 10; height: 10; radius: 5; color: card.sevColor(model.severity) }
            Label { text: model.source; color: theme.subtext; font.pixelSize: 12 }
            Item { Layout.fillWidth: true }
            Label { text: qsTr("weight %1").arg(model.weight); color: theme.subtext; font.pixelSize: 12 }
        }
        Label { text: model.title; color: theme.text; wrapMode: Text.WordWrap; Layout.fillWidth: true }
        Label {
            visible: model.detail.length > 0
            text: model.detail; color: theme.subtext; font.pixelSize: 12
            wrapMode: Text.WordWrap; Layout.fillWidth: true
        }
        Label {
            visible: model.mitre.length > 0
            text: "MITRE ATT&CK: " + model.mitre; color: theme.subtext; font.pixelSize: 12
        }
    }
}
