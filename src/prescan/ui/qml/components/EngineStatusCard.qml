import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import PreScan

Flow {
    id: flow
    property var theme
    spacing: 8
    Component.onCompleted: Bridge.refreshEngines()

    Repeater {
        model: Bridge.enginesModel
        delegate: Rectangle {
            radius: 8
            height: 26
            width: label.implicitWidth + 20
            color: model.availability === "ready" ? Qt.rgba(0.18, 0.8, 0.44, 0.15)
                                                   : (theme.card)
            border.color: theme.border
            Label {
                id: label
                anchors.centerIn: parent
                text: model.name + " · " + Bridge.availabilityText(model.availability, model.detail)
                color: theme.text
                font.pixelSize: 12
            }
            ToolTip.visible: hover.hovered
            ToolTip.text: model.detail
            HoverHandler { id: hover }
        }
    }
}
