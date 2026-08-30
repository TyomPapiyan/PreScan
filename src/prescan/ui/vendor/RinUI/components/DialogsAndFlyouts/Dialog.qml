import QtQuick 2.15
import QtQuick.Controls 2.15 as QQC2
import QtQuick.Layouts 2.15
import "../../themes"
import "../../components"


QQC2.Dialog {
    id: root

    property bool titleBarVisible: false

    anchors.centerIn: QQC2.Overlay.overlay  // Center in the overlay
    closePolicy: QQC2.Popup.NoAutoClose  // 更符合fds规范

    padding: 24
    topPadding: 24
    bottomPadding: 24
    implicitWidth: Math.min(
        Math.max(Utils.dialogMinimumWidth, Math.min(implicitContentWidth + 48, Utils.dialogMaximumWidth)),
        Math.max(0, QQC2.Overlay.overlay.width - 16)
    )
    implicitHeight: Math.min(implicitContentHeight + topPadding + bottomPadding + footer.implicitHeight, Math.max(0, QQC2.Overlay.overlay.height - 16))

    contentItem: ColumnLayout {
        spacing: 12
        Text {
            Layout.fillWidth: true
            typography: Typography.Subtitle
            text: root.title
        }
    }


    header: Item {}

    // 定制footer
    footer: DialogButtonBox {
        id: buttonBox
        standardButtons: root.standardButtons
    }

    background: Rectangle {
        id: background
        anchors.fill: parent
        color: Theme.currentTheme.colors.backgroundAcrylicColor
        border.color: Theme.currentTheme.colors.windowBorderColor
        border.width: 1
        radius: Theme.currentTheme.appearance.windowRadius

        Behavior on color {
            ColorAnimation {
                duration: Utils.backdropEnabled ? 0 : 150
            }
        }

        layer.enabled: true
        layer.effect: Shadow {
            style: "dialog"
            source: background
        }
    }

    QQC2.Overlay.modal: Rectangle {
        color: Theme.currentTheme.colors.backgroundSmokeColor
    }

    // 动画 / Animation //
    enter: Transition {
        ParallelAnimation {
            NumberAnimation {
                target: root
                property: "opacity"
                from: 0
                to: 1
                duration: Utils.appearanceSpeed
                easing.type: Easing.InOutQuart
            }
            NumberAnimation {
                target: root
                property: "scale"
                from: 1.1
                to: 1
                duration: Utils.animationSpeedMiddle
                easing.type: Easing.OutQuint
            }
        }
    }

    exit: Transition {
        ParallelAnimation {
            NumberAnimation {
                target: root
                property: "opacity"
                from: 1
                to: 0
                duration: 100
                easing.type: Easing.InOutQuart
            }
            NumberAnimation {
                target: root
                property: "scale"
                from: 1
                to: 1.1
                duration: Utils.animationSpeedMiddle
                easing.type: Easing.OutQuint
            }
        }
    }
}
