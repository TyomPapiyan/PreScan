import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts
import "../../themes"
import "../../components"

ListView {
    id: root
    focusPolicy: Qt.StrongFocus
    property string textRole: ""  // 文字role

    property bool keyboardNavigation: false
    property alias verticalScrollBar: scrollBar
    signal itemClicked(int index)
    // 自动检测模型类型
    readonly property string modelType: {
        if (!model) return "null";
        const isArrayModel = Array.isArray(model) || model instanceof Array;
        if (isArrayModel && root.textRole) return "array-with-role";
        if (isArrayModel) return "array";
        if (model instanceof ListModel) return "listmodel";
        if (typeof model === "object" && "count" in model) return "listmodel-like";
        return "unknown";
    }

    clip: true

    Keys.onPressed: function(event) {
        if (event.key === Qt.Key_Up || event.key === Qt.Key_Down)
            root.keyboardNavigation = true
    }

    // 垂直滚动条 / Vertical ScrollBar //
    ScrollBar.vertical: ScrollBar {
        id: scrollBar
        policy: ScrollBar.AsNeeded
    }

    // 交换动画
    // move: Transition {
    //     NumberAnimation { property: "y"; duration: 200 }
    // }
    // moveDisplaced: Transition {
    //     NumberAnimation { property: "y"; duration: 200 }
    // }

    displaced: Transition {
        NumberAnimation {
            property: "y"
            duration: Utils.animationSpeedMiddle
            easing.type: Easing.OutQuint
        }
    }

    add: Transition {
        ParallelAnimation {
            NumberAnimation {
                property: "opacity"
                from: 0
                to: 1
                duration: Utils.animationSpeed
                easing.type: Easing.OutQuint
            }
            NumberAnimation {
                properties: "scale"
                from: 0.9
                to: 1
                duration: Utils.animationSpeed
                easing.type: Easing.OutQuint
            }
        }
    }

    // 删除动画
    remove: Transition {
        ParallelAnimation{
            NumberAnimation {
                property: "opacity"
                from: 1
                to: 0
                duration: Utils.animationSpeed
                easing.type: Easing.OutQuint
            }
            NumberAnimation {
                properties: "scale"
                from: 1
                to: 0.9
                duration: Utils.animationSpeed
                easing.type: Easing.OutQuint
            }
        }
    }

    property Animation updateAnimation: ParallelAnimation {
        NumberAnimation {
            target: root
            property: "contentY"
            from: -12
            to: 0
            duration: Utils.animationSpeedMiddle
            easing.type: Easing.OutQuint
        }
        NumberAnimation {
            target: root
            property: "opacity"
            from: 0
            to: 1
            duration: Utils.animationSpeed
            easing.type: Easing.OutQuart
        }
    }

    onModelChanged: {
        // 动画移动到 targetOffset
        updateAnimation.restart()
    }

    delegate: ListViewDelegate {
        keyboardNavigation: root.keyboardNavigation && highlighted
        text: {
            switch (root.modelType) {
                case "array": return modelData;
                case "array-with-role": return modelData[root.textRole] || modelData || "";
                case "listmodel":
                case "listmodel-like":
                    // modelData 仅对 JS 数组/QStringList/单 role 模型注入；
                    // 多 role 的 ListModel 里 modelData 为 undefined，直接索引会抛
                    // TypeError 并中止整个 || 链，因此先做空值保护
                    return (modelData ? modelData[root.textRole] : "")
                        || model[root.textRole]
                        || modelData
                        || model
                        || "";
                default: return "";
            }
        }
    }
}
