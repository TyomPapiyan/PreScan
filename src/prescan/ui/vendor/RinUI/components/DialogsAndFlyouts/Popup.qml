import QtQuick 2.15
import QtQuick.Controls.Basic 2.15 as QQC2
import QtQuick.Layouts 2.15
import Qt5Compat.GraphicalEffects
import "../../themes"
import "../../components"
import "PopupPositioner.js" as PopupPositioner

QQC2.Popup {
    id: popup
    property int position: Position.Bottom
    property Item anchorItem: parent
    property real posX: _targetX
    property real posY: _targetY
    property real _targetX: x
    property real _targetY: y
    property int _resolvedPosition: position
    property bool _repositionPending: false
    property bool _manualPosition: false
    property real _manualX: 0
    property real _manualY: 0
    property bool _settingPosition: false
    property bool _componentCompleted: false
    readonly property real _spacing: 5
    readonly property real _margin: 8

    function _overlay() {
        return QQC2.Overlay.overlay
    }

    function _scheduleReposition() {
        if (position === Position.None || !visible || _repositionPending)
            return

        _repositionPending = true
        Qt.callLater(function() {
            _repositionPending = false
            _reposition()
        })
    }

    function _captureManualPosition() {
        if (position !== Position.None)
            return

        // x/y changes captured before opening are authoritative, including 0.
        if (_manualPosition)
            return

        // Explicit x/y assignments are captured by onXChanged/onYChanged.
        // Do not infer from the current value: it may be a previous automatic placement.
    }

    function _reposition() {
        if (position === Position.None)
            return 
        var overlay = _overlay()
        if (!overlay || !parent)
            return

        var popupWidth = Math.max(width, implicitWidth)
        var popupHeight = Math.max(height, implicitHeight)
        var bounds = { x: 0, y: 0, width: overlay.width, height: overlay.height }
        var result

        if (position === Position.None && _manualPosition) {
            var manualInOverlay = parent.mapToItem(overlay, _manualX, _manualY)
            result = {
                x: PopupPositioner.clamp(manualInOverlay.x, _margin, overlay.width - popupWidth - _margin),
                y: PopupPositioner.clamp(manualInOverlay.y, _margin, overlay.height - popupHeight - _margin),
                position: Position.None
            }
        } else if (position === Position.Center) {
            result = PopupPositioner.resolve(
                bounds, popupWidth, popupHeight, bounds, Position.Center, _spacing, _margin, Position)
        } else if (anchorItem) {
            var anchorOrigin = anchorItem.mapToItem(overlay, 0, 0)
            var anchor = {
                x: anchorOrigin.x,
                y: anchorOrigin.y,
                width: anchorItem.width,
                height: anchorItem.height
            }
            result = PopupPositioner.resolve(
                anchor, popupWidth, popupHeight, bounds, position, _spacing, _margin, Position)
        } else {
            result = PopupPositioner.resolve(
                bounds, popupWidth, popupHeight, bounds, Position.Center, _spacing, _margin, Position)
        }

        var localPosition = overlay.mapToItem(parent, result.x, result.y)
        _resolvedPosition = result.position
        _targetX = localPosition.x
        _targetY = localPosition.y
        _settingPosition = true
        x = _targetX
        y = _targetY
        _settingPosition = false
    }

    // Kept for existing controls that already call autoPosition().
    function autoPosition() {
        _captureManualPosition()
        _reposition()
    }

    onAboutToShow: {
        _captureManualPosition()
        _reposition()
    }

    onVisibleChanged: {
        if (visible)
            _scheduleReposition()
    }

    onPositionChanged: _scheduleReposition()
    onXChanged: {
        if (_componentCompleted && !visible && !_settingPosition && position === Position.None) {
            _manualPosition = true
            _manualX = x
        }
    }
    onYChanged: {
        if (_componentCompleted && !visible && !_settingPosition && position === Position.None) {
            _manualPosition = true
            _manualY = y
        }
    }
    onAnchorItemChanged: _scheduleReposition()
    onWidthChanged: _scheduleReposition()
    onHeightChanged: _scheduleReposition()
    onImplicitWidthChanged: _scheduleReposition()
    onImplicitHeightChanged: _scheduleReposition()

    Connections {
        target: popup._overlay()
        function onWidthChanged() { popup._scheduleReposition() }
        function onHeightChanged() { popup._scheduleReposition() }
    }

    Connections {
        target: popup.anchorItem
        function onXChanged() { popup._scheduleReposition() }
        function onYChanged() { popup._scheduleReposition() }
        function onWidthChanged() { popup._scheduleReposition() }
        function onHeightChanged() { popup._scheduleReposition() }
    }

    Component.onCompleted: {
        _componentCompleted = true
        if (position === Position.None && !_manualPosition && (x !== 0 || y !== 0)) {
            _manualPosition = true
            _manualX = x
            _manualY = y
        }
    }

    QQC2.Overlay.modal: Rectangle {
        color: Theme.currentTheme.colors.backgroundSmokeColor
    }

    background: Rectangle {
        id: background
        anchors.fill: parent
        y: -6

        radius: Theme.currentTheme.appearance.windowRadius
        color: Theme.currentTheme.colors.backgroundAcrylicColor
        border.color: Theme.currentTheme.colors.flyoutBorderColor

        Behavior on color {
            ColorAnimation {
                duration: Utils.appearanceSpeed
                easing.type: Easing.OutQuart
            }
        }

        layer.enabled: true
        layer.effect: Shadow {
            style: "flyout"
            source: background
        }
    }

    // 动画 / Animation //
    enter: Transition {
        enabled: position !== Position.None
        ParallelAnimation {
            NumberAnimation {
                target: popup
                property: "opacity"
                from: 0
                to: 1
                duration: Utils.appearanceSpeed
                easing.type: Easing.OutQuint
            }
            NumberAnimation {
                target: popup
                property: "y"
                from: posY + (_resolvedPosition !== Position.Center
                    ? (_resolvedPosition === Position.Top ? 15 : _resolvedPosition === Position.Bottom ? -15 : 0) : 0)
                to: posY
                duration: Utils.animationSpeedMiddle * 1.25
                easing.type: Easing.OutQuint
            }
            NumberAnimation {
                target: popup
                property: "x"
                from: posX + (_resolvedPosition !== Position.Center
                    ? (_resolvedPosition === Position.Left ? 15 : _resolvedPosition === Position.Right ? -15 : 0) : 0)
                to: posX
                duration: Utils.animationSpeedMiddle * 1.25
                easing.type: Easing.OutQuint
            }
        }
    }
    exit: Transition {
        enabled: position !== Position.None
        ParallelAnimation {
            NumberAnimation {
                target: popup
                property: "opacity"
                from: 1
                to: 0
                duration: Utils.animationSpeed
                easing.type: Easing.OutQuint
            }
        }
    }
}
