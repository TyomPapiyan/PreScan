import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import PreScan

ListView {
    id: list
    property var theme
    clip: true
    spacing: 4
    model: Bridge.stagesModel

    function statusIcon(s) {
        if (s === "done") return "✓"
        if (s === "running") return "⏳"
        if (s === "skipped") return "—"
        if (s === "failed") return "✕"
        if (s === "cancelled") return "⊘"
        return "·"
    }
    function statusColor(s) {
        if (s === "done") return theme.safe
        if (s === "failed") return theme.dangerous
        if (s === "skipped") return theme.subtext
        return theme.text
    }

    delegate: RowLayout {
        width: list.width
        spacing: 10
        Label { text: list.statusIcon(model.status); color: list.statusColor(model.status); width: 20 }
        Label { text: model.stageId; color: theme.text; Layout.preferredWidth: 160 }
        Label { text: model.summary; color: theme.subtext; Layout.fillWidth: true; elide: Text.ElideRight }
    }
}
