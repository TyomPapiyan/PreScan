import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    property var theme
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 12
        Label { text: qsTr("About PreScan"); color: theme.text; font.pixelSize: 22; font.bold: true }
        Label { text: "PreScan 0.0.0"; color: theme.text }
        Label {
            Layout.maximumWidth: 620
            wrapMode: Text.WordWrap
            color: theme.subtext
            text: qsTr("PreScan is not an antivirus and does not replace your system's protection. "
                + "The verdict is informational. The decision to run a file is yours.")
        }
        Label {
            Layout.maximumWidth: 620
            wrapMode: Text.WordWrap
            color: theme.subtext
            text: qsTr("Built with Qt / PySide6 (LGPLv3), YARA-X, LIEF, oletools, pikepdf. "
                + "RinUI (MIT) is vendored in ui/vendor/RinUI. Full licenses are in the "
                + "licenses/ folder. ClamAV is used as an external process, not linked.")
        }
        Label {
            text: "https://github.com/TyomPapiyan/PreScan"
            color: theme.accent
        }
        Item { Layout.fillHeight: true }
    }
}
