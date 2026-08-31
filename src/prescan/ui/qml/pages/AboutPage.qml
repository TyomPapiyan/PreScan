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
                + "RinUI (MIT) is vendored in ui/vendor/RinUI. The malware classifier and "
                + "its feature extractor derive from the EMBER2024 project (Apache-2.0). "
                + "Full licenses are in the licenses/ folder. ClamAV is used as an "
                + "external process, not linked.")
        }
        // LGPLv3 §11.2: link to the corresponding PySide6/Qt sources.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: theme.subtext
            textFormat: Text.StyledText
            linkColor: theme.accent
            onLinkActivated: (link) => Qt.openUrlExternally(link)
            text: qsTr("PySide6 / Qt are used under the LGPLv3. Corresponding source: ")
                + '<a href="https://download.qt.io/official_releases/QtForPython/">'
                + "https://download.qt.io/official_releases/QtForPython/</a>"
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: theme.subtext
            text: qsTr("Google Safe Browsing and the VirusTotal public API are free for "
                + "non-commercial use only.")
        }
        Label {
            text: "https://github.com/TyomPapiyan/PreScan"
            color: theme.accent
        }
        Item { Layout.fillHeight: true }
    }
}
