import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"
import PreScan

Item {
    id: page
    property var theme
    property var win

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth
        ColumnLayout {
            width: parent.width
            anchors.margins: 24
            spacing: 16
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: 24
            anchors.rightMargin: 24
            anchors.topMargin: 24

            Label { text: qsTr("Settings"); color: theme.text; font.pixelSize: 22; font.bold: true }

            // ---- Local engines ---------------------------------------- //
            GroupBox {
                Layout.fillWidth: true
                title: qsTr("Local engines")
                ColumnLayout {
                    anchors.fill: parent
                    EngineStatusCard { theme: page.theme }
                    RowLayout {
                        Button { text: qsTr("Update YARA rules") }
                        Button { text: qsTr("Update ClamAV databases") }
                        Button { text: qsTr("Re-check"); onClicked: Bridge.refreshEngines() }
                    }
                }
            }

            // ---- Privacy: full-URL disclosure (§6.2) ------------------- //
            GroupBox {
                Layout.fillWidth: true
                title: qsTr("Privacy")
                ColumnLayout {
                    anchors.fill: parent
                    spacing: 6
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: theme.text
                        text: qsTr("When you scan a link, the FULL URL is sent to these sources:")
                    }
                    Repeater {
                        model: Bridge.fullUrlSources()
                        delegate: Label { text: "•  " + modelData; color: theme.dangerous }
                    }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: theme.safe
                        text: qsTr("Google Safe Browsing receives only truncated hash prefixes — never the full URL.")
                    }
                    CheckBox { text: qsTr("Never upload files to the cloud"); checked: true; enabled: false }
                    CheckBox { text: qsTr("Send only hashes"); checked: true; enabled: false }
                }
            }

            // ---- Interface -------------------------------------------- //
            GroupBox {
                Layout.fillWidth: true
                title: qsTr("Interface")
                ColumnLayout {
                    anchors.fill: parent
                    RowLayout {
                        Label { text: qsTr("Theme:"); color: theme.text }
                        ComboBox {
                            model: ["system", "dark", "light"]
                            currentIndex: model.indexOf(Bridge.theme)
                            onActivated: Bridge.setTheme(currentText)
                        }
                    }
                    RowLayout {
                        Label { text: qsTr("Language:"); color: theme.text }
                        ComboBox {
                            model: ["system", "ru", "en"]
                            currentIndex: model.indexOf(Bridge.language)
                            onActivated: Bridge.setLanguage(currentText)
                        }
                    }
                }
            }
            Item { Layout.fillHeight: true }
        }
    }
}
