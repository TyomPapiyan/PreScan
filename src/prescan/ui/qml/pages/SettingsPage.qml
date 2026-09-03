import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"
import PreScan

Item {
    id: page
    property var theme
    property var win

    // provider id -> "Check key" result text
    property var keyResults: ({})
    Connections {
        target: Bridge
        function onKeyCheckResult(provider, text) {
            var m = page.keyResults; m[provider] = text; page.keyResults = m
        }
    }

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth
        ColumnLayout {
            width: page.width - 48
            x: 24
            y: 24
            spacing: 16

            Label { text: qsTr("Settings"); color: theme.text; font.pixelSize: 22; font.bold: true }

            // ---- Local engines ---------------------------------------- //
            GroupBox {
                Layout.fillWidth: true
                title: qsTr("Local engines")
                ColumnLayout {
                    anchors.fill: parent
                    EngineStatusCard { theme: page.theme }
                    RowLayout {
                        Button { text: qsTr("Update YARA rules"); onClicked: Bridge.updateRules() }
                        Button {
                            text: qsTr("Update ClamAV databases"); onClicked: Bridge.updateClamav()
                        }
                        Button { text: qsTr("Download ML model"); onClicked: Bridge.updateModel() }
                        Button { text: qsTr("Re-check"); onClicked: Bridge.refreshEngines() }
                    }
                    Label {
                        id: updateStatus
                        visible: text.length > 0
                        color: page.theme.subtext
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                        Connections {
                            target: Bridge
                            function onUpdateStatus(msg) { updateStatus.text = msg }
                        }
                    }
                }
            }

            // ---- API keys --------------------------------------------- //
            GroupBox {
                Layout.fillWidth: true
                title: qsTr("API keys")
                ColumnLayout {
                    anchors.fill: parent
                    spacing: 8
                    Repeater {
                        model: Bridge.providerIds()
                        delegate: RowLayout {
                            required property string modelData
                            Layout.fillWidth: true
                            spacing: 8
                            Label {
                                text: modelData
                                color: theme.text
                                Layout.preferredWidth: 110
                            }
                            TextField {
                                id: keyField
                                Layout.fillWidth: true
                                echoMode: TextInput.Password
                                placeholderText: Bridge.hasApiKey(modelData)
                                    ? qsTr("key configured — enter to replace")
                                    : qsTr("paste API key")
                            }
                            Button {
                                text: qsTr("Save")
                                enabled: keyField.text.length > 0
                                onClicked: { Bridge.setApiKey(modelData, keyField.text); keyField.clear() }
                            }
                            Button {
                                text: qsTr("Check key")
                                onClicked: Bridge.checkKey(modelData)
                            }
                            Label {
                                Layout.preferredWidth: 150
                                elide: Text.ElideRight
                                color: theme.subtext
                                text: page.keyResults[modelData] || ""
                            }
                        }
                    }
                }
            }

            // ---- Privacy: full-URL disclosure (§6.2) + working toggles - //
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
                        delegate: Label {
                            required property string modelData
                            text: "•  " + modelData; color: theme.dangerous
                        }
                    }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: theme.safe
                        text: qsTr("Google Safe Browsing receives only truncated hash prefixes — never the full URL.")
                    }
                    CheckBox {
                        text: qsTr("Never upload files to the cloud")
                        checked: Bridge.neverUpload
                        onToggled: Bridge.setNeverUpload(checked)
                    }
                    CheckBox {
                        text: qsTr("Send only hashes")
                        checked: Bridge.onlyHashes
                        onToggled: Bridge.setOnlyHashes(checked)
                    }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: theme.subtext
                        text: qsTr("When on, links are checked only by Safe Browsing hash prefixes — a green (safe) verdict for a URL is not possible.")
                    }
                    CheckBox {
                        text: qsTr("Disable all network activity")
                        checked: !Bridge.allowNetwork
                        onToggled: Bridge.setAllowNetwork(!checked)
                    }
                }
            }

            // ---- Scanning --------------------------------------------- //
            GroupBox {
                Layout.fillWidth: true
                title: qsTr("Scanning")
                GridLayout {
                    anchors.fill: parent
                    columns: 2
                    columnSpacing: 16
                    Label { text: qsTr("Download size limit (MB):"); color: theme.text }
                    SpinBox {
                        from: 1; to: 100000; value: Bridge.maxDownloadMb; editable: true
                        onValueModified: Bridge.setMaxDownloadMb(value)
                    }
                    Label { text: qsTr("Scan timeout (s):"); color: theme.text }
                    SpinBox {
                        from: 1; to: 3600; value: Bridge.scanTimeoutS; editable: true
                        onValueModified: Bridge.setScanTimeoutS(value)
                    }
                    Label { text: qsTr("Archive extraction depth:"); color: theme.text }
                    SpinBox {
                        from: 1; to: 20; value: Bridge.archiveDepth; editable: true
                        onValueModified: Bridge.setArchiveDepth(value)
                    }
                    Label { text: qsTr("Cache TTL (days):"); color: theme.text }
                    SpinBox {
                        from: 0; to: 365; value: Bridge.cacheTtlDays; editable: true
                        onValueModified: Bridge.setCacheTtlDays(value)
                    }
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
            Item { Layout.fillHeight: true; Layout.preferredHeight: 24 }
        }
    }
}
