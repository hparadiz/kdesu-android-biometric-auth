// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

// Remote approvals over ntfy for one phone: used only when KDE Connect can't see it.
Kirigami.Dialog {
    id: dialog

    property string deviceId
    property string deviceName
    property string remote        // current ntfy server, empty when off
    property bool adminEnabled
    property string phoneUrl      // ntfy topic the computer publishes to (requests, receipts)
    property string computerUrl   // ntfy topic the phone publishes to (approvals)
    readonly property bool running: kcm.busy && kcm.taskDeviceId === deviceId
                                    && (kcm.task === "remote-setup" || kcm.task === "remote-remove" || kcm.task === "authority-enable")

    title: i18nc("@title:window", "Remote Approvals for %1", deviceName)
    padding: Kirigami.Units.largeSpacing * 2
    preferredWidth: Kirigami.Units.gridUnit * 30
    closePolicy: running ? QQC2.Popup.NoAutoClose : (QQC2.Popup.CloseOnEscape | QQC2.Popup.CloseOnPressOutside)
    showCloseButton: !running
    standardButtons: running ? Kirigami.Dialog.NoButton : Kirigami.Dialog.Close

    onOpened: {
        kcm.clearMessages()
        server.text = remote.length > 0 ? remote : "https://ntfy.sh"
        token.text = ""
    }

    customFooterActions: [
        Kirigami.Action {
            visible: !dialog.running && dialog.remote.length > 0
            text: i18nc("@action:button", "Turn Off")
            icon.name: "edit-delete-remove"
            onTriggered: kcm.removeRemote(dialog.deviceId)
        },
        Kirigami.Action {
            visible: !dialog.running
            text: dialog.remote.length > 0 ? i18nc("@action:button", "Set Up Again") : i18nc("@action:button", "Set Up")
            icon.name: "cloud-upload"
            enabled: server.text.trim().startsWith("https://")
            onTriggered: kcm.setupRemote(dialog.deviceId, server.text, token.text)
        },
        Kirigami.Action {
            visible: dialog.running && kcm.task === "remote-setup"
            text: i18nc("@action:button", "Cancel")
            icon.name: "dialog-cancel"
            onTriggered: kcm.cancel()
        }
    ]

    Connections {
        target: kcm
        function onTaskFinished(task, success) {
            if (success && (task === "remote-setup" || task === "remote-remove" || task === "authority-enable"))
                dialog.remote = task === "remote-remove" ? "" : (task === "remote-setup" ? server.text.trim() : dialog.remote)
        }
    }

    ColumnLayout {
        spacing: Kirigami.Units.largeSpacing

        QQC2.Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            text: i18n("When KDE Connect can't see %1 (for example when it is on mobile data), requests go through an ntfy server instead. Both sides only connect out to the server; every message is end-to-end encrypted with a key that never leaves this computer and the phone, and approvals are still signed by the phone's fingerprint key. The server sees only random topic names, timing and sizes.", dialog.deviceName)
        }
        QQC2.Label {
            Layout.fillWidth: true
            visible: dialog.remote.length > 0 && dialog.phoneUrl.length > 0
            wrapMode: Text.Wrap
            textFormat: Text.StyledText
            onLinkActivated: link => Qt.openUrlExternally(link)
            text: i18n("See the traffic on ntfy (end-to-end encrypted, so it shows only ciphertext): <a href=\"%1\">phone inbox</a> (requests from this computer) · <a href=\"%2\">computer inbox</a> (approvals from the phone). Anyone with these addresses can see when messages are sent, so don't share them.", dialog.phoneUrl, dialog.computerUrl)
            HoverHandler { cursorShape: parent.hoveredLink ? Qt.PointingHandCursor : Qt.ArrowCursor }
        }
        Kirigami.FormLayout {
            Layout.fillWidth: true
            enabled: !dialog.running
            QQC2.TextField {
                id: server
                Kirigami.FormData.label: i18nc("@label:textbox", "ntfy server:")
                Layout.fillWidth: true
                placeholderText: "https://ntfy.sh"
                inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoAutoUppercase
            }
            Kirigami.PasswordField {
                id: token
                Kirigami.FormData.label: i18nc("@label:textbox", "Access token:")
                Layout.fillWidth: true
                placeholderText: i18nc("@info:placeholder", "Optional, for a server with access control")
            }
        }
        QQC2.Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            font: Kirigami.Theme.smallFont
            opacity: 0.8
            text: dialog.adminEnabled
                ? i18n("Administrator prompts are on for this phone, so the administrator password is asked afterwards to update them.")
                : i18n("Set Up sends a request to Navi over KDE Connect; approve it with your fingerprint on the phone.")
        }
        RowLayout {
            visible: dialog.running
            spacing: Kirigami.Units.smallSpacing
            QQC2.BusyIndicator {
                running: parent.visible
                Layout.preferredHeight: Kirigami.Units.iconSizes.medium
                Layout.preferredWidth: Layout.preferredHeight
            }
            QQC2.Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: kcm.task === "remote-setup" ? i18n("Approve “Allow remote approvals” in Navi on %1 with your fingerprint…", dialog.deviceName)
                    : kcm.task === "authority-enable" ? i18n("Updating administrator prompts…")
                    : i18n("Turning off…")
            }
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: !dialog.running && kcm.lastError.length > 0
            type: Kirigami.MessageType.Error
            text: kcm.lastError
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: !dialog.running && kcm.lastResult.length > 0
            type: Kirigami.MessageType.Positive
            text: kcm.lastResult
        }
    }
}
