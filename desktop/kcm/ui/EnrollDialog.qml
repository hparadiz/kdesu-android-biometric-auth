// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

Kirigami.Dialog {
    id: dialog

    property string deviceName
    property int secondsLeft: 0
    readonly property bool running: kcm.busy && kcm.task === "enroll"
    readonly property bool succeeded: !running && kcm.lastResult.length > 0
    readonly property var steps: [
        i18n("Send the pairing offer to the phone"),
        i18n("Enter the code in Navi Authenticator"),
        i18n("Approve the pairing with your fingerprint"),
        i18n("Enrolled")
    ]
    // Index of the step in progress; everything before it is complete.
    readonly property int stepIndex: ({
        "offer-sent": 1,
        "hello-verified": 2,
        "awaiting-biometric": 2,
        "receipt-sent": 3,
        "done": 4
    })[kcm.step] ?? 0

    title: i18nc("@title:window", "Enroll %1", deviceName)
    padding: Kirigami.Units.largeSpacing * 2
    preferredWidth: Kirigami.Units.gridUnit * 28
    closePolicy: running ? QQC2.Popup.NoAutoClose : (QQC2.Popup.CloseOnEscape | QQC2.Popup.CloseOnPressOutside)
    showCloseButton: !running
    standardButtons: running ? Kirigami.Dialog.NoButton : Kirigami.Dialog.Close
    customFooterActions: Kirigami.Action {
        visible: dialog.running
        text: i18nc("@action:button", "Cancel")
        icon.name: "dialog-cancel"
        onTriggered: kcm.cancel()
    }

    Timer {
        interval: 1000
        repeat: true
        running: dialog.visible && kcm.codeExpiresAt > 0
        triggeredOnStart: true
        onTriggered: dialog.secondsLeft = Math.max(0, Math.round((kcm.codeExpiresAt - Date.now()) / 1000))
    }

    ColumnLayout {
        spacing: Kirigami.Units.largeSpacing

        QQC2.Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            visible: kcm.code.length > 0 && dialog.stepIndex <= 1
            text: i18n("Open <b>Navi Authenticator</b> on %1 and enter this code:", dialog.deviceName)
        }
        QQC2.Label {
            Layout.alignment: Qt.AlignHCenter
            visible: kcm.code.length > 0 && dialog.stepIndex <= 1
            text: kcm.code
            font.family: "monospace"
            font.pixelSize: Kirigami.Units.gridUnit * 2.5
            font.weight: Font.Bold
            font.letterSpacing: Kirigami.Units.smallSpacing
            textFormat: Text.PlainText
            Accessible.name: kcm.code.split("").join(" ")
        }
        QQC2.Label {
            Layout.alignment: Qt.AlignHCenter
            visible: kcm.code.length > 0 && dialog.stepIndex <= 1
            opacity: 0.7
            font: Kirigami.Theme.smallFont
            text: i18n("Expires in %1:%2", Math.floor(dialog.secondsLeft / 60), String(dialog.secondsLeft % 60).padStart(2, "0"))
        }
        QQC2.Label {
            Layout.fillWidth: true
            visible: kcm.code.length > 0 && dialog.stepIndex <= 1
            wrapMode: Text.Wrap
            font: Kirigami.Theme.smallFont
            opacity: 0.8
            text: i18n("No code box in Navi? The offer went to the phone's Downloads: open it with Navi from KDE Connect's "
                     + "notification, or tap <b>Pair a computer…</b> → <b>Open pairing offer…</b> in Navi and choose <tt>%1</tt>.",
                       kcm.offerFile.length > 0 ? kcm.offerFile : "navi-auth-enroll-offer-….json")
        }
        QQC2.BusyIndicator {
            Layout.alignment: Qt.AlignHCenter
            visible: dialog.running && kcm.code.length === 0
            running: visible
        }
        Kirigami.Separator {
            Layout.fillWidth: true
        }
        Repeater {
            model: dialog.steps
            delegate: RowLayout {
                required property var modelData
                required property int index
                spacing: Kirigami.Units.smallSpacing
                Kirigami.Icon {
                    Layout.preferredWidth: Kirigami.Units.iconSizes.small
                    Layout.preferredHeight: Kirigami.Units.iconSizes.small
                    source: index < dialog.stepIndex ? "checkmark"
                          : index === dialog.stepIndex && dialog.running ? "media-playback-start" : "draw-circle"
                    opacity: index <= dialog.stepIndex ? 1 : 0.4
                }
                QQC2.Label {
                    text: modelData
                    opacity: index <= dialog.stepIndex ? 1 : 0.6
                    font.weight: index === dialog.stepIndex ? Font.DemiBold : Font.Normal
                }
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
            visible: dialog.succeeded
            type: Kirigami.MessageType.Positive
            text: kcm.lastResult
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: !dialog.running && !dialog.succeeded && kcm.lastError.length === 0 && kcm.step.length > 0
            type: Kirigami.MessageType.Information
            text: i18n("Enrollment was canceled.")
        }
    }
}
