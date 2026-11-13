// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCM

KCM.ScrollViewKCM {
    id: root

    implicitWidth: Kirigami.Units.gridUnit * 36
    implicitHeight: Kirigami.Units.gridUnit * 28

    function fingerprint(id) {
        return id.length >= 12 ? id.substring(0, 4) + " " + id.substring(4, 8) + " " + id.substring(8, 12) : id
    }

    actions: [
        Kirigami.Action {
            icon.name: "view-refresh"
            text: i18nc("@action:button", "Refresh")
            enabled: !kcm.refreshing
            onTriggered: kcm.refresh()
        },
        Kirigami.Action {
            icon.name: "kdeconnect"
            text: i18nc("@action:button", "KDE Connect Settings…")
            onTriggered: kcm.openKdeConnectSettings()
        }
    ]

    header: ColumnLayout {
        spacing: Kirigami.Units.smallSpacing

        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: kcm.lastError.length > 0 && !enrollDialog.visible
            type: Kirigami.MessageType.Error
            text: kcm.lastError
            showCloseButton: true
            onVisibleChanged: if (!visible) kcm.clearMessages()
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: kcm.lastResult.length > 0 && !enrollDialog.visible
            type: Kirigami.MessageType.Positive
            text: kcm.lastResult
            showCloseButton: true
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: kcm.kdeConnectError.length > 0
            type: Kirigami.MessageType.Warning
            text: kcm.kdeConnectError
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: !kcm.initialized && kcm.kdeConnectError.length === 0 && !kcm.refreshing
            type: Kirigami.MessageType.Information
            text: i18n("This computer does not have a Navi signing identity yet. Create one before enrolling a phone.")
            actions: Kirigami.Action {
                text: i18nc("@action:button", "Create Identity")
                icon.name: "document-new"
                enabled: !kcm.busy
                onTriggered: kcm.initialize()
            }
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: kcm.authorityMachineMismatch
            type: Kirigami.MessageType.Warning
            text: i18n("The protected administrator configuration uses a different computer identity than this account. Administrator prompts will not reach phones enrolled here until an administrator runs the configure command again.")
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: kcm.kdesuWithoutNavi
            type: Kirigami.MessageType.Warning
            text: i18n("kdesu on this computer doesn't use Navi, so administrator prompts never reach your phone. A system update probably replaced the Navi-patched kdesu-gui package; reinstall it (see INSTALL).")
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: kcm.authorityProblem.length > 0
            type: Kirigami.MessageType.Information
            text: i18n("Administrator prompt status is unavailable: %1", kcm.authorityProblem)
        }
        QQC2.Label {
            Layout.fillWidth: true
            visible: kcm.initialized
            wrapMode: Text.Wrap
            text: i18n("Phones paired with KDE Connect can be enrolled to approve requests from this account with a fingerprint. This computer's fingerprint: <b>%1</b>", root.fingerprint(kcm.machineId))
        }
    }

    view: ListView {
        id: list
        model: kcm.devices
        clip: true
        spacing: 0

        Kirigami.PlaceholderMessage {
            anchors.centerIn: parent
            width: parent.width - Kirigami.Units.gridUnit * 4
            visible: list.count === 0 && !kcm.refreshing
            icon.name: "smartphone"
            text: i18n("No paired phones")
            explanation: i18n("Pair your phone in KDE Connect and enable file sharing, then return here.")
            helpfulAction: Kirigami.Action {
                icon.name: "kdeconnect"
                text: i18nc("@action:button", "Open KDE Connect Settings")
                onTriggered: kcm.openKdeConnectSettings()
            }
        }

        delegate: QQC2.ItemDelegate {
            id: card
            required property string deviceId
            required property string name
            required property bool reachable
            required property bool shareEnabled
            required property bool enrolled
            required property string phoneKeyId
            required property var certificateExpiry
            required property string adminState

            width: ListView.view.width
            down: false
            highlighted: false
            hoverEnabled: false

            readonly property bool usable: reachable && shareEnabled
            readonly property bool adminEnabled: adminState === "enabled"
            readonly property string statusText: {
                if (!reachable) return enrolled ? i18n("Enrolled · offline") : i18n("Offline")
                if (!shareEnabled) return i18n("KDE Connect file sharing is disabled")
                if (enrolled) {
                    if (certificateExpiry && certificateExpiry.getTime && certificateExpiry.getTime() > 0)
                        return i18n("Enrolled · certificate expires %1", Qt.formatDate(certificateExpiry, Locale.ShortFormat))
                    return i18n("Enrolled")
                }
                return i18n("Not enrolled")
            }

            contentItem: RowLayout {
                spacing: Kirigami.Units.largeSpacing

                Kirigami.Icon {
                    source: card.reachable ? "smartphone" : "smartphonedisconnected"
                    Layout.preferredWidth: Kirigami.Units.iconSizes.medium
                    Layout.preferredHeight: Kirigami.Units.iconSizes.medium
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0
                    QQC2.Label {
                        Layout.fillWidth: true
                        text: card.name
                        elide: Text.ElideRight
                        font.weight: Font.DemiBold
                    }
                    RowLayout {
                        spacing: Kirigami.Units.smallSpacing
                        Rectangle {
                            implicitWidth: Kirigami.Units.smallSpacing * 2
                            implicitHeight: implicitWidth
                            radius: width / 2
                            color: card.enrolled && card.usable ? Kirigami.Theme.positiveTextColor
                                 : card.usable ? Kirigami.Theme.neutralTextColor : Kirigami.Theme.disabledTextColor
                        }
                        QQC2.Label {
                            Layout.fillWidth: true
                            text: card.statusText
                            elide: Text.ElideRight
                            opacity: 0.8
                            font: Kirigami.Theme.smallFont
                        }
                    }
                    RowLayout {
                        visible: card.enrolled && kcm.authorityAvailable && kcm.authorityProblem.length === 0
                        spacing: Kirigami.Units.smallSpacing
                        QQC2.Switch {
                            id: adminSwitch
                            text: i18nc("@option:check", "Administrator prompts")
                            font: Kirigami.Theme.smallFont
                            checked: card.adminEnabled
                            // Turning on needs the administrator password (polkit); turning off does not.
                            enabled: !kcm.busy && card.adminState !== "other-device"
                                     && (card.adminEnabled || kcm.canEnableAdministratorPrompts)
                            onToggled: {
                                const wanted = checked
                                checked = Qt.binding(() => card.adminEnabled) // reflect the real state, not the click
                                if (wanted)
                                    kcm.enableAdministratorPrompts(card.deviceId)
                                else
                                    kcm.disableAdministratorPrompts(card.deviceId)
                            }
                            QQC2.ToolTip.text: card.adminEnabled
                                ? i18n("This phone can approve kdesu and other administrator prompts. Turn off to stop that immediately.")
                                : i18n("Let this phone approve kdesu and other administrator prompts. Asks for the administrator password.")
                            QQC2.ToolTip.visible: hovered
                            QQC2.ToolTip.delay: Kirigami.Units.toolTipDelay
                        }
                        QQC2.BusyIndicator {
                            visible: kcm.busy && kcm.taskDeviceId === card.deviceId
                                     && (kcm.task === "authority-enable" || kcm.task === "authority-revoke")
                            running: visible
                            Layout.preferredHeight: Kirigami.Units.iconSizes.small
                            Layout.preferredWidth: Layout.preferredHeight
                        }
                        QQC2.Label {
                            Layout.fillWidth: true
                            visible: card.adminState === "revoked" || card.adminState === "other-device"
                            text: card.adminState === "revoked" ? i18n("(revoked)") : i18n("(set up for another KDE Connect device)")
                            elide: Text.ElideRight
                            opacity: 0.7
                            font: Kirigami.Theme.smallFont
                        }
                    }
                }
                QQC2.BusyIndicator {
                    visible: kcm.busy && kcm.taskDeviceId === card.deviceId && kcm.task !== "enroll"
                             && kcm.task !== "authority-enable" && kcm.task !== "authority-revoke"
                    running: visible
                    Layout.preferredHeight: Kirigami.Units.iconSizes.medium
                    Layout.preferredWidth: Layout.preferredHeight
                }
                QQC2.Button {
                    visible: card.enrolled
                    text: i18nc("@action:button", "Send Test")
                    icon.name: "fingerprint"
                    enabled: !kcm.busy && card.usable
                    onClicked: testMenu.popup(this, 0, height)
                    QQC2.ToolTip.text: i18n("Ask the phone for a fingerprint approval without running anything. Choose how the request travels: as signed files through KDE Connect, or over Navi's direct network connection (needs Enable network authentication in Navi → ☰ → Settings).")
                    QQC2.ToolTip.visible: hovered
                    QQC2.ToolTip.delay: Kirigami.Units.toolTipDelay
                    QQC2.Menu {
                        id: testMenu
                        QQC2.MenuItem {
                            text: i18nc("@action:inmenu", "Through KDE Connect messages")
                            icon.name: "kdeconnect"
                            onTriggered: kcm.sendTest(card.deviceId, "kdeconnect")
                        }
                        QQC2.MenuItem {
                            text: i18nc("@action:inmenu", "Over the network (direct)")
                            icon.name: "network-wireless"
                            onTriggered: kcm.sendTest(card.deviceId, "network")
                        }
                    }
                }
                QQC2.Button {
                    text: card.enrolled ? i18nc("@action:button", "Re-enroll") : i18nc("@action:button", "Enroll")
                    icon.name: card.enrolled ? "view-refresh" : "list-add"
                    enabled: !kcm.busy && kcm.initialized && card.usable
                    onClicked: {
                        enrollDialog.deviceName = card.name
                        enrollDialog.open()
                        kcm.startEnrollment(card.deviceId)
                    }
                }
                QQC2.ToolButton {
                    visible: card.enrolled
                    icon.name: "overflow-menu"
                    display: QQC2.AbstractButton.IconOnly
                    text: i18nc("@action:button", "More")
                    enabled: !kcm.busy
                    onClicked: menu.popup()
                    QQC2.Menu {
                        id: menu
                        QQC2.MenuItem {
                            text: i18nc("@action:inmenu", "Show Administrator Command…")
                            icon.name: "utilities-terminal"
                            onTriggered: {
                                authorityDialog.command = kcm.authorityCommand(card.deviceId)
                                authorityDialog.open()
                            }
                        }
                        QQC2.MenuItem {
                            text: i18nc("@action:inmenu", "Remove Enrollment…")
                            icon.name: "edit-delete-remove"
                            onTriggered: {
                                removeDialog.deviceId = card.deviceId
                                removeDialog.deviceName = card.name
                                removeDialog.adminState = card.adminState
                                removeDialog.open()
                            }
                        }
                    }
                }
            }
        }
    }

    EnrollDialog {
        id: enrollDialog
    }

    Kirigami.PromptDialog {
        id: removeDialog
        property string deviceId
        property string deviceName
        property string adminState
        title: i18nc("@title:window", "Remove Enrollment")
        subtitle: adminState === "enabled"
            ? i18n("%1 will no longer be able to approve requests for this account, and will be disabled for administrator prompts. Turning administrator prompts back on later needs the administrator password.", deviceName)
            : adminState === "other-device"
            ? i18n("%1 will no longer be able to approve requests for this account. Its administrator-prompt entry uses another KDE Connect device and must be revoked by an administrator.", deviceName)
            : i18n("%1 will no longer be able to approve requests for this account.", deviceName)
        standardButtons: Kirigami.Dialog.Cancel
        customFooterActions: Kirigami.Action {
            text: i18nc("@action:button", "Remove")
            icon.name: "edit-delete-remove"
            onTriggered: {
                kcm.revoke(removeDialog.deviceId)
                removeDialog.close()
            }
        }
    }

    Kirigami.Dialog {
        id: authorityDialog
        property string command
        title: i18nc("@title:window", "Administrator Command")
        padding: Kirigami.Units.largeSpacing
        preferredWidth: Kirigami.Units.gridUnit * 34
        standardButtons: Kirigami.Dialog.Close
        customFooterActions: Kirigami.Action {
            text: i18nc("@action:button", "Copy Command")
            icon.name: "edit-copy"
            onTriggered: kcm.copyToClipboard(authorityDialog.command)
        }
        ColumnLayout {
            spacing: Kirigami.Units.largeSpacing
            QQC2.Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: i18n("Enrollment only lets this phone approve requests for your account. For kdesu and other administrator prompts, the “Administrator prompts” switch asks for the administrator password and does this for you. To do it by hand instead, run this in an administrator shell:")
            }
            QQC2.TextArea {
                Layout.fillWidth: true
                readOnly: true
                wrapMode: TextEdit.WrapAnywhere
                font.family: "monospace"
                text: authorityDialog.command
            }
        }
    }
}
