// SPDX-License-Identifier: MIT
#pragma once

#include <QAbstractListModel>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>
#include <QList>

/** KDE Connect devices joined with this account's Navi enrollment records (from host.py). */
class DeviceModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)

public:
    enum Roles {
        DeviceIdRole = Qt::UserRole + 1,
        NameRole,
        TypeRole,
        ReachableRole,
        ShareEnabledRole,
        EnrolledRole,
        PhoneKeyIdRole,
        CertificateExpiryRole,
        EnrolledAtRole,
        AdminStateRole,
        RemoteRole,
        RemotePhoneUrlRole,
        RemoteComputerUrlRole,
        RemoteAdminRole,
    };
    Q_ENUM(Roles)

    struct Device {
        QString id;
        QString name;
        QString type;
        bool reachable = false;
        bool share = false;
        bool enrolled = false;
        QString phoneKeyId;
        QDateTime certificateExpiry;
        QDateTime enrolledAt;
        /** none | enabled | revoked | other-device, from the protected root authority. */
        QString adminState = QStringLiteral("none");
        /** ntfy server URL when remote approvals are set up for this phone, else empty. */
        QString remote;
        /** Web addresses of the phone's and the computer's ntfy inbox topics (encrypted traffic). */
        QString remotePhoneUrl;
        QString remoteComputerUrl;
        /** Short ID of this account's remote approval setup (empty if none). */
        QString remoteId;
        /**
         * Whether administrator prompts use the same remote approvals: "" (not applicable or neither has them),
         * "same", "stale" (the root copy still has remote approvals this account turned off) or
         * "outdated" (the root copy lacks this account's current remote approvals).
         */
        QString remoteAdmin;
    };

    using QAbstractListModel::QAbstractListModel;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    /**
     * devices: `host.py --json devices`; phones: the `phones` array of `host.py --json status`;
     * authority: the `authority` event of `host.py --json authority-status` (may be empty).
     */
    void update(const QJsonArray &devices, const QJsonArray &phones, const QJsonObject &authority);
    const Device *find(const QString &deviceId) const;

Q_SIGNALS:
    void countChanged();

private:
    QList<Device> m_devices;
};
