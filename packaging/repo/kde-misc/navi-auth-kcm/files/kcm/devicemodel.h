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
