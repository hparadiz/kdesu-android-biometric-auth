// SPDX-License-Identifier: MIT
#include "devicemodel.h"

#include <QJsonObject>

int DeviceModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_devices.size();
}

QVariant DeviceModel::data(const QModelIndex &index, int role) const
{
    if (!checkIndex(index, CheckIndexOption::IndexIsValid | CheckIndexOption::ParentIsInvalid)) {
        return {};
    }
    const Device &device = m_devices.at(index.row());
    switch (role) {
    case Qt::DisplayRole:
    case NameRole:
        return device.name;
    case DeviceIdRole:
        return device.id;
    case TypeRole:
        return device.type;
    case ReachableRole:
        return device.reachable;
    case ShareEnabledRole:
        return device.share;
    case EnrolledRole:
        return device.enrolled;
    case PhoneKeyIdRole:
        return device.phoneKeyId;
    case CertificateExpiryRole:
        return device.certificateExpiry;
    case EnrolledAtRole:
        return device.enrolledAt;
    case AdminStateRole:
        return device.adminState;
    case RemoteRole:
        return device.remote;
    case RemotePhoneUrlRole:
        return device.remotePhoneUrl;
    case RemoteComputerUrlRole:
        return device.remoteComputerUrl;
    }
    return {};
}

QHash<int, QByteArray> DeviceModel::roleNames() const
{
    return {
        {DeviceIdRole, "deviceId"},
        {NameRole, "name"},
        {TypeRole, "deviceType"},
        {ReachableRole, "reachable"},
        {ShareEnabledRole, "shareEnabled"},
        {EnrolledRole, "enrolled"},
        {PhoneKeyIdRole, "phoneKeyId"},
        {CertificateExpiryRole, "certificateExpiry"},
        {EnrolledAtRole, "enrolledAt"},
        {AdminStateRole, "adminState"},
        {RemoteRole, "remote"},
        {RemotePhoneUrlRole, "remotePhoneUrl"},
        {RemoteComputerUrlRole, "remoteComputerUrl"},
    };
}

void DeviceModel::update(const QJsonArray &devices, const QJsonArray &phones, const QJsonObject &authority)
{
    // Root entries only count when the installed authority is valid and belongs to this account.
    QHash<QString, QJsonObject> rootByKey;
    if (authority.value(QStringLiteral("available")).toBool() && authority.value(QStringLiteral("valid")).toBool()
        && authority.value(QStringLiteral("account_matches")).toBool()) {
        for (const QJsonValue &value : authority.value(QStringLiteral("phones")).toArray()) {
            const QJsonObject entry = value.toObject();
            rootByKey.insert(entry.value(QStringLiteral("phone_key_id")).toString(), entry);
        }
    }
    const bool authorityEnabled = authority.value(QStringLiteral("enabled")).toBool();
    QHash<QString, QJsonObject> phoneByKey;
    for (const QJsonValue &value : phones) {
        const QJsonObject phone = value.toObject();
        phoneByKey.insert(phone.value(QStringLiteral("phone_key_id")).toString(), phone);
    }
    QList<Device> updated;
    for (const QJsonValue &value : devices) {
        const QJsonObject object = value.toObject();
        Device device;
        device.id = object.value(QStringLiteral("id")).toString();
        device.name = object.value(QStringLiteral("name")).toString();
        device.type = object.value(QStringLiteral("type")).toString();
        device.reachable = object.value(QStringLiteral("reachable")).toBool();
        device.share = object.value(QStringLiteral("share")).toBool();
        device.enrolled = object.value(QStringLiteral("enrolled")).toBool();
        device.phoneKeyId = object.value(QStringLiteral("phone_key_id")).toString();
        device.remote = object.value(QStringLiteral("remote")).toString();
        device.remotePhoneUrl = object.value(QStringLiteral("remote_phone_url")).toString();
        device.remoteComputerUrl = object.value(QStringLiteral("remote_computer_url")).toString();
        const QJsonObject phone = phoneByKey.value(device.phoneKeyId);
        if (const qint64 expiry = qint64(phone.value(QStringLiteral("certificate_expires_at_ms")).toDouble())) {
            device.certificateExpiry = QDateTime::fromMSecsSinceEpoch(expiry);
        }
        if (const qint64 enrolled = qint64(phone.value(QStringLiteral("enrolled_at_ms")).toDouble())) {
            device.enrolledAt = QDateTime::fromMSecsSinceEpoch(enrolled);
        }
        if (!device.phoneKeyId.isEmpty() && rootByKey.contains(device.phoneKeyId)) {
            const QJsonObject entry = rootByKey.value(device.phoneKeyId);
            const QString route = entry.value(QStringLiteral("kdeconnect_device")).toString();
            if (!route.isEmpty() && route != device.id) {
                device.adminState = QStringLiteral("other-device");
            } else if (authorityEnabled && entry.value(QStringLiteral("enabled")).toBool(true)) {
                device.adminState = QStringLiteral("enabled");
            } else {
                device.adminState = QStringLiteral("revoked");
            }
        }
        if (!device.id.isEmpty()) {
            updated.append(device);
        }
    }
    const bool countChanging = updated.size() != m_devices.size();
    beginResetModel();
    m_devices = updated;
    endResetModel();
    if (countChanging) {
        Q_EMIT countChanged();
    }
}

const DeviceModel::Device *DeviceModel::find(const QString &deviceId) const
{
    for (const Device &device : m_devices) {
        if (device.id == deviceId) {
            return &device;
        }
    }
    return nullptr;
}
