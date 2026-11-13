// SPDX-License-Identifier: MIT
#pragma once

#include <KQuickConfigModule>
#include <QJsonArray>
#include <QJsonObject>
#include <QPointer>
#include <QProcess>
#include <QTimer>

#include "devicemodel.h"

/**
 * System Settings page for Navi phone enrollment.
 *
 * All protocol and key handling stays in host.py; this module runs it with --json
 * and renders its event stream. Nothing here holds or parses key material.
 */
class NaviAuthKcm : public KQuickConfigModule
{
    Q_OBJECT
    Q_PROPERTY(DeviceModel *devices READ devices CONSTANT)
    Q_PROPERTY(bool busy READ busy NOTIFY taskChanged)
    Q_PROPERTY(QString task READ task NOTIFY taskChanged)
    Q_PROPERTY(QString taskDeviceId READ taskDeviceId NOTIFY taskChanged)
    Q_PROPERTY(QString taskDeviceName READ taskDeviceName NOTIFY taskChanged)
    Q_PROPERTY(QString code READ code NOTIFY progressChanged)
    Q_PROPERTY(qint64 codeExpiresAt READ codeExpiresAt NOTIFY progressChanged)
    Q_PROPERTY(QString offerFile READ offerFile NOTIFY progressChanged)
    Q_PROPERTY(QString step READ step NOTIFY progressChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY messageChanged)
    Q_PROPERTY(QString lastResult READ lastResult NOTIFY messageChanged)
    Q_PROPERTY(bool initialized READ initialized NOTIFY statusChanged)
    Q_PROPERTY(QString machineId READ machineId NOTIFY statusChanged)
    Q_PROPERTY(QString kdeConnectError READ kdeConnectError NOTIFY statusChanged)
    Q_PROPERTY(bool refreshing READ refreshing NOTIFY refreshingChanged)
    Q_PROPERTY(bool authorityAvailable READ authorityAvailable NOTIFY statusChanged)
    Q_PROPERTY(bool authorityConfigured READ authorityConfigured NOTIFY statusChanged)
    Q_PROPERTY(bool authorityMachineMismatch READ authorityMachineMismatch NOTIFY statusChanged)
    Q_PROPERTY(QString authorityProblem READ authorityProblem NOTIFY statusChanged)
    Q_PROPERTY(bool canEnableAdministratorPrompts READ canEnableAdministratorPrompts CONSTANT)

public:
    NaviAuthKcm(QObject *parent, const KPluginMetaData &data);
    ~NaviAuthKcm() override;

    DeviceModel *devices() const { return m_devices; }
    bool busy() const { return !m_task.isEmpty(); }
    QString task() const { return m_task; }
    QString taskDeviceId() const { return m_taskDeviceId; }
    QString taskDeviceName() const { return m_taskDeviceName; }
    QString code() const { return m_code; }
    qint64 codeExpiresAt() const { return m_codeExpiresAt; }
    QString offerFile() const { return m_offerFile; }
    QString step() const { return m_step; }
    QString lastError() const { return m_lastError; }
    QString lastResult() const { return m_lastResult; }
    bool initialized() const { return m_initialized; }
    QString machineId() const { return m_machineId; }
    QString kdeConnectError() const { return m_kdeConnectError; }
    bool refreshing() const { return m_refresh != nullptr; }
    /** The setuid helper answered (navi-auth is installed). */
    bool authorityAvailable() const;
    /** A valid root configuration exists for this account. */
    bool authorityConfigured() const;
    /** The root copy holds a different machine identity than this account's host.py state. */
    bool authorityMachineMismatch() const;
    /** Human-readable reason the root authority cannot be shown, or empty. */
    QString authorityProblem() const;
    /** pkexec and the installed polkit entry point exist. */
    bool canEnableAdministratorPrompts() const;

    Q_INVOKABLE void refresh();
    Q_INVOKABLE void initialize();
    Q_INVOKABLE void startEnrollment(const QString &deviceId);
    Q_INVOKABLE void sendTest(const QString &deviceId);
    Q_INVOKABLE void revoke(const QString &deviceId);
    /** Asks for the administrator password (polkit) and adds the phone to the protected authority. */
    Q_INVOKABLE void enableAdministratorPrompts(const QString &deviceId);
    /** Disables the phone for administrator prompts; the helper allows this without a password. */
    Q_INVOKABLE void disableAdministratorPrompts(const QString &deviceId);
    Q_INVOKABLE void cancel();
    Q_INVOKABLE void clearMessages();
    Q_INVOKABLE QString authorityCommand(const QString &deviceId) const;
    Q_INVOKABLE void copyToClipboard(const QString &text) const;
    Q_INVOKABLE void openKdeConnectSettings() const;

Q_SIGNALS:
    void taskChanged();
    void progressChanged();
    void messageChanged();
    void statusChanged();
    void refreshingChanged();
    void taskFinished(const QString &task, bool success);

private Q_SLOTS:
    void scheduleRefresh();

private:
    QStringList baseArguments() const;
    void startTask(const QString &task, const QString &deviceId, const QStringList &arguments);
    void startProcess(const QString &task, const QString &deviceId, const QString &program, const QStringList &arguments);
    void handleEvent(const QJsonObject &event);
    void taskOutput();
    void taskExited(int exitCode, QProcess::ExitStatus status);
    void runRefreshStep(const QStringList &command);
    void setMessages(const QString &error, const QString &result);

    DeviceModel *m_devices;
    QPointer<QProcess> m_process;
    QPointer<QProcess> m_refresh;
    QByteArray m_buffer;
    QTimer m_refreshTimer;
    QTimer m_expiryTimer;
    QString m_task, m_taskDeviceId, m_taskDeviceName;
    QString m_code, m_step, m_offerFile;
    qint64 m_codeExpiresAt = 0;
    QString m_lastError, m_lastResult, m_taskError;
    bool m_taskDone = false;
    bool m_initialized = false;
    QString m_machineId, m_stateDir, m_kdeConnectError;
    QJsonArray m_phones;
    QJsonArray m_deviceList;
    QJsonObject m_authority;
    QString m_revokeAfterAuthority; // device whose local enrollment is removed once root revocation succeeds
    bool m_authorityRevoked = false;
    bool m_refreshPending = false;
};
