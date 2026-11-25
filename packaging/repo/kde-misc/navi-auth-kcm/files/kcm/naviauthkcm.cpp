// SPDX-License-Identifier: MIT
#include "naviauthkcm.h"

#include <KLocalizedString>
#include <KPluginFactory>

#include <QClipboard>
#include <QDBusConnection>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFileInfo>
#include <QProcessEnvironment>
#include <QStandardPaths>

#include <algorithm>

#include <unistd.h>

#include <utility>

K_PLUGIN_CLASS_WITH_JSON(NaviAuthKcm, "kcm_navi_auth.json")

namespace
{
constexpr auto KdeConnectService = "org.kde.kdeconnect";
constexpr auto KdeConnectPath = "/modules/kdeconnect";
constexpr auto KdeConnectInterface = "org.kde.kdeconnect.daemon";

QString environmentOr(const char *name, const char *fallback)
{
    const QString value = qEnvironmentVariable(name);
    return value.isEmpty() ? QString::fromUtf8(fallback) : value;
}

QString python()
{
    return environmentOr("NAVI_AUTH_PYTHON", NAVI_AUTH_PYTHON_DEFAULT);
}

QString hostScript()
{
    return environmentOr("NAVI_AUTH_HOST", NAVI_AUTH_HOST_DEFAULT);
}

QString pkexec()
{
    return environmentOr("NAVI_AUTH_PKEXEC", "pkexec");
}

QString polkitConfigure()
{
    return environmentOr("NAVI_AUTH_POLKIT_CONFIGURE", NAVI_AUTH_POLKIT_CONFIGURE_DEFAULT);
}

QString quoted(const QString &value)
{
    // Single-quoted POSIX shell word for the copyable administrator command.
    QString escaped = value;
    escaped.replace(QLatin1Char('\''), QStringLiteral("'\\''"));
    return QLatin1Char('\'') + escaped + QLatin1Char('\'');
}
}

NaviAuthKcm::NaviAuthKcm(QObject *parent, const KPluginMetaData &data)
    : KQuickConfigModule(parent, data)
    , m_devices(new DeviceModel(this))
{
    setButtons(NoAdditionalButton);

    m_refreshTimer.setSingleShot(true);
    m_refreshTimer.setInterval(400);
    connect(&m_refreshTimer, &QTimer::timeout, this, &NaviAuthKcm::refresh);

    // The phone drops an unconfirmed offer at expiry; reflect that in the dialog.
    m_expiryTimer.setSingleShot(true);
    connect(&m_expiryTimer, &QTimer::timeout, this, [this] {
        if (m_task == QLatin1String("enroll") && m_step == QLatin1String("offer-sent")) {
            cancel();
        }
    });

    auto bus = QDBusConnection::sessionBus();
    for (const char *signal : {"deviceListChanged", "deviceVisibilityChanged", "deviceAdded", "deviceRemoved"}) {
        bus.connect(QString::fromLatin1(KdeConnectService), QString::fromLatin1(KdeConnectPath), QString::fromLatin1(KdeConnectInterface),
                    QString::fromLatin1(signal), this, SLOT(scheduleRefresh()));
    }
    refresh();
}

NaviAuthKcm::~NaviAuthKcm()
{
    // Leaving System Settings mid-enrollment withdraws the request (host.py sends a signed cancel).
    if (m_process && m_process->state() != QProcess::NotRunning) {
        m_process->terminate();
        if (!m_process->waitForFinished(3000)) {
            m_process->kill();
        }
    }
}

QStringList NaviAuthKcm::baseArguments() const
{
    return {QStringLiteral("-I"), hostScript(), QStringLiteral("--json")};
}

void NaviAuthKcm::scheduleRefresh()
{
    m_refreshTimer.start();
}

void NaviAuthKcm::refresh()
{
    if (m_refresh) {
        m_refreshPending = true;
        return;
    }
    runRefreshStep({QStringLiteral("status")});
}

void NaviAuthKcm::runRefreshStep(const QStringList &command)
{
    auto *process = new QProcess(this);
    m_refresh = process;
    Q_EMIT refreshingChanged();
    connect(process, &QProcess::finished, this, [this, process, command](int, QProcess::ExitStatus) {
        process->deleteLater();
        QJsonArray devices;
        QJsonObject authority;
        bool listed = false;
        QString error;
        for (const QByteArray &line : process->readAllStandardOutput().split('\n')) {
            const QJsonObject event = QJsonDocument::fromJson(line).object();
            const QString name = event.value(QStringLiteral("event")).toString();
            if (name == QLatin1String("status")) {
                m_initialized = event.value(QStringLiteral("initialized")).toBool();
                m_machineId = event.value(QStringLiteral("machine_id")).toString();
                m_stateDir = event.value(QStringLiteral("state_dir")).toString();
                m_phones = event.value(QStringLiteral("phones")).toArray();
            } else if (name == QLatin1String("devices")) {
                devices = event.value(QStringLiteral("devices")).toArray();
                listed = true;
            } else if (name == QLatin1String("authority")) {
                authority = event;
            } else if (name == QLatin1String("error")) {
                error = event.value(QStringLiteral("message")).toString();
            }
        }
        if (process->error() == QProcess::FailedToStart) {
            error = i18n("Could not run %1. Is the navi-auth package installed?", hostScript());
        }
        if (command.first() == QLatin1String("status")) {
            if (!error.isEmpty()) {
                m_kdeConnectError = error;
                m_refresh = nullptr;
                Q_EMIT statusChanged();
                Q_EMIT refreshingChanged();
                return;
            }
            Q_EMIT statusChanged();
            runRefreshStep({QStringLiteral("devices")});
            return;
        }
        if (command.first() == QLatin1String("devices")) {
            m_kdeConnectError = listed ? QString() : (error.isEmpty() ? i18n("KDE Connect devices could not be listed.") : error);
            if (listed) {
                m_deviceList = devices;
                m_devices->update(m_deviceList, m_phones, m_authority);
            }
            runRefreshStep({QStringLiteral("authority-status")});
            return;
        }
        // authority-status: read-only view of the protected root configuration for this account.
        m_authority = authority.isEmpty()
            ? QJsonObject{{QStringLiteral("available"), false}, {QStringLiteral("error"), error.isEmpty() ? i18n("The protected authority did not answer.") : error}}
            : authority;
        m_devices->update(m_deviceList, m_phones, m_authority);
        m_refresh = nullptr;
        Q_EMIT statusChanged();
        Q_EMIT refreshingChanged();
        if (m_refreshPending) {
            m_refreshPending = false;
            refresh();
        }
    });
    process->start(python(), baseArguments() + command);
}

void NaviAuthKcm::initialize()
{
    startTask(QStringLiteral("init"), QString(), {QStringLiteral("init")});
}

void NaviAuthKcm::startEnrollment(const QString &deviceId)
{
    startTask(QStringLiteral("enroll"), deviceId, {QStringLiteral("enroll"), QStringLiteral("--kdeconnect-device"), deviceId});
}

void NaviAuthKcm::sendTest(const QString &deviceId, const QString &transport)
{
    const DeviceModel::Device *device = m_devices->find(deviceId);
    if (!device || !device->enrolled) {
        return;
    }
    // Network: host.py resolves the phone's current LAN address through KDE Connect and opens Navi's
    // pinned TLS connection, the same route kdesu uses with the LAN transport. Remote: ntfy only.
    m_testTransport = transport;
    const bool network = transport == QLatin1String("network");
    QStringList arguments{QStringLiteral("authenticate"), network ? QStringLiteral("--kdeconnect-device") : QStringLiteral("--kdeconnect-messages"),
                          deviceId, QStringLiteral("--phone-key-id"), device->phoneKeyId, QStringLiteral("--notification-only"),
                          QStringLiteral("--application"), QStringLiteral("System Settings"), QStringLiteral("--operation"),
                          network ? QStringLiteral("Test network approval from System Settings")
                          : transport == QLatin1String("remote") ? QStringLiteral("Test remote approval from System Settings")
                                                                 : QStringLiteral("Test approval from System Settings")};
    if (transport == QLatin1String("remote")) {
        arguments << QStringLiteral("--remote-only");
    }
    startTask(QStringLiteral("test"), deviceId, arguments);
}

void NaviAuthKcm::setupRemote(const QString &deviceId, const QString &server, const QString &token)
{
    const DeviceModel::Device *device = m_devices->find(deviceId);
    if (!device || !device->enrolled) {
        return;
    }
    QStringList arguments{QStringLiteral("remote-setup"), QStringLiteral("--kdeconnect-device"), deviceId,
                          QStringLiteral("--server"), server.trimmed().isEmpty() ? QStringLiteral("https://ntfy.sh") : server.trimmed()};
    if (!token.trimmed().isEmpty()) {
        arguments << QStringLiteral("--token") << token.trimmed();
    }
    // Administrator prompts keep a root copy of the remote settings: refresh it afterwards.
    m_updateAdminAfter = device->adminState == QLatin1String("enabled") ? deviceId : QString();
    startTask(QStringLiteral("remote-setup"), deviceId, arguments);
}

void NaviAuthKcm::removeRemote(const QString &deviceId)
{
    const DeviceModel::Device *device = m_devices->find(deviceId);
    if (!device) {
        return;
    }
    m_updateAdminAfter = device->adminState == QLatin1String("enabled") ? deviceId : QString();
    startTask(QStringLiteral("remote-remove"), deviceId, {QStringLiteral("remote-remove"), QStringLiteral("--kdeconnect-device"), deviceId});
}

void NaviAuthKcm::revoke(const QString &deviceId)
{
    const DeviceModel::Device *device = m_devices->find(deviceId);
    if (!device || device->phoneKeyId.isEmpty()) {
        return;
    }
    if (device->adminState == QLatin1String("enabled")) {
        // Disable administrator prompts first (the helper allows this for the caller's own device),
        // then remove the local enrollment. A failure leaves both in place so it can be retried.
        m_revokeAfterAuthority = deviceId;
        startTask(QStringLiteral("authority-revoke"), deviceId, {QStringLiteral("authority-revoke"), deviceId});
        return;
    }
    startTask(QStringLiteral("revoke"), deviceId, {QStringLiteral("revoke"), device->phoneKeyId});
}

bool NaviAuthKcm::canEnableAdministratorPrompts() const
{
    return !QStandardPaths::findExecutable(pkexec()).isEmpty() && QFileInfo(polkitConfigure()).isExecutable();
}

void NaviAuthKcm::enableAdministratorPrompts(const QString &deviceId)
{
    const DeviceModel::Device *device = m_devices->find(deviceId);
    if (!device || !device->enrolled || device->phoneKeyId.isEmpty() || m_machineId.isEmpty() || m_stateDir.isEmpty()) {
        return;
    }
    // The configurator re-validates everything as root and only accepts this user's own account and state.
    startProcess(QStringLiteral("authority-enable"), deviceId, pkexec(),
                 {polkitConfigure(), QStringLiteral("--source-state"), m_stateDir, QStringLiteral("--uid"), QString::number(getuid()),
                  QStringLiteral("--transport"), QStringLiteral("kdeconnect-share"), QStringLiteral("--kdeconnect-device"), device->id,
                  QStringLiteral("--phone-key-id"), device->phoneKeyId, QStringLiteral("--machine-key-id"), m_machineId,
                  QStringLiteral("--add-phone")});
}

void NaviAuthKcm::disableAdministratorPrompts(const QString &deviceId)
{
    if (m_devices->find(deviceId)) {
        startTask(QStringLiteral("authority-revoke"), deviceId, {QStringLiteral("authority-revoke"), deviceId});
    }
}

bool NaviAuthKcm::authorityAvailable() const
{
    return m_authority.value(QStringLiteral("available")).toBool();
}

bool NaviAuthKcm::authorityConfigured() const
{
    return authorityAvailable() && m_authority.value(QStringLiteral("configured")).toBool() && m_authority.value(QStringLiteral("valid")).toBool()
        && m_authority.value(QStringLiteral("account_matches")).toBool();
}

bool NaviAuthKcm::authorityMachineMismatch() const
{
    const QString rootMachine = m_authority.value(QStringLiteral("machine_key_id")).toString();
    return authorityConfigured() && !rootMachine.isEmpty() && !m_machineId.isEmpty() && rootMachine != m_machineId;
}

QString NaviAuthKcm::authorityProblem() const
{
    if (m_authority.isEmpty()) {
        return {};
    }
    if (!authorityAvailable()) {
        return m_authority.value(QStringLiteral("error")).toString();
    }
    if (!m_authority.value(QStringLiteral("configured")).toBool()) {
        return {}; // Normal before the first administrator setup; shown per device instead.
    }
    if (!m_authority.value(QStringLiteral("valid")).toBool()) {
        return i18n("The protected administrator configuration is invalid: %1", m_authority.value(QStringLiteral("reason")).toString());
    }
    if (!m_authority.value(QStringLiteral("account_matches")).toBool()) {
        return i18n("Administrator prompts on this computer are configured for a different account.");
    }
    return {};
}

bool NaviAuthKcm::kdesuWithoutNavi() const
{
    // host.py reports false only when /usr/libexec/kf6/kdesu exists and lacks the Navi protocol marker.
    const QJsonValue navi = m_authority.value(QStringLiteral("kdesu_navi"));
    if (!authorityConfigured() || !navi.isBool() || navi.toBool()) {
        return false;
    }
    const QJsonArray phones = m_authority.value(QStringLiteral("phones")).toArray();
    return std::any_of(phones.begin(), phones.end(), [](const QJsonValue &phone) {
        return phone.toObject().value(QStringLiteral("enabled")).toBool();
    });
}

void NaviAuthKcm::startTask(const QString &task, const QString &deviceId, const QStringList &arguments)
{
    startProcess(task, deviceId, python(), baseArguments() + arguments);
}

void NaviAuthKcm::startProcess(const QString &task, const QString &deviceId, const QString &program, const QStringList &arguments)
{
    if (busy()) {
        return;
    }
    const DeviceModel::Device *device = m_devices->find(deviceId);
    m_task = task;
    m_taskDeviceId = deviceId;
    m_taskDeviceName = device ? device->name : QString();
    m_code.clear();
    m_offerFile.clear();
    m_codeExpiresAt = 0;
    m_step.clear();
    m_taskError.clear();
    m_taskDone = false;
    m_buffer.clear();
    setMessages(QString(), QString());
    Q_EMIT taskChanged();
    Q_EMIT progressChanged();

    m_process = new QProcess(this);
    m_process->setProcessChannelMode(QProcess::SeparateChannels);
    connect(m_process, &QProcess::readyReadStandardOutput, this, &NaviAuthKcm::taskOutput);
    connect(m_process, &QProcess::finished, this, &NaviAuthKcm::taskExited);
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            m_taskError = i18n("Could not run %1. Is the navi-auth package installed?", m_process ? m_process->program() : hostScript());
            taskExited(-1, QProcess::CrashExit);
        }
    });
    m_process->start(program, arguments);
}

void NaviAuthKcm::cancel()
{
    if (m_process && m_process->state() != QProcess::NotRunning) {
        m_process->terminate(); // SIGTERM: host.py withdraws the request with a signed cancellation.
    }
}

void NaviAuthKcm::taskOutput()
{
    m_buffer += m_process->readAllStandardOutput();
    qsizetype newline;
    while ((newline = m_buffer.indexOf('\n')) >= 0) {
        const QByteArray line = m_buffer.left(newline);
        m_buffer.remove(0, newline + 1);
        const QJsonObject event = QJsonDocument::fromJson(line).object();
        if (!event.isEmpty()) {
            handleEvent(event);
        }
    }
}

void NaviAuthKcm::handleEvent(const QJsonObject &event)
{
    const QString name = event.value(QStringLiteral("event")).toString();
    if (name == QLatin1String("code")) {
        m_code = event.value(QStringLiteral("code")).toString();
        m_offerFile = event.value(QStringLiteral("offer_file")).toString();
        m_codeExpiresAt = qint64(event.value(QStringLiteral("expires_at_ms")).toDouble());
        m_step = QStringLiteral("offer-sent");
        m_expiryTimer.start(int(qBound(qint64(1000), m_codeExpiresAt - QDateTime::currentMSecsSinceEpoch() + 2000, qint64(15 * 60 * 1000))));
        Q_EMIT progressChanged();
    } else if (name == QLatin1String("step")) {
        const QString step = event.value(QStringLiteral("step")).toString();
        if (step == QLatin1String("route")) {
            m_route = event.value(QStringLiteral("route")).toString();
            return;
        }
        if (step != QLatin1String("offer-sent") || m_code.isEmpty()) {
            m_step = step;
        }
        if (step != QLatin1String("offer-sent")) {
            m_expiryTimer.stop();
        }
        Q_EMIT progressChanged();
    } else if (name == QLatin1String("done")) {
        m_taskDone = true;
        m_step = QStringLiteral("done");
        Q_EMIT progressChanged();
    } else if (name == QLatin1String("error")) {
        m_taskError = event.value(QStringLiteral("canceled")).toBool() ? QString() : event.value(QStringLiteral("message")).toString();
    }
}

void NaviAuthKcm::taskExited(int exitCode, QProcess::ExitStatus status)
{
    if (m_task.isEmpty()) {
        return;
    }
    QString standardError;
    if (m_process) {
        taskOutput();
        standardError = QString::fromUtf8(m_process->readAllStandardError()).trimmed();
        m_process->deleteLater();
    }
    m_expiryTimer.stop();
    const QString task = m_task;
    if (task == QLatin1String("authority-enable") && status == QProcess::NormalExit) {
        // pkexec: 126 = authentication dialog dismissed, 127 = not authorized; otherwise the configurator's exit.
        m_taskDone = exitCode == 0;
        if (exitCode == 126) {
            exitCode = 130; // treated as a quiet cancel below
        } else if (exitCode == 127) {
            m_taskError = i18n("Not authorized to change administrator prompts.");
        } else if (exitCode != 0) {
            const QStringList lines = standardError.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
            m_taskError = lines.isEmpty() ? QString() : lines.last();
        }
    }
    const bool success = m_taskDone && exitCode == 0 && status == QProcess::NormalExit;
    QString result;
    if (success) {
        if (task == QLatin1String("enroll")) {
            result = i18n("%1 is enrolled. Use “Send test” to try an approval.", m_taskDeviceName);
        } else if (task == QLatin1String("test")) {
            result = m_route == QLatin1String("ntfy") && m_testTransport != QLatin1String("remote")
                ? i18n("%1 approved the test over ntfy (KDE Connect couldn't see the phone) with a verified signature.", m_taskDeviceName)
                : m_testTransport == QLatin1String("remote")
                ? i18n("%1 approved the test over ntfy (remote approvals) with a verified signature.", m_taskDeviceName)
                : m_testTransport == QLatin1String("network")
                ? i18n("%1 approved the test over the direct network connection with a verified signature.", m_taskDeviceName)
                : i18n("%1 approved the test over KDE Connect messages with a verified signature.", m_taskDeviceName);
        } else if (task == QLatin1String("remote-setup")) {
            result = i18n("%1 can now approve over ntfy when KDE Connect can't see it.", m_taskDeviceName);
        } else if (task == QLatin1String("remote-remove")) {
            result = i18n("Remote approvals are off for %1. Also turn them off in Navi → ☰ → Settings.", m_taskDeviceName);
        } else if (task == QLatin1String("revoke")) {
            result = m_authorityRevoked
                ? i18n("%1 can no longer approve requests from this account or administrator prompts.", m_taskDeviceName)
                : i18n("%1 can no longer approve requests from this account.", m_taskDeviceName);
        } else if (task == QLatin1String("authority-revoke")) {
            result = i18n("%1 can no longer approve administrator prompts.", m_taskDeviceName);
        } else if (task == QLatin1String("authority-enable")) {
            result = i18n("%1 can now approve administrator prompts for this account.", m_taskDeviceName);
        } else {
            result = i18n("This computer's signing identity is ready.");
        }
    }
    QString error = m_taskError;
    if (!success && error.isEmpty() && exitCode != 130 && status == QProcess::NormalExit && exitCode != 0) {
        error = i18n("The operation failed (exit code %1).", exitCode);
    }
    const QString deviceId = m_taskDeviceId;
    m_task.clear();
    m_taskDeviceId.clear();
    const QString chained = std::exchange(m_revokeAfterAuthority, QString());
    if (task == QLatin1String("authority-revoke") && success && chained == deviceId) {
        m_authorityRevoked = true;
        Q_EMIT taskChanged();
        if (const DeviceModel::Device *device = m_devices->find(deviceId)) {
            startTask(QStringLiteral("revoke"), deviceId, {QStringLiteral("revoke"), device->phoneKeyId});
            return;
        }
    }
    if (task != QLatin1String("authority-revoke")) {
        m_authorityRevoked = false;
    }
    m_route.clear();
    const QString updateAdmin = std::exchange(m_updateAdminAfter, QString());
    if ((task == QLatin1String("remote-setup") || task == QLatin1String("remote-remove")) && success && updateAdmin == deviceId
        && canEnableAdministratorPrompts()) {
        // Copy the changed remote settings into the protected administrator entry (password prompt).
        setMessages(QString(), result);
        Q_EMIT taskChanged();
        enableAdministratorPrompts(deviceId);
        return;
    }
    setMessages(error, result);
    Q_EMIT taskChanged();
    Q_EMIT taskFinished(task, success);
    refresh();
}

void NaviAuthKcm::setMessages(const QString &error, const QString &result)
{
    m_lastError = error;
    m_lastResult = result;
    Q_EMIT messageChanged();
}

void NaviAuthKcm::clearMessages()
{
    setMessages(QString(), QString());
}

QString NaviAuthKcm::authorityCommand(const QString &deviceId) const
{
    const DeviceModel::Device *device = m_devices->find(deviceId);
    if (!device || !device->enrolled || m_machineId.isEmpty()) {
        return {};
    }
    const QString configure = QString::fromUtf8(NAVI_AUTH_CONFIGURE_DEFAULT);
    const QString interpreter = QString::fromUtf8(NAVI_AUTH_PYTHON_DEFAULT);
    return QStringLiteral("%1 -I %2 \\\n  --source-state %3 \\\n  --uid %4 --transport kdeconnect-share --kdeconnect-device %5 \\\n"
                          "  --phone-key-id %6 \\\n  --machine-key-id %7 --add-phone\n%1 -I %8 --check")
        .arg(interpreter, configure, quoted(m_stateDir), QString::number(getuid()), device->id, device->phoneKeyId, m_machineId,
             QStringLiteral("/usr/libexec/navi-auth/rootauth.py"));
}

void NaviAuthKcm::copyToClipboard(const QString &text) const
{
    QGuiApplication::clipboard()->setText(text);
}

void NaviAuthKcm::openKdeConnectSettings() const
{
    QProcess::startDetached(QStringLiteral("kcmshell6"), {QStringLiteral("kcm_kdeconnect")});
}

#include "naviauthkcm.moc"
