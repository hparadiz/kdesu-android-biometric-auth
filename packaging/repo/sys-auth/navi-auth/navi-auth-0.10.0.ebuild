EAPI=8

# The installed scripts run the system default /usr/bin/python3 (python-exec, following
# `eselect python`), so a Python upgrade needs no rebuild. python-r1 keeps the required
# modules installed for every Python in PYTHON_TARGETS.
PYTHON_COMPAT=( python3_{12..15} )
inherit python-r1 toolchain-funcs

DESCRIPTION="Navi phone biometric verifier for KDE privileged commands"
HOMEPAGE="https://github.com/hparadiz/kdesu-android-biometric-auth"
S="${WORKDIR}"
LICENSE="MIT"
SLOT="0"
KEYWORDS="amd64"
IUSE="login sudo"
REQUIRED_USE="${PYTHON_REQUIRED_USE}"

RDEPEND="${PYTHON_DEPS}
    dev-python/cryptography[${PYTHON_USEDEP}]
    dev-python/dbus-python[${PYTHON_USEDEP}]
    dev-python/pygobject[${PYTHON_USEDEP}]
    kde-misc/kdeconnect
    sys-auth/polkit
    dev-qt/qttools:6[qdbus]
    login? ( sys-libs/pam )
    sudo? ( app-admin/sudo sys-libs/pam )"

src_unpack() {
    # The reviewed sources are carried in this repository's files/ directory.
    cp -r "${FILESDIR}"/. "${S}"/ || die
}

src_compile() {
    emake CC="$(tc-getCC)" authorize
}

src_install() {
    # USE=sudo / USE=login install the optional phone-approval helpers; PAM files are never edited here.
    # NAVI_AUTH_MAX_COMMAND (e.g. in /etc/portage/env/navi-auth.conf + package.env) sets the longest
    # command offered for phone approval, 512-16384 characters (default 10240). Navi must be built
    # with at least the same limit.
    emake DESTDIR="${D}" POLKIT_SRC=. ENABLE_SUDO=$(usex sudo yes no) ENABLE_LOGIN=$(usex login yes no) \
        MAX_COMMAND="${NAVI_AUTH_MAX_COMMAND:-10240}" install
    fperms 4755 /usr/libexec/navi-auth/authorize
}

pkg_postinst() {
    elog "Commands up to ${NAVI_AUTH_MAX_COMMAND:-10240} characters are offered for phone approval"
    elog "(NAVI_AUTH_MAX_COMMAND). Requests are compressed with the bundled dictionary, so Navi must be"
    elog "version 0.13.0 or newer."
    # The helper and configurator start /usr/bin/python3 -I; its default must have the modules.
    if ! /usr/bin/python3 -I -c 'import cryptography, dbus, gi' >/dev/null 2>&1; then
        ewarn "The default /usr/bin/python3 ($(/usr/bin/python3 -I -c 'import sys; print(sys.version.split()[0])' 2>/dev/null))"
        ewarn "cannot import cryptography, dbus and gi. Administrator prompts and the settings page"
        ewarn "will fail until the default Python (eselect python) is listed in PYTHON_TARGETS"
        ewarn "and navi-auth's dependencies are rebuilt for it."
    fi
    if use sudo || use login; then
        elog "Optional phone approval is installed but not active. Turn it on in"
        elog "System Settings -> Navi Authenticator (asks for the administrator password),"
        elog "or as root: /usr/libexec/navi-auth/navi-pam enable SERVICE"
        use sudo && elog "  sudo: sudo in local Konsole/Kitty terminals (/etc/pam.d/sudo)"
        use login && elog "  sddm: the SDDM login screen; kde: the Plasma lock screen (Enter with an empty"
        use login && elog "        password asks the phone; typing the password works as before)"
        elog "Each adds one line to /etc/pam.d/SERVICE; 'navi-pam disable SERVICE' removes it."
        elog "Console logins, SSH, su, pkexec and polkit prompts keep using passwords."
        use login && elog "The SDDM login needs Remote Approvals (ntfy): KDE Connect only runs after login."
    fi
}
