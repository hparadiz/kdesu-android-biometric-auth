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
IUSE="sudo"
REQUIRED_USE="${PYTHON_REQUIRED_USE}"

RDEPEND="${PYTHON_DEPS}
    dev-python/cryptography[${PYTHON_USEDEP}]
    dev-python/dbus-python[${PYTHON_USEDEP}]
    dev-python/pygobject[${PYTHON_USEDEP}]
    kde-misc/kdeconnect
    sys-auth/polkit
    dev-qt/qttools:6[qdbus]
    sudo? ( app-admin/sudo sys-libs/pam )"

src_unpack() {
    # The reviewed sources are carried in this repository's files/ directory.
    cp -r "${FILESDIR}"/. "${S}"/ || die
}

src_compile() {
    emake CC="$(tc-getCC)" authorize
}

src_install() {
    # USE=sudo installs the optional sudo approval helper; PAM configuration is never edited.
    emake DESTDIR="${D}" POLKIT_SRC=. ENABLE_SUDO=$(usex sudo yes no) install
    fperms 4755 /usr/libexec/navi-auth/authorize
}

pkg_postinst() {
    # The helper and configurator start /usr/bin/python3 -I; its default must have the modules.
    if ! /usr/bin/python3 -I -c 'import cryptography, dbus, gi' >/dev/null 2>&1; then
        ewarn "The default /usr/bin/python3 ($(/usr/bin/python3 -I -c 'import sys; print(sys.version.split()[0])' 2>/dev/null))"
        ewarn "cannot import cryptography, dbus and gi. Administrator prompts and the settings page"
        ewarn "will fail until the default Python (eselect python) is listed in PYTHON_TARGETS"
        ewarn "and navi-auth's dependencies are rebuilt for it."
    fi
    if use sudo; then
        elog "Phone approval for sudo is installed but not active. Turn it on in"
        elog "System Settings -> Navi Authenticator (asks for the administrator password),"
        elog "or as root: /usr/libexec/navi-auth/sudo-pam enable"
        elog "It adds one line to /etc/pam.d/sudo; 'sudo-pam disable' removes it."
        elog "Only sudo in local Konsole/Kitty terminals is affected; SSH, other terminals,"
        elog "su, pkexec and polkit prompts keep using passwords. If an app-admin/sudo update"
        elog "replaces /etc/pam.d/sudo, System Settings offers to restore the line."
    fi
}
