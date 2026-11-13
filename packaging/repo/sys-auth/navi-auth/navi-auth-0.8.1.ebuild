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
IUSE=""
REQUIRED_USE="${PYTHON_REQUIRED_USE}"

RDEPEND="${PYTHON_DEPS}
    dev-python/cryptography[${PYTHON_USEDEP}]
    dev-python/dbus-python[${PYTHON_USEDEP}]
    dev-python/pygobject[${PYTHON_USEDEP}]
    kde-misc/kdeconnect
    sys-auth/polkit
    dev-qt/qttools:6[qdbus]"

src_compile() {
    $(tc-getCC) ${CFLAGS} ${LDFLAGS} -fPIE -pie -Wl,-z,relro,-z,now \
        -o authorize "${FILESDIR}/authorize.c" || die
}

src_install() {
    exeinto /usr/libexec/navi-auth
    doexe "${FILESDIR}/rootauth.py" "${FILESDIR}/host.py" "${FILESDIR}/configure-authority.py" "${FILESDIR}/kdeconnect_transport.py"
    doexe authorize
    # polkit entry point for "Administrator prompts" in System Settings.
    newexe "${FILESDIR}/navi-auth-configure" configure
    insinto /usr/share/polkit-1/actions
    doins "${FILESDIR}/in.akuj.navi-auth.policy"
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
}
