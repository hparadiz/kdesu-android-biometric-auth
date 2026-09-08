EAPI=8

inherit toolchain-funcs

DESCRIPTION="Navi phone biometric verifier for KDE privileged commands"
HOMEPAGE="https://github.com/hparadiz/kdesu-android-biometric-auth"
S="${WORKDIR}"
LICENSE="MIT"
SLOT="0"
KEYWORDS="amd64"
IUSE=""

RDEPEND="dev-lang/python:3.14
    dev-python/cryptography[python_targets_python3_14]
    dev-python/dbus-python[python_targets_python3_14]
    dev-python/pygobject[python_targets_python3_14]
    kde-misc/kdeconnect
    dev-qt/qttools:6[qdbus]"

src_compile() {
    $(tc-getCC) ${CFLAGS} ${LDFLAGS} -fPIE -pie -Wl,-z,relro,-z,now \
        -o authorize "${FILESDIR}/authorize.c" || die
}

src_install() {
    exeinto /usr/libexec/navi-auth
    doexe "${FILESDIR}/rootauth.py" "${FILESDIR}/host.py" "${FILESDIR}/configure-authority.py" "${FILESDIR}/kdeconnect_transport.py"
    doexe authorize
    fperms 4755 /usr/libexec/navi-auth/authorize
}
