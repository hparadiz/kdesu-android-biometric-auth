EAPI=8

inherit cmake

DESCRIPTION="System Settings page to enroll and test Navi phone authenticators"
HOMEPAGE="https://github.com/hparadiz/kdesu-android-biometric-auth"
S="${WORKDIR}/kcm"
LICENSE="MIT"
SLOT="0"
KEYWORDS="amd64"
IUSE=""

DEPEND="dev-qt/qtbase:6[dbus,gui]
    dev-qt/qtdeclarative:6
    kde-frameworks/kcmutils:6
    kde-frameworks/kcoreaddons:6
    kde-frameworks/ki18n:6"
RDEPEND="${DEPEND}
    =sys-auth/navi-auth-${PV}
    kde-frameworks/kirigami:6
    kde-misc/kdeconnect"
BDEPEND="kde-frameworks/extra-cmake-modules:0"

src_unpack() {
    # The reviewed source is carried in this repository, like navi-auth's files.
    cp -r "${FILESDIR}/kcm" "${S}" || die
}

src_configure() {
    local mycmakeargs=(
        -DNAVI_AUTH_HOST=/usr/libexec/navi-auth/host.py
        -DNAVI_AUTH_CONFIGURE=/usr/libexec/navi-auth/configure-authority.py
        -DNAVI_AUTH_PYTHON=/usr/bin/python3.14
        -DNAVI_AUTH_POLKIT_CONFIGURE=/usr/libexec/navi-auth/configure
    )
    cmake_src_configure
}
