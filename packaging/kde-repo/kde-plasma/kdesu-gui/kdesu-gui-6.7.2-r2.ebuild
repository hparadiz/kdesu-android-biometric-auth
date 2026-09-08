# Copyright 1999-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

ECM_HANDBOOK="forceoff"
ECM_TEST="false"
KDE_ORG_NAME="kde-cli-tools"
KFMIN=6.26.0
QTMIN=6.10.1
inherit ecm plasma.kde.org

DESCRIPTION="Graphical frontend for KDE Frameworks' kdesu"
HOMEPAGE="https://invent.kde.org/plasma/kde-cli-tools"

LICENSE="Artistic-2 GPL-2 MIT"
SLOT="0"
KEYWORDS="~amd64 ~arm64 ~ppc64 ~riscv ~x86"
IUSE="X"

DEPEND="
	>=dev-qt/qtbase-${QTMIN}:6=[gui,network,widgets]
	>=dev-qt/qtsvg-${QTMIN}:6
	>=kde-frameworks/kguiaddons-${KFMIN}:6
	>=kde-frameworks/kconfig-${KFMIN}:6
	>=kde-frameworks/kcoreaddons-${KFMIN}:6
	>=kde-frameworks/kdesu-${KFMIN}:6
	>=kde-frameworks/ki18n-${KFMIN}:6
	>=kde-frameworks/kwidgetsaddons-${KFMIN}:6
	>=kde-frameworks/kwindowsystem-${KFMIN}:6[X?]
"
RDEPEND="${DEPEND}
	!<${CATEGORY}/${KDE_ORG_NAME}-6.1.4-r2:*[kdesu(+)]
	>=${CATEGORY}/${KDE_ORG_NAME}-common-${PV}
	sys-apps/dbus[X]
"

# downstream split
PATCHES=(
	"${FILESDIR}/${PN}-6.1.80-build-only-kdesu.patch"
	"${FILESDIR}/${PN}-6.7.2-r2-navi.patch"
)

src_prepare() {
	ecm_src_prepare
	ecm_punt_po_install
}

src_configure() {
	local mycmakeargs=(
		-DWITH_X11=$(usex X)
		-DBUILD_TESTING=OFF
	)
	ecm_src_configure
}

src_install() {
	ecm_src_install
	dosym ../libexec/kf6/kdesu /usr/bin/kdesu
}
