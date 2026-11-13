# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.22)
project(navi-auth-kcm VERSION 0.8.1 LANGUAGES CXX)

set(QT_MIN_VERSION "6.6.0")
set(KF_MIN_VERSION "6.0.0")

find_package(ECM ${KF_MIN_VERSION} REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)
include(FeatureSummary)

find_package(Qt6 ${QT_MIN_VERSION} REQUIRED COMPONENTS Core DBus Gui Quick)
find_package(KF6 ${KF_MIN_VERSION} REQUIRED COMPONENTS CoreAddons I18n KCMUtils)
find_package(KF6Kirigami ${KF_MIN_VERSION})
set_package_properties(KF6Kirigami PROPERTIES TYPE RUNTIME)

# Installed paths of the navi-auth package; NAVI_AUTH_HOST/NAVI_AUTH_PYTHON override at runtime.
set(NAVI_AUTH_HOST "/usr/libexec/navi-auth/host.py" CACHE STRING "Installed host.py")
set(NAVI_AUTH_CONFIGURE "/usr/libexec/navi-auth/configure-authority.py" CACHE STRING "Installed configurator")
set(NAVI_AUTH_PYTHON "/usr/bin/python3.14" CACHE STRING "Interpreter for host.py")
set(NAVI_AUTH_POLKIT_CONFIGURE "/usr/libexec/navi-auth/configure" CACHE STRING "pkexec entry point for the configurator")

add_definitions(-DTRANSLATION_DOMAIN=\"kcm_navi_auth\")

kcmutils_add_qml_kcm(kcm_navi_auth SOURCES naviauthkcm.cpp devicemodel.cpp)
target_compile_definitions(kcm_navi_auth PRIVATE
    NAVI_AUTH_HOST_DEFAULT="${NAVI_AUTH_HOST}"
    NAVI_AUTH_CONFIGURE_DEFAULT="${NAVI_AUTH_CONFIGURE}"
    NAVI_AUTH_PYTHON_DEFAULT="${NAVI_AUTH_PYTHON}"
    NAVI_AUTH_POLKIT_CONFIGURE_DEFAULT="${NAVI_AUTH_POLKIT_CONFIGURE}")
target_link_libraries(kcm_navi_auth PRIVATE
    Qt::Core Qt::DBus Qt::Gui Qt::Quick
    KF6::CoreAddons KF6::I18n KF6::KCMUtilsQuick)

feature_summary(WHAT ALL INCLUDE_QUIET_PACKAGES FATAL_ON_MISSING_REQUIRED_PACKAGES)
