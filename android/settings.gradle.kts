// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Android client for the vpn server. See ../docs/CLIENT_INTEGRATION.md for the
// contract and ../docs/DECISIONS/ADR-0012-android-client-tunnel.md for why the
// tunnel is the official WireGuard library rather than our own NDK port.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "winter-vpn"
include(":app")
