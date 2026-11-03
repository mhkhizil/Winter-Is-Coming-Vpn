// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.winteriscoming.vpn"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.winteriscoming.vpn"
        // wireguard-android supports API 21+; 24 keeps us clear of pre-N TLS quirks.
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    // The tunnel library uses Java 8+ APIs that need desugaring on older runtimes.
    // Documented requirement of com.wireguard.android:tunnel.
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // Where the app talks to the control plane. Override per build type or with
    // -PapiBaseUrl; production must be an https:// URL terminated by nginx/Caddy
    // (ADR-0009), because the server refuses plaintext when require_https is on.
    defaultConfig {
        buildConfigField(
            "String",
            "API_BASE_URL",
            "\"${project.findProperty("apiBaseUrl") ?: "https://vpn.example.com"}\"",
        )
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
    }
}

dependencies {
    // The official tunnel: reference-correct WireGuard, Apache-2.0. Embedding it
    // means every session also proves our server interoperates with the official
    // implementation - the project's biggest open risk (ADR-0012).
    implementation("com.wireguard.android:tunnel:1.0.20260102")
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.3")

    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")  // android org.json is stubbed on the JVM
}
