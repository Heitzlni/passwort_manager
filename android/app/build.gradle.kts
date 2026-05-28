plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.example.passwort_manager"
    // Pin to the NDK we actually have installed — otherwise AGP picks
    // its bundled default (currently 28.2.x) and warns on every build.
    ndkVersion = "29.0.14206865"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.example.passwort_manager"
        minSdk = 26               // Android 8.0 — Autofill Framework floor.
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // We only ship arm64 for now — covers every phone built since
        // 2017 and keeps the APK small.
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
}

// ===================== Rust JNI build =====================
//
// We don't use a heavyweight Gradle-Rust plugin — they tend to lag
// AGP releases. Just shell out to cargo-ndk, which knows how to drive
// the NDK toolchain for cross-compile and writes the .so into the
// right jniLibs/<abi>/ structure.
//
// Maps:
//   :crypto crate (../crypto)  →  src/main/jniLibs/arm64-v8a/libpasswort_jni.so
//
// Build mode: always --release on the Rust side. Argon2id at debug
// speeds is painful.

val rustCrateDir = file("../crypto")
val jniLibsDir = file("src/main/jniLibs")

val cargoNdkBuild by tasks.registering(Exec::class) {
    group = "build"
    description = "Cross-compile the Rust crypto crate for arm64 Android"

    val home = System.getProperty("user.home")
    val cargo = "$home/.cargo/bin/cargo"
    val ndkDir = "$home/Android/Sdk/ndk/29.0.14206865"

    workingDir = rustCrateDir
    environment("ANDROID_NDK_HOME", ndkDir)
    environment(
        "PATH",
        "$home/.cargo/bin:${System.getenv("PATH") ?: ""}"
    )

    // cargo-ndk is a cargo subcommand, not a standalone tool: invoke
    // via `cargo ndk ...` so it can locate cargo itself.
    commandLine(
        cargo, "ndk",
        "-t", "arm64-v8a",
        "-o", jniLibsDir.absolutePath,
        "build",
        "--release"
    )

    inputs.dir(rustCrateDir.resolve("src"))
    inputs.file(rustCrateDir.resolve("Cargo.toml"))
    outputs.dir(jniLibsDir)
}

// Wire the Rust build into every variant's "merge JNI libs" step so
// the .so is present before AGP packages the APK.
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }
    .configureEach { dependsOn(cargoNdkBuild) }

tasks.named("clean") {
    doLast {
        delete(jniLibsDir)
        delete(rustCrateDir.resolve("target"))
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    // Brings ContentCopy / Visibility / VisibilityOff etc. that aren't
    // in the (smaller) icons-core artifact pulled in by material3.
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment)
    implementation(libs.androidx.autofill)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
