plugins {
    id("com.android.application") version "8.7.3"
    id("org.jetbrains.kotlin.android") version "2.0.21"
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21"
}

dependencyLocking { lockAllConfigurations() }

val releaseStore = System.getenv("BIFROST_ANDROID_KEYSTORE")
val releaseStorePassword = System.getenv("BIFROST_ANDROID_KEYSTORE_PASSWORD")
val releaseAlias = System.getenv("BIFROST_ANDROID_KEY_ALIAS")
val releaseKeyPassword = System.getenv("BIFROST_ANDROID_KEY_PASSWORD")
val releaseSigningReady = listOf(releaseStore, releaseStorePassword, releaseAlias, releaseKeyPassword).all { !it.isNullOrBlank() } &&
    releaseStore?.let { file(it).isFile } == true
val releaseSigningScope = if (releaseSigningReady) "signed" else "unsigned-local"
val releaseSequence = System.getenv("BIFROST_RELEASE_SEQUENCE")?.toLongOrNull() ?: 0L
if (releaseSigningReady && releaseSequence <= 0L) throw GradleException("BF-RELEASE-SEQUENCE: signed APK requires its immutable release sequence")
// Release trust-root provisioning is an explicit offline ceremony input. No
// test vector or mutable release-directory key is a production trust root.
// Test roots are scoped to the explicit debug/corpus-test variant property;
// task-name inspection is deliberately not used as an authority boundary.
val bifrostTestVariant = providers.gradleProperty("bifrostTestVariant").orNull == "true"
val provisionedReleaseRoot = providers.gradleProperty("releaseTrustRootFile").orNull?.let {
    val candidate = file(it)
    if (!candidate.isAbsolute) throw GradleException("BF-KEYS-PATH")
    candidate
} ?: if (bifrostTestVariant) file("src/test/resources/com/bifrost/client/release-test-root.json") else null
val releaseTrustRootTestOnly = providers.gradleProperty("releaseTrustRootTestOnly").orNull == "true"
if (releaseTrustRootTestOnly && !bifrostTestVariant) throw GradleException("BF-RELEASE-TEST-VARIANT-REQUIRED")
if (bifrostTestVariant && !releaseTrustRootTestOnly) throw GradleException("BF-RELEASE-TEST-VARIANT-ROOT-REQUIRED")
val releaseRootProvisioned = provisionedReleaseRoot?.isFile == true
if (releaseSigningReady && !releaseRootProvisioned) throw GradleException("BF-RELEASE-TRUST-ROOT-PENDING: explicit offline ceremony artifact is required")

val releaseBindingSourceSet = if (bifrostTestVariant) "debug" else "main"
val releaseTrustBindingDir = layout.buildDirectory.dir("generated/source/${if (bifrostTestVariant) "bifrostTest/debug" else "releaseTrust/main"}")
val generateReleaseTrustBinding = tasks.register("generateReleaseTrustBinding") {
    val input = provisionedReleaseRoot
    inputs.property("ceremonyPath", input?.absolutePath ?: "")
    outputs.dir(releaseTrustBindingDir)
    doLast {
        val out = releaseTrustBindingDir.get().asFile
        out.deleteRecursively(); out.mkdirs()
        val target = out.resolve("com/bifrost/client/ReleaseTrustBinding.kt")
        target.parentFile.mkdirs()
        if (input == null) {
            target.writeText("""
                package com.bifrost.client
                internal object ReleaseTrustBinding {
                    const val TRUST_ROOT_KEY_ID = "bifrost-root-v1"
                    val TRUST_ROOT_PEM: String? = null
                    const val TRUST_ROOT_PROVISIONED = false
                    val TRUST_ROOT_FINGERPRINT: String? = null
                    const val BUILD_MARKER = "UNPROVISIONED-RELEASE-TRUST-BINDING"
                }
            """.trimIndent() + "\n")
        } else {
                exec {
                val args = mutableListOf("node", rootProject.file("../tools/provision-release-root.mjs").absolutePath, "--input", input.absolutePath, "--kotlin-output", target.absolutePath)
                if (releaseTrustRootTestOnly) args += "--test-only"
                commandLine(args)
                }
        }
    }
}

android { namespace = "com.bifrost.client"; compileSdk = 35
    // Pin the native stripper: otherwise AGP can silently ship Go debug tables.
    ndkVersion = "28.2.13676358"
    defaultConfig {
        applicationId = "com.bifrost.client"
        minSdk = 28
        targetSdk = 35
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    versionCode = 20241
    versionName = "2.2.41"
        // The control plane URL is deliberately a build-time default only.
        // Production installs may override it through the signed enrollment
        // flow; no node credentials are embedded in the APK.
        val configuredControlUrl = (System.getenv("BIFROST_CONTROL_BASE_URL") ?: "")
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
        buildConfigField("String", "CONTROL_BASE_URL", "\"$configuredControlUrl\"")
        buildConfigField("String", "RELEASE_SIGNING_SCOPE", "\"$releaseSigningScope\"")
        buildConfigField("long", "RELEASE_SEQUENCE", "${releaseSequence}L")
        buildConfigField("boolean", "BIFROST_TEST_VARIANT", bifrostTestVariant.toString())
    }
    signingConfigs {
        // Direct Gradle validation intentionally emits an explicitly marked
        // unsigned-local APK when production signing material is absent. The
        // release packaging script below remains fail-closed.
        if (releaseSigningReady) create("bifrostRelease") {
            storeFile = file(releaseStore!!)
            storePassword = releaseStorePassword!!
            keyAlias = releaseAlias!!
            keyPassword = releaseKeyPassword!!
        }
    }
    buildTypes {
        getByName("debug") {
            if (bifrostTestVariant) applicationIdSuffix = ".test"
        }
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = if (releaseSigningReady) signingConfigs.getByName("bifrostRelease") else null
        }
    }
    // Ship one installable APK per supported ABI.  The universal variant is
    // intentionally disabled for release/update distribution because libbox
    // is large; offline lab builds may still create a universal artifact via
    // an explicit Gradle task, but the signed update manifest never selects it.
    splits {
        abi {
            isEnable = true
            reset()
            include("armeabi-v7a", "arm64-v8a", "x86_64")
            isUniversalApk = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true; buildConfig = true; aidl = true }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
        jniLibs.useLegacyPackaging = false
    }
}

kotlin.sourceSets.getByName(releaseBindingSourceSet).kotlin.srcDir(releaseTrustBindingDir)
kotlin.sourceSets.getByName("test").kotlin.srcDir("src/sharedTest/java")
kotlin.sourceSets.getByName("androidTest").kotlin.srcDir("src/sharedTest/java")
android.sourceSets.getByName("androidTest").resources.srcDir("src/test/resources")

// Small privileged TUN/route helper. It contains no account keys or proxy
// implementation; all three app ABIs use the same pinned NDK and source.
val generatedRootHelpers = layout.buildDirectory.dir("generated/rootHelpers")
val generatedRootJni = layout.buildDirectory.dir("generated/rootJni")
val buildRootHelpers = tasks.register("buildRootHelpers") {
    val source = layout.projectDirectory.file("src/main/cpp/bifrost_root.cpp")
    val socketSource = layout.projectDirectory.file("src/main/cpp/bifrost_socket.cpp")
    inputs.file(source)
    inputs.file(socketSource)
    inputs.file(layout.projectDirectory.file("src/main/cpp/bifrost_root_mark.h"))
    inputs.file(layout.projectDirectory.file("src/main/cpp/bifrost_connection_owner.h"))
    inputs.property("ndk", android.ndkVersion)
    outputs.dir(generatedRootHelpers)
    outputs.dir(generatedRootJni)
    doLast {
        // A production invocation commonly runs `clean lintRelease
        // assembleRelease` in one Gradle graph.  Do not rely on an implicit
        // parent created by a previous incremental build: native linkers do
        // not create their `-o` parent directory and a pristine workspace
        // must be buildable in one pass.
        val helperRoot = generatedRootHelpers.get().asFile.resolve("root")
        val jniRoot = generatedRootJni.get().asFile
        if (!helperRoot.isDirectory && !helperRoot.mkdirs())
            throw GradleException("BF-ROOT-OUTPUT: cannot create ${helperRoot.absolutePath}")
        if (!jniRoot.isDirectory && !jniRoot.mkdirs())
            throw GradleException("BF-ROOT-OUTPUT: cannot create ${jniRoot.absolutePath}")
        val sdk = System.getenv("ANDROID_SDK_ROOT") ?: System.getenv("ANDROID_HOME")
            ?: throw GradleException("BF-ROOT-NDK: ANDROID_SDK_ROOT is required")
        val host = if (System.getProperty("os.name").startsWith("Windows")) "windows-x86_64"
            else if (System.getProperty("os.name").startsWith("Mac")) "darwin-x86_64" else "linux-x86_64"
        val compiler = file("$sdk/ndk/" + android.ndkVersion + "/toolchains/llvm/prebuilt/$host/bin/clang++" +
            if (host.startsWith("windows")) ".exe" else "")
        val targets = mapOf("arm64-v8a" to "aarch64-linux-android28", "armeabi-v7a" to "armv7a-linux-androideabi28",
            "x86_64" to "x86_64-linux-android28")
        targets.forEach { (abi, target) ->
            val output = generatedRootHelpers.get().file("root/$abi/bifrost-root").asFile
            if (!output.parentFile.isDirectory && !output.parentFile.mkdirs())
                throw GradleException("BF-ROOT-OUTPUT: cannot create ${output.parentFile.absolutePath}")
            exec { commandLine(compiler.absolutePath, "--target=$target", "-std=c++17", "-O2",
                "-fPIE", "-pie", "-static-libstdc++", "-fstack-protector-strong",
                "-Wl,--strip-all,-z,relro,-z,now,-z,max-page-size=16384", "-Wall", "-Wextra", "-Werror",
                source.asFile.absolutePath, "-o", output.absolutePath) }
            val socketOutput = generatedRootJni.get().file("$abi/libbifrost_socket.so").asFile
            if (!socketOutput.parentFile.isDirectory && !socketOutput.parentFile.mkdirs())
                throw GradleException("BF-ROOT-OUTPUT: cannot create ${socketOutput.parentFile.absolutePath}")
            exec { commandLine(compiler.absolutePath, "--target=$target", "-std=c++17", "-O2",
                "-fPIC", "-shared", "-static-libstdc++", "-fstack-protector-strong",
                "-Wl,--strip-all,-z,relro,-z,now,-z,max-page-size=16384", "-Wall", "-Wextra", "-Werror",
                socketSource.asFile.absolutePath, "-o", socketOutput.absolutePath) }
        }
    }
}
android.sourceSets.getByName("main").assets.srcDir(generatedRootHelpers)
android.sourceSets.getByName("main").jniLibs.srcDir(generatedRootJni)
tasks.matching { it.name == "preBuild" }.configureEach { dependsOn(buildRootHelpers) }

// License/source-offer bytes are copied into the APK from the checked-in
// client boundary at build time.  They are not a UI summary and are not
// sourced from the workspace or a mutable release directory at runtime.
val generatedLicenseAssets = layout.buildDirectory.dir("generated/assets/main/licenses")
val syncLicenseAssets = tasks.register("syncLicenseAssets") {
    val sourceRoot = rootProject.projectDir.parentFile
    val inputsToShip = listOf(
        sourceRoot.resolve("COPYING"),
        sourceRoot.resolve("licenses/GPL-3.0-only.txt"),
        sourceRoot.resolve("licenses/Apache-2.0.txt"),
        sourceRoot.resolve("licenses/MPL-2.0.txt"),
        sourceRoot.resolve("licenses/MIT.txt"),
        sourceRoot.resolve("licenses/domain-list-community-MIT.txt"),
        sourceRoot.resolve("licenses/ios-rule-script-GPL-2.0.txt"),
        sourceRoot.resolve("LICENSES.txt"),
        sourceRoot.resolve("THIRD_PARTY_NOTICES.md"),
        sourceRoot.resolve("INSTALLATION_INFORMATION.md"),
        sourceRoot.resolve("CORE_PROVENANCE.md"),
    )
    inputs.files(inputsToShip)
    outputs.dir(generatedLicenseAssets)
    doLast {
        val output = generatedLicenseAssets.get().asFile
        output.deleteRecursively(); output.mkdirs()
        inputsToShip.forEach { source ->
            if (!source.isFile) throw GradleException("BF-LICENSE-ASSET-MISSING:${source.name}")
            source.copyTo(output.resolve(source.name), overwrite = false)
        }
    }
}
android.sourceSets.getByName("main").assets.srcDir(generatedLicenseAssets)
tasks.matching { it.name == "preBuild" || it.name.startsWith("merge") && it.name.endsWith("Assets") }.configureEach {
    dependsOn(syncLicenseAssets)
}
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    dependsOn(generateReleaseTrustBinding)
}

val releaseSigningMarker = tasks.register("writeReleaseSigningMarker") {
    val marker = layout.buildDirectory.file("outputs/apk/release/Bifrost-release-signing.txt")
    outputs.file(marker)
    doLast {
        val output = marker.get().asFile
        output.parentFile.mkdirs()
        output.writeText("scope=$releaseSigningScope\nproduction_signing_material_present=$releaseSigningReady\n")
    }
}
// AGP registers variant assemble tasks lazily.  Use a future-safe callback so
// direct unsigned-local builds work with both the pinned and newer AGP plugin
// without failing during script evaluation when the task is not registered yet.
tasks.configureEach {
    if (name == "assembleRelease") finalizedBy(releaseSigningMarker)
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("com.github.topjohnwu.libsu:service:6.0.0")
    implementation(files("libs/libbox.aar"))
    // Pure-Java Ed25519 verification usable on API 28; platform Ed25519
    // KeyFactory/Signature are only available from API 33.
    implementation("com.google.crypto.tink:tink-android:1.8.0")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    testImplementation("junit:junit:4.13.2")
    // The Android framework's org.json methods are stubs on the local JVM;
    // use the same API-compatible implementation for executable compiler
    // contract tests (the APK continues to use the platform implementation).
    testImplementation("org.json:json:20240303")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

// Deterministic evidence is deliberately a test/build-only task. It executes
// the compiled debug production policy and test exporter on Gradle's own
// unit-test runtime classpath; it never becomes part of the release APK.
val r63AndroidPolicySource = layout.projectDirectory.file("src/main/java/com/bifrost/client/ui/model/BifrostAndroidLayoutPolicy.kt")
val r63AndroidExporterSource = layout.projectDirectory.file("src/test/java/com/bifrost/client/BifrostAndroidLayoutPolicyEvidenceExporter.kt")
val r63AndroidEvidenceOutput = providers.gradleProperty("r63AndroidLayoutEvidenceOutput")
    .orElse(layout.projectDirectory.file("../artifacts/ui-acceptance/r63-remediation-9/android-policy-exporter.json").asFile.absolutePath)
tasks.register<JavaExec>("exportR63AndroidLayoutPolicyEvidence") {
    group = "verification"
    description = "Execute the production Android layout policy and export canonical R63 evidence."
    dependsOn(
        "compileDebugKotlin",
        "compileDebugJavaWithJavac",
        "compileDebugUnitTestKotlin",
        "compileDebugUnitTestJavaWithJavac",
    )
    classpath(
        files(
            layout.buildDirectory.dir("tmp/kotlin-classes/debug"),
            layout.buildDirectory.dir("tmp/kotlin-classes/debugUnitTest"),
            layout.buildDirectory.dir("intermediates/javac/debug/compileDebugJavaWithJavac/classes"),
            layout.buildDirectory.dir("intermediates/javac/debugUnitTest/compileDebugUnitTestJavaWithJavac/classes"),
        ),
        configurations.getByName("debugUnitTestRuntimeClasspath"),
    )
    mainClass.set("com.bifrost.client.BifrostAndroidLayoutPolicyEvidenceExporter")
    args(r63AndroidEvidenceOutput.get(), r63AndroidPolicySource.asFile.absolutePath)
    inputs.file(r63AndroidPolicySource)
    inputs.file(r63AndroidExporterSource)
    outputs.file(r63AndroidEvidenceOutput)
    workingDir(projectDir)
}
