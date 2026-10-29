import java.util.Properties
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.oguzhanstech.hybridvpn"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.oguzhanstech.hybridvpn"
        minSdk = 24
        targetSdk = 37
        versionCode = 9
        versionName = "0.6.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Only an explicitly requested public-release build produces per-ABI downloads.
    if (providers.gradleProperty("publicRelease").orNull == "true") {
        splits {
            abi {
                isEnable = true
                reset()
                include("arm64-v8a", "x86_64")
                isUniversalApk = true
            }
        }
        packaging.jniLibs.excludes += setOf("**/armeabi-v7a/**", "**/x86/**")
    }

    buildTypes {
        release {
            optimization {
                enable = true
                packageScope = setOf("androidx.**", "kotlin.**", "kotlinx.**")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true // BuildConfig.DEBUG gates experimental engines
    }
}

ksp {
    // Exported Room schemas are versioned with the source so migrations can be tested.
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    implementation(project(":engine"))
    implementation(project(":discovery"))
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
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

// --- Go network engine (spike, ADR 0003) ---------------------------------------------------------
// libhybridvpn_go.so is built from ../go with the NDK's clang, only when an NDK is installed.
// Without an NDK the app builds exactly as before and GoBridge reports the engine as unavailable.

abstract class GoJniTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val goModule: DirectoryProperty

    @get:Input abstract val ndkDir: Property<String>
    @get:Input abstract val apiLevel: Property<Int>
    @get:Input abstract val goExecutable: Property<String>
    @get:Input abstract val abis: ListProperty<String>
    /** Link OpenVPN 3 Core (third_party/ built by scripts/openvpn3-deps.sh). */
    @get:Input abstract val openvpn3: Property<Boolean>
    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    @get:Inject abstract val exec: ExecOperations

    @TaskAction
    fun build() {
        val prebuilt = File(ndkDir.get(), "toolchains/llvm/prebuilt").listFiles()?.firstOrNull()
            ?: throw GradleException("No LLVM toolchain under ${ndkDir.get()}")
        for (abi in abis.get()) {
            val (goArch, triple) = when (abi) {
                "arm64-v8a" -> "arm64" to "aarch64-linux-android"
                "x86_64" -> "amd64" to "x86_64-linux-android"
                else -> throw GradleException("Unsupported ABI $abi")
            }
            val out = outputDir.file("$abi/libhybridvpn_go.so").get().asFile
            exec.exec {
                workingDir = goModule.get().asFile
                environment("GOOS", "android")
                environment("GOARCH", goArch)
                environment("CGO_ENABLED", "1")
                environment("GOTOOLCHAIN", "auto") // go.mod pins the toolchain (fetched once, checksum-verified)
                environment("CC", File(prebuilt, "bin/$triple${apiLevel.get()}-clang").absolutePath)
                environment("CXX", File(prebuilt, "bin/$triple${apiLevel.get()}-clang++").absolutePath)
                val tags = if (openvpn3.get()) listOf("-tags", "openvpn3") else emptyList()
                // Keep the statically linked OpenSSL and libc++ out of the export table. Set here,
                // not in a #cgo directive, because cgo's flag allowlist rejects it.
                if (openvpn3.get()) environment("CGO_LDFLAGS", "-Wl,--exclude-libs,ALL")
                commandLine(listOf(goExecutable.get(), "build", "-buildmode=c-shared", "-trimpath", "-ldflags=-s -w") + tags +
                    listOf("-o", out.absolutePath, "./jni"))
            }
            File(out.parentFile, "libhybridvpn_go.h").delete()
        }
    }
}

fun findNdk(): File? {
    val local = Properties().apply { rootProject.file("local.properties").takeIf { it.exists() }?.reader()?.use(::load) }
    local.getProperty("ndk.dir")?.let { return File(it).takeIf(File::isDirectory) }
    System.getenv("ANDROID_NDK_HOME")?.let { return File(it).takeIf(File::isDirectory) }
    val sdk = local.getProperty("sdk.dir") ?: System.getenv("ANDROID_HOME") ?: return null
    return File(sdk, "ndk").listFiles()?.filter(File::isDirectory)?.maxByOrNull { it.name }
}

/** Gradle daemons started by Android Studio often lack the shell's PATH, so try the usual install locations. */
fun findGo(): String =
    (listOfNotNull(System.getenv("GOROOT")?.let { "$it/bin/go" }) + listOf("/opt/homebrew/bin/go", "/usr/local/go/bin/go", "/usr/local/bin/go"))
        .firstOrNull { File(it).canExecute() } ?: "go"

val goNdk = findNdk()
if (goNdk != null) {
    val goLocal = Properties().apply { rootProject.file("local.properties").takeIf { it.exists() }?.reader()?.use(::load) }
    val buildGoJni = tasks.register<GoJniTask>("buildGoJni") {
        goModule.set(rootProject.layout.projectDirectory.dir("go"))
        ndkDir.set(goNdk.absolutePath)
        apiLevel.set(24) // matches minSdk
        goExecutable.set(goLocal.getProperty("go.executable") ?: findGo())
        abis.set(listOf("arm64-v8a", "x86_64"))
        // OpenVPN is linked only when its native dependencies were built for every ABI.
        openvpn3.set(listOf("android_arm64", "android_amd64").all {
            rootProject.file("third_party/openssl/$it/lib/libcrypto.a").exists()
        } && rootProject.file("third_party/src/openvpn3").isDirectory)
        outputDir.set(layout.buildDirectory.dir("generated/goJniLibs"))
    }
    androidComponents {
        onVariants { variant -> variant.sources.jniLibs?.addGeneratedSourceDirectory(buildGoJni, GoJniTask::outputDir) }
    }
} else {
    logger.info("No Android NDK found; building without the Go engine library")
}
