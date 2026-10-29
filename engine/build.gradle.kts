import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Pure-JVM networking core: packet codecs, DNS filtering/proxying and the policy engine.
// Kept free of Android APIs so it can be unit-tested on the host and reused by any data plane.
plugins {
    id("org.jetbrains.kotlin.jvm")
    alias(libs.plugins.kotlin.serialization)
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_11) }
}

dependencies {
    api(libs.kotlinx.serialization.json)
    testImplementation(libs.junit)
}
