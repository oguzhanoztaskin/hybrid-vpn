import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Pure-JVM LAN discovery: mDNS, SSDP, subnet probing and evidence-based device identity.
// Android specifics (network binding, multicast lock, permissions) are injected by :app.
plugins {
    id("org.jetbrains.kotlin.jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_11) }
}

dependencies {
    implementation(project(":engine"))
    api(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
