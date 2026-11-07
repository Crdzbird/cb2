import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

description = "A command line tour of cb2 from Kotlin"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
        allWarningsAsErrors = true
    }
}

dependencies {
    implementation(project(":cb2-kotlin"))
}

application {
    mainClass = "com.cipherbird.cb2.example.tour.TourKt"
    applicationDefaultJvmArgs = listOf("--enable-native-access=ALL-UNNAMED")
}

tasks.register<JavaExec>("quickStart") {
    description = "Runs the quick start of the README."
    group = "application"
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass = "com.cipherbird.cb2.example.tour.QuickStartKt"
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
