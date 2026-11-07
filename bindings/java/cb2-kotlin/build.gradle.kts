import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    `maven-publish`
}

description = "Kotlin extensions for cb2: a rules DSL, a claims builder and extension functions on the keys"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
        allWarningsAsErrors = true
        freeCompilerArgs.add("-Xjdk-release=17")
    }
}

dependencies {
    api(project(":cb2"))
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
}

tasks.jar {
    manifest {
        attributes("Automatic-Module-Name" to "com.cipherbird.cb2.kotlin")
    }
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

publishing {
    publications {
        register<MavenPublication>("maven") {
            artifactId = "cb2-kotlin"
            from(components["java"])
            pom {
                name = "cb2-kotlin"
                description = project.description
                url = "https://github.com/Crdzbird/cb2"
                licenses {
                    license {
                        name = "MIT License"
                        url = "https://opensource.org/licenses/MIT"
                    }
                }
                scm {
                    url = "https://github.com/Crdzbird/cb2"
                }
            }
        }
    }
}
