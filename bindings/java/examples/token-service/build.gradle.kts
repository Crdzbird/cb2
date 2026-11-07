plugins {
    application
}

description = "A small HTTP token service on cb2, driven by its own client"

dependencies {
    implementation(project(":cb2"))
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 17
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

application {
    mainModule = "com.cipherbird.cb2.example.service"
    mainClass = "com.cipherbird.cb2.example.service.TokenService"
    applicationDefaultJvmArgs = listOf("--enable-native-access=com.cipherbird.cb2")
}

tasks.register<JavaExec>("quickStart") {
    description = "Runs the quick start of the README."
    group = "application"
    classpath = sourceSets.main.get().runtimeClasspath
    mainModule = "com.cipherbird.cb2.example.service"
    mainClass = "com.cipherbird.cb2.example.service.QuickStart"
    jvmArgs("--enable-native-access=com.cipherbird.cb2")
}
