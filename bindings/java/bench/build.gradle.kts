plugins {
    application
}

description = "JMH benchmarks of cb2 against JJWT, Nimbus JOSE+JWT and paseto4j; never published"

dependencies {
    implementation(project(":cb2"))
    implementation(libs.jmh.core)
    annotationProcessor(libs.jmh.annprocess)
    implementation(libs.jjwt.api)
    runtimeOnly(libs.jjwt.impl)
    runtimeOnly(libs.jjwt.jackson)
    implementation(libs.nimbus.jose.jwt)
    runtimeOnly(libs.tink)
    implementation(libs.paseto4j.version4)
    implementation(libs.jackson.databind)
    implementation(libs.bcprov)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 17
}

application {
    mainClass = "org.openjdk.jmh.Main"
    applicationDefaultJvmArgs = listOf("--enable-native-access=ALL-UNNAMED")
}

tasks.register<JavaExec>("tokenSizes") {
    description = "Prints the size of each token the benchmarks make."
    group = "application"
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass = "com.cipherbird.cb2.bench.TokenSizes"
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
