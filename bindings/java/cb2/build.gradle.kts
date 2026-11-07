plugins {
    `java-library`
    `maven-publish`
}

description = "cb2 tokens for Java: cb2.local, cb2.public, kcb2.seal and holder proofs over the cb2 C ABI"

val hostOs: String = System.getProperty("os.name").lowercase().let {
    when {
        it.startsWith("mac") || it.startsWith("darwin") -> "macos"
        it.startsWith("windows") -> "windows"
        it.startsWith("linux") -> "linux"
        else -> it.replace(Regex("[^a-z0-9]"), "")
    }
}
val hostArch: String = System.getProperty("os.arch").lowercase().let {
    when (it) {
        "amd64", "x86_64", "x64" -> "x86_64"
        "aarch64", "arm64" -> "aarch64"
        else -> it.replace(Regex("[^a-z0-9_]"), "")
    }
}
val platform = "$hostOs-$hostArch"
val jniFileName = if (hostOs == "macos") "libcb2_jni.dylib" else "libcb2_jni.so"
val cAbiVersion: String = rootDir.resolve("../c/include/cb2_c.h").readLines()
    .firstNotNullOfOrNull { Regex("^#define CB2_C_ABI_VERSION ([0-9]+)$").find(it)?.groupValues?.get(1) }
    ?: error("CB2_C_ABI_VERSION not found in bindings/c/include/cb2_c.h")
val cFileName = if (hostOs == "macos") "libcb2_c.$cAbiVersion.dylib" else "libcb2_c.so.$cAbiVersion"

val cLibraryDir: Provider<String> = providers.gradleProperty("cb2.c.dir")
    .orElse(providers.environmentVariable("CB2_C_LIBRARY_DIR"))
    .orElse(rootDir.resolve("../../build/bindings/c").canonicalPath)
val cmakeDir = layout.buildDirectory.dir("cmake")
val nativeDir = layout.buildDirectory.dir("generated/native")
val nativePath = "com/cipherbird/cb2/native/$platform"

val configureJni = tasks.register<Exec>("configureJni") {
    description = "Configures the JNI glue with CMake against the built libcb2_c."
    inputs.file("CMakeLists.txt")
    inputs.property("cDir", cLibraryDir)
    outputs.dir(cmakeDir.map { it.dir("CMakeFiles") })
    environment("JAVA_HOME", providers.systemProperty("java.home").get())
    commandLine(
        "cmake", "-S", projectDir.path, "-B", cmakeDir.get().asFile.path,
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCB2_JNI_BUNDLED=ON",
        "-DCB2_C_LIBRARY_DIR=${cLibraryDir.get()}",
    )
}

val buildJni = tasks.register<Exec>("buildJni") {
    description = "Builds libcb2_jni from src/main/cpp."
    dependsOn(configureJni)
    inputs.dir("src/main/cpp")
    inputs.dir("../../c/include")
    inputs.file(cLibraryDir.map { "$it/$cFileName" })
    outputs.file(cmakeDir.map { it.file(jniFileName) })
    commandLine("cmake", "--build", cmakeDir.get().asFile.path, "--config", "Release")
}

val nativeIndex = tasks.register("nativeIndex") {
    description = "Writes the load order of the bundled native libraries."
    val index = layout.buildDirectory.file("generated/native-index/libraries")
    val names = listOf(cFileName, jniFileName)
    inputs.property("names", names)
    outputs.file(index)
    doLast { index.get().asFile.writeText(names.joinToString("\n", postfix = "\n")) }
}

val bundleNative = tasks.register<Sync>("bundleNative") {
    description = "Collects libcb2_jni, libcb2_c and their index as jar resources for $platform."
    into(nativeDir)
    into(nativePath) {
        from(buildJni)
        from(cLibraryDir.map { "$it/$cFileName" })
        from(nativeIndex)
    }
}

sourceSets.main {
    resources.srcDir(bundleNative)
}

java {
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 17
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.javadoc {
    (options as StandardJavadocDocletOptions).apply {
        addStringOption("Xdoclint:all", "-quiet")
        addBooleanOption("Xwerror", true)
    }
}

dependencies {
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    systemProperty("cb2.test.source", "bundled:$platform")
}

val testLibraryPath = tasks.register<Test>("testLibraryPath") {
    description = "Runs the tests with the glue found on java.library.path instead of in the jar."
    group = "verification"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    dependsOn(bundleNative)
    systemProperty("cb2.jni.bundled", "false")
    systemProperty("java.library.path", nativeDir.get().dir(nativePath).asFile.path)
    systemProperty("cb2.test.source", "library-path")
}

tasks.check {
    dependsOn(testLibraryPath)
}

publishing {
    publications {
        register<MavenPublication>("maven") {
            artifactId = "cb2"
            from(components["java"])
            pom {
                name = "cb2"
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
