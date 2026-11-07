package com.cipherbird.cb2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Finds and loads the JNI glue, first match wins:
 * <ol>
 * <li>the file named by the system property {@value #LIBRARY_PROPERTY};</li>
 * <li>the libraries bundled in this jar under
 * {@code com/cipherbird/cb2/native/<os>-<arch>/}, listed in load order in
 * the file {@code libraries} there, extracted into a fresh directory only
 * the current user can read (under {@value #TMPDIR_PROPERTY}, or
 * java.io.tmpdir), loaded, then deleted; skipped when
 * {@value #BUNDLED_PROPERTY} is false;</li>
 * <li>{@code System.loadLibrary("cb2_jni")} from java.library.path.</li>
 * </ol>
 */
final class NativeLoader {
    static final String LIBRARY_PROPERTY = "cb2.jni.library";
    static final String BUNDLED_PROPERTY = "cb2.jni.bundled";
    static final String TMPDIR_PROPERTY = "cb2.jni.tmpdir";

    private static final String RESOURCE_ROOT = "/com/cipherbird/cb2/native/";
    private static final Pattern FILE_NAME = Pattern.compile("[A-Za-z0-9_][A-Za-z0-9._-]*");

    private static String source = "none";

    private NativeLoader() {
    }

    static String source() {
        return source;
    }

    @SuppressWarnings("restricted")
    static void load() {
        String path = System.getProperty(LIBRARY_PROPERTY);
        if (path != null && !path.isEmpty()) {
            System.load(path);
            source = "property";
            return;
        }
        UnsatisfiedLinkError bundledError = null;
        if (!"false".equalsIgnoreCase(System.getProperty(BUNDLED_PROPERTY))) {
            String platform = platform(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
            try {
                if (loadBundled(platform)) {
                    source = "bundled:" + platform;
                    return;
                }
            } catch (UnsatisfiedLinkError e) {
                bundledError = e;
            }
        }
        try {
            System.loadLibrary("cb2_jni");
            source = "library-path";
        } catch (UnsatisfiedLinkError e) {
            if (bundledError != null) {
                e.addSuppressed(bundledError);
            }
            throw e;
        }
    }

    static String platform(String osName, String osArch) {
        String os = osName.toLowerCase(Locale.ROOT);
        String arch = osArch.toLowerCase(Locale.ROOT);
        String osPart;
        if (os.startsWith("mac") || os.startsWith("darwin")) {
            osPart = "macos";
        } else if (os.startsWith("windows")) {
            osPart = "windows";
        } else if (os.startsWith("linux")) {
            osPart = "linux";
        } else {
            osPart = os.replaceAll("[^a-z0-9]", "");
        }
        String archPart = switch (arch) {
            case "amd64", "x86_64", "x64" -> "x86_64";
            case "aarch64", "arm64" -> "aarch64";
            default -> arch.replaceAll("[^a-z0-9_]", "");
        };
        return osPart + "-" + archPart;
    }

    @SuppressWarnings("restricted")
    private static boolean loadBundled(String platform) {
        String dir = RESOURCE_ROOT + platform + "/";
        List<String> names = index(dir + "libraries");
        if (names.isEmpty()) {
            return false;
        }
        Path tmp = null;
        List<Path> files = new ArrayList<>();
        try {
            tmp = Files.createTempDirectory(tempRoot(), "cb2-jni-");
            for (String name : names) {
                Path file = tmp.resolve(name);
                try (InputStream in = NativeLoader.class.getResourceAsStream(dir + name)) {
                    if (in == null) {
                        throw new UnsatisfiedLinkError("cb2: " + dir + name + " is listed but missing from the jar");
                    }
                    Files.copy(in, file, StandardCopyOption.REPLACE_EXISTING);
                }
                files.add(file);
            }
            for (Path file : files) {
                System.load(file.toAbsolutePath().toString());
            }
            return true;
        } catch (IOException e) {
            throw linkError("cb2: cannot extract the bundled native libraries", e);
        } finally {
            delete(files, tmp);
        }
    }

    private static List<String> index(String resource) {
        List<String> names = new ArrayList<>();
        try (InputStream in = NativeLoader.class.getResourceAsStream(resource)) {
            if (in == null) {
                return names;
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                String name = line.trim();
                if (name.isEmpty()) {
                    continue;
                }
                if (!FILE_NAME.matcher(name).matches()) {
                    throw new UnsatisfiedLinkError("cb2: bad library name in " + resource + ": " + name);
                }
                names.add(name);
            }
        } catch (IOException e) {
            throw linkError("cb2: cannot read " + resource, e);
        }
        return names;
    }

    private static UnsatisfiedLinkError linkError(String message, IOException cause) {
        UnsatisfiedLinkError error = new UnsatisfiedLinkError(message + ": " + cause.getMessage());
        error.initCause(cause);
        return error;
    }

    private static Path tempRoot() {
        String dir = System.getProperty(TMPDIR_PROPERTY);
        if (dir == null || dir.isEmpty()) {
            dir = System.getProperty("java.io.tmpdir");
        }
        return Paths.get(dir);
    }

    private static void delete(List<Path> files, Path dir) {
        for (Path file : files) {
            deleteOrDefer(file);
        }
        if (dir != null) {
            deleteOrDefer(dir);
        }
    }

    private static void deleteOrDefer(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            path.toFile().deleteOnExit();
        }
    }
}
