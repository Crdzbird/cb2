package com.cipherbird.cb2;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class NativeLoaderTest {
    @Test
    void platformNames() {
        assertEquals("macos-aarch64", NativeLoader.platform("Mac OS X", "aarch64"));
        assertEquals("macos-x86_64", NativeLoader.platform("Mac OS X", "x86_64"));
        assertEquals("linux-x86_64", NativeLoader.platform("Linux", "amd64"));
        assertEquals("linux-aarch64", NativeLoader.platform("Linux", "arm64"));
        assertEquals("windows-x86_64", NativeLoader.platform("Windows 11", "amd64"));
        assertEquals("freebsd-riscv64", NativeLoader.platform("FreeBSD", "riscv64"));
    }

    @Test
    void theGlueCameFromTheExpectedSource() {
        Cb2.load();
        String expected = System.getProperty("cb2.test.source");
        if (expected != null) {
            assertEquals(expected, NativeLoader.source(), "where the glue was loaded from");
        }
    }
}
