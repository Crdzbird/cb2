package com.cipherbird.cb2;

import java.util.Arrays;
import java.util.List;

/**
 * A claim table for compact tokens (docs/PROTOCOL.md section 15.5): an
 * ordered list of 1 to 256 distinct, non-empty strings that an issuer and
 * its verifiers configure alike, typically the issuer's name and its
 * audiences. Under a table an iss or aud equal to an entry travels as its
 * index, so the token is shorter. The table's digest is bound into the
 * token and never sent: a token opens only under the same table, with the
 * same entries in the same order, and under another table or none the
 * verdict is {@link Code#INVALID}.
 *
 * <p>A table is immutable and may be shared between threads. Close it to
 * release the native table; a call after close throws
 * IllegalStateException. A table that is never closed is released once it
 * becomes unreachable.
 */
public final class ClaimTable implements AutoCloseable {
    /** The size in bytes of a table's digest. */
    public static final int DIGEST_BYTES = 32;

    final NativeHandle handle;
    private final List<String> entries;

    private ClaimTable(long handle, List<String> entries) {
        this.handle = NativeHandle.of(this, "ClaimTable", handle, Native::claimTableFree);
        this.entries = entries;
    }

    /**
     * A table of these entries, in this order.
     *
     * @param entries the entries
     * @return the table, which the caller closes
     * @throws Cb2Exception with {@link Code#ARGUMENT} for no entries, more
     *     than 256, a repeated or empty entry, or an entry with control
     *     characters
     */
    public static ClaimTable of(String... entries) {
        return of(Arrays.asList(Text.required(entries, "entries")));
    }

    /**
     * A table of these entries, in this order.
     *
     * @param entries the entries
     * @return the table, which the caller closes
     * @throws Cb2Exception with {@link Code#ARGUMENT} for no entries, more
     *     than 256, a repeated or empty entry, or an entry with control
     *     characters
     */
    public static ClaimTable of(List<String> entries) {
        StringBuilder json = new StringBuilder("[");
        for (String entry : Text.required(entries, "entries")) {
            if (json.length() > 1) {
                json.append(',');
            }
            Json.quoteTo(json, Text.required(entry, "an entry"));
        }
        List<String> copy = List.copyOf(entries);
        return new ClaimTable(Native.claimTableFromJson(Text.utf8(json.append(']').toString())), copy);
    }

    /**
     * The entries of this table, in order.
     *
     * @return an unmodifiable list of the entries
     */
    public List<String> entries() {
        return entries;
    }

    /**
     * The {@value #DIGEST_BYTES}-byte digest of this table, the value bound
     * into its tokens, so two parties can compare their tables.
     *
     * @return the digest
     */
    public byte[] digest() {
        return handle.use(Native::claimTableDigest);
    }

    /** Releases the native table; closing twice does nothing. */
    @Override
    public void close() {
        handle.close();
    }
}
