package hash.pith;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Java bindings for {@code pith-file}: FastCDC chunk signatures,
 * exact chunk-set Jaccard and PDF text extraction over the suite
 * cdylib.
 *
 * <p>{@link #binarySignature(byte[])} returns the <dfn>canonical
 * stream</dfn> every {@code reference.json} signature vector is
 * defined over: the {@code chunk_count} big-endian {@code u64}, then
 * the sorted unique 32-byte SHA-256 chunk digests ({@link
 * BinarySignature#parse} unpacks it). Refusals throw
 * {@link PithFfiException}, never crash the JVM.
 *
 * <p>The cdylib is resolved once per process — {@code PITH_CDYLIB}
 * (explicit file), {@code PITH_CDYLIB_DIR} (directory, relative
 * resolves against the working directory and its ancestors), then the
 * {@code target/release} of a repository checkout — and loaded with
 * {@link System#load}.
 */
public final class PithFile {
    /** Status: success. */
    public static final int PITH_OK = 0;
    /** Status: a caller argument is invalid (null array, unknown format). */
    public static final int PITH_E_INVALID = -1;
    /** Status: the core pipeline refused the input. */
    public static final int PITH_E_REJECTED = -2;

    /** Format wire code: a PDF container — the single extraction lane
     * {@link #textContent(byte[], int)} exposes. */
    public static final int PITH_FILE_FORMAT_PDF = 0;

    private static final String CDYLIB = PithNative.findCdylib("pith_file");

    static {
        System.load(CDYLIB);
    }

    private PithFile() {
    }

    /** Signs a byte string into the canonical chunk-set stream.
     *
     * @param input the complete file bytes
     * @return the canonical stream: {@code chunk_count} as one
     *         big-endian u64, then {@code chunk_count} 32-byte SHA-256
     *         digests in sorted order (the empty input yields exactly
     *         the 8 zero bytes of a zero count)
     * @throws PithFfiException {@code -1} on a null input array,
     *         {@code -2} when the core refuses (unreachable with the
     *         spec-pinned chunking parameters) */
    public static native byte[] binarySignature(byte[] input);

    /** The exact Jaccard similarity of the binary signatures of two
     * byte strings (both signatures computed inside the cdylib).
     *
     * @param a the first input's complete bytes
     * @param b the second input's complete bytes
     * @return the similarity in {@code [0, 1]} — two empty inputs
     *         score {@code 1.0} (two empty files are identical)
     * @throws PithFfiException {@code -1} on a null array argument,
     *         {@code -2} when the core refuses */
    public static native double jaccard(byte[] a, byte[] b);

    /** Extracts the container text of a byte string.
     *
     * @param input the complete container bytes
     * @param format the wire format code ({@link #PITH_FILE_FORMAT_PDF})
     * @return the extracted text bytes ({@code pith_pdf} output)
     * @throws PithFfiException {@code -1} on a null input array or an
     *         unknown format code, {@code -2} when the text layer
     *         refuses the container (malformed PDF) */
    public static native byte[] textContent(byte[] input, int format);

    /** The canonical chunk-set stream, unpacked into the fields the
     * {@code reference.json} vectors pin. */
    public static final class BinarySignature {
        /** The number of unique chunk digests. */
        public final long chunkCount;
        /** The unique 32-byte SHA-256 digests, in sorted order. */
        public final List<byte[]> digests;

        private BinarySignature(long chunkCount, List<byte[]> digests) {
            this.chunkCount = chunkCount;
            this.digests = digests;
        }

        /** Unpacks the canonical stream; throws {@link IllegalArgumentException}
         * when the length does not match the header. */
        public static BinarySignature parse(byte[] wire) {
            if (wire.length < 8) {
                throw new IllegalArgumentException("truncated chunk-set header");
            }
            long count = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN).getLong(0);
            if (wire.length != 8 + Math.toIntExact(count) * 32) {
                throw new IllegalArgumentException("chunk-set length " + wire.length
                        + " does not match " + count + " chunk digests");
            }
            List<byte[]> digests = new ArrayList<>(Math.toIntExact(count));
            for (int i = 0; i < count; i++) {
                digests.add(Arrays.copyOfRange(wire, 8 + i * 32, 8 + (i + 1) * 32));
            }
            return new BinarySignature(count, digests);
        }

        /** The concatenation of the digests — the bytes the recorded
         * {@code chunk_digests_fnv1a64}/{@code chunk_digests_sha256}
         * fold over. */
        public byte[] foldedDigests() {
            byte[] folded = new byte[digests.size() * 32];
            for (int i = 0; i < digests.size(); i++) {
                System.arraycopy(digests.get(i), 0, folded, i * 32, 32);
            }
            return folded;
        }

        /** The first digest as lowercase hex ({@code chunk_digests_first});
         * {@code null} when the count is zero. */
        public String firstDigestHex() {
            return digests.isEmpty() ? null : hex(digests.get(0));
        }
    }

    /** Convenience wrapper over {@link BinarySignature#parse(byte[])}. */
    public static BinarySignature parseBinarySignature(byte[] wire) {
        return BinarySignature.parse(wire);
    }

    /** The standard FNV-1a 64-bit hash: offset basis
     * {@code 0xcbf29ce484222325}, prime {@code 0x100000001b3} — the
     * algorithm the recorded {@code chunk_digests_fnv1a64} uses over
     * the concatenated chunk digests. */
    public static long fnv1a64(byte[] data) {
        long hash = 0xCBF29CE484222325L;
        for (byte b : data) {
            hash = (hash ^ (b & 0xFF)) * 0x100000001B3L;
        }
        return hash;
    }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16));
            out.append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }

    static String hex16(long value) {
        return String.format("%016x", value);
    }

    static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static long parseHex64(String hex) {
        return Long.parseUnsignedLong(hex, 16);
    }
}
