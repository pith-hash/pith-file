package hash.pith;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/** Hex-exact conformance: the committed reference vectors through the
 * real JVM and the suite cdylib.
 *
 * <p>Every vector in the repository-root {@code reference.json} is
 * replayed through {@link PithFile#binarySignature(byte[])},
 * {@link PithFile#jaccard(byte[], byte[])} and {@link
 * PithFile#textContent(byte[], int)} and compared against every
 * recorded field: the 6 signature vectors compare the raw input
 * SHA-256, the chunk-digest count/first/folds; the 5 jaccard vectors
 * compare the exact IEEE-754 bit pattern; the text fixture compares
 * the extraction digests; the 2 error vectors come back as {@link
 * PithFfiException}, never a crash.
 */
class ReferenceVectorsTest {
    private static final Path REPO_ROOT = PithNative.repoRoot();
    private static final Map<String, JsonObject> VECTORS = vectors();

    // --- the input synthesis recipes of tools/gen-reference/main.rs ---

    /** The splitmix64 golden gamma increment. */
    private static final long GAMMA = 0x9E3779B97F4A7C15L;
    /** splitmix64 output-mixing multipliers. */
    private static final long M1 = 0xBF58476D1CE4E5B9L;
    /** splitmix64 output-mixing multipliers. */
    private static final long M2 = 0x94D049BB133111EBL;

    /** The Steele/Lea/Flood splitmix64 generator, one {@code next_u64}
     * per byte with the low byte kept — the byte recipe of the
     * generator in {@code pith-digest}. All arithmetic is unsigned
     * 64-bit integer math in java longs (no floats). */
    private static final class SplitMix64 {
        private long state;

        SplitMix64(long seed) {
            this.state = seed;
        }

        long nextU64() {
            state += GAMMA;
            long z = state;
            z = (z ^ (z >>> 30)) * M1;
            z = (z ^ (z >>> 27)) * M2;
            return z ^ (z >>> 31);
        }
    }

    /** The deterministic input bytes for a corpus kind: {@code
     * splitmix64} (one {@code next_u64} per byte, low byte kept),
     * {@code prefix-insert} (one {@code 0xAA} byte in front of the
     * seed stream) and {@code zeros}. */
    private static byte[] buildInput(String kind, long seed, int length) {
        if ("splitmix64".equals(kind)) {
            SplitMix64 rng = new SplitMix64(seed);
            byte[] out = new byte[length];
            for (int i = 0; i < length; i++) {
                out[i] = (byte) rng.nextU64();
            }
            return out;
        }
        if ("prefix-insert".equals(kind)) {
            SplitMix64 rng = new SplitMix64(seed);
            byte[] out = new byte[1 + length];
            out[0] = (byte) 0xAA;
            for (int i = 0; i < length; i++) {
                out[1 + i] = (byte) rng.nextU64();
            }
            return out;
        }
        if ("zeros".equals(kind)) {
            return new byte[length];
        }
        throw new IllegalArgumentException("unknown corpus kind " + kind);
    }

    /** The FNV-1a 64-bit hash: offset basis {@code 0xcbf29ce484222325},
     * prime {@code 0x100000001b3}. */
    private static long fnv1a64(byte[] data) {
        long hash = 0xCBF29CE484222325L;
        for (byte b : data) {
            hash = (hash ^ (b & 0xFF)) * 0x100000001B3L;
        }
        return hash;
    }

    private static Map<String, JsonObject> vectors() {
        try {
            JsonObject reference = JsonParser.parseString(
                    Files.readString(REPO_ROOT.resolve("reference.json")))
                    .getAsJsonObject();
            Map<String, JsonObject> out = new LinkedHashMap<>();
            for (JsonElement element : reference.getAsJsonArray("vectors")) {
                JsonObject vector = element.getAsJsonObject();
                out.put(vector.get("name").getAsString(), vector);
            }
            return out;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] fixture(String relative) {
        try {
            return Files.readAllBytes(REPO_ROOT.resolve(relative));
        } catch (Exception e) {
            throw new IllegalStateException(relative, e);
        }
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            return PithFile.hex(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The signature-vector inputs, synthesized once (the jaccard
     * vectors reference them by name). */
    private static Map<String, byte[]> inputs() {
        Map<String, byte[]> out = new LinkedHashMap<>();
        for (Map.Entry<String, JsonObject> entry : VECTORS.entrySet()) {
            JsonObject vector = entry.getValue();
            if (!vector.has("raw_sha256")) {
                continue;
            }
            JsonObject input = vector.getAsJsonObject("input");
            out.put(entry.getKey(), buildInput(
                    input.get("kind").getAsString(),
                    PithFile.parseHex64(input.get("seed_hex").getAsString()),
                    input.get("length").getAsInt()));
        }
        return out;
    }

    private static final Map<String, byte[]> INPUTS = inputs();

    @Test
    void cdylibIsDiscoverable() {
        assertTrue(Files.isRegularFile(Path.of(PithNative.findCdylib("pith_file"))));
    }

    @Test
    void signatureVectorsReproduceHexExact() {
        for (String name : new TreeSet<>(INPUTS.keySet())) {
            JsonObject vector = VECTORS.get(name);
            byte[] data = INPUTS.get(name);

            assertEquals(vector.get("raw_sha256").getAsString(), sha256Hex(data), name);

            byte[] raw = PithFile.binarySignature(data);
            PithFile.BinarySignature signature = PithFile.parseBinarySignature(raw);
            assertEquals(vector.get("chunk_digest_count").getAsInt(),
                    signature.chunkCount, name);
            if (signature.chunkCount > 0) {
                assertEquals(vector.get("chunk_digests_first").getAsString(),
                        signature.firstDigestHex(), name);
            } else {
                assertTrue(vector.get("chunk_digests_first").isJsonNull(), name);
                assertNull(signature.firstDigestHex(), name);
            }

            byte[] folded = signature.foldedDigests();
            assertEquals(vector.get("chunk_digests_fnv1a64").getAsString(),
                    PithFile.hex16(fnv1a64(folded)), name);
            assertEquals(vector.get("chunk_digests_sha256").getAsString(),
                    sha256Hex(folded), name);
        }
    }

    @Test
    void jaccardVectorsAreBitExact() {
        for (String name : new TreeSet<>(VECTORS.keySet())) {
            JsonObject vector = VECTORS.get(name);
            if (!vector.has("value_bits")) {
                continue;
            }
            byte[] a = INPUTS.get(vector.get("a").getAsString());
            byte[] b = INPUTS.get(vector.get("b").getAsString());
            double score = PithFile.jaccard(a, b);
            assertEquals(Long.parseUnsignedLong(vector.get("value_bits").getAsString(), 16),
                    Double.doubleToRawLongBits(score), name);
        }
    }

    @Test
    void textFixtureVectorIsReproducedHexExact() {
        JsonObject vector = VECTORS.get("text-fixture-text_page");
        byte[] pdf = fixture(vector.get("input_path").getAsString());
        assertEquals(vector.get("input_sha256").getAsString(), sha256Hex(pdf));

        byte[] extracted = PithFile.textContent(pdf, PithFile.PITH_FILE_FORMAT_PDF);
        assertEquals(vector.get("text_bytes").getAsInt(), extracted.length);
        assertEquals(vector.get("text_sha256").getAsString(), sha256Hex(extracted));
    }

    @Test
    void errorVectorsRefuseInsteadOfCrashing() {
        for (String name : new TreeSet<>(VECTORS.keySet())) {
            JsonObject vector = VECTORS.get(name);
            if (!vector.has("error_kind")) {
                continue;
            }
            byte[] data = PithFile.unhex(vector.get("input_hex").getAsString());
            PithFfiException thrown = assertThrows(PithFfiException.class,
                    () -> PithFile.textContent(data, PithFile.PITH_FILE_FORMAT_PDF), name);
            assertEquals(-2, thrown.getStatus(), name);
        }
    }

    @Test
    void emptyStreamMatchesTheRustPinnedLiterals() {
        // The 'empty' vector's chunk stream, pinned in the committed
        // reference.json and re-derived by the Rust unit tests: the
        // empty input signs to exactly the 8-byte zero count, the
        // empty digest fold hashes to the empty SHA-256 and the empty
        // FNV-1a input is the offset basis. This test fails loudly
        // even if reference.json were regenerated wrongly.
        byte[] raw = PithFile.binarySignature(new byte[0]);
        assertArrayEquals(new byte[8], raw);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                sha256Hex(java.util.Arrays.copyOfRange(raw, 0, 0)));
        assertEquals("cbf29ce484222325", PithFile.hex16(fnv1a64(new byte[0])));
    }

    @Test
    void unknownFormatCodeIsRefusedNotCrashing() {
        PithFfiException thrown = assertThrows(PithFfiException.class,
                () -> PithFile.textContent("%PDF-1.7\nbody".getBytes(), 99));
        assertEquals(-1, thrown.getStatus());
    }

    @Test
    void malformedPdfIsRefusedNotCrashing() {
        PithFfiException thrown = assertThrows(PithFfiException.class,
                () -> PithFile.textContent("%PDF-1.7\nbody".getBytes(),
                        PithFile.PITH_FILE_FORMAT_PDF));
        assertEquals(-2, thrown.getStatus());
    }
}
