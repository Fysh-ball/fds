package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.sovworks.eds.crypto.EncryptionEngine;
import com.sovworks.eds.crypto.FileEncryptionEngine;
import com.sovworks.eds.crypto.engines.AESXTS;
import com.sovworks.eds.crypto.engines.SerpentXTS;
import com.sovworks.eds.crypto.engines.TwofishXTS;
import com.sovworks.eds.crypto.hash.RIPEMD160;
import com.sovworks.eds.crypto.hash.Whirlpool;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Known-answer tests for the primitives, against reference values produced by OpenSSL and
 * never by this repository.
 *
 * The container fixtures already prove the whole stack end to end, but they prove it only
 * where a container exists: a failure there names a container, not a primitive. These tests
 * fail on one line of C.
 *
 * Coverage is deliberately uneven and the gap is stated rather than papered over. AES-XTS,
 * RIPEMD-160 and Whirlpool have an independent oracle on this host (python-cryptography and
 * OpenSSL's legacy provider). Serpent and Twofish have none: OpenSSL does not implement
 * either, so there is no second implementation here to disagree with ours. For those two the
 * oracle is the desktop VeraCrypt container in ContainerFixtureTest, and what is added below
 * is only what can be checked without an oracle: that decrypt inverts encrypt, and that the
 * three engines do not silently produce the SAME ciphertext, which is what a registry that
 * wired every cipher name to AES would look like.
 */
@RunWith(AndroidJUnit4.class)
public class CipherKatTest
{
    /**
     * Reference values from python-cryptography (OpenSSL), data unit 512 bytes, tweak = the
     * 64-bit sector number little-endian. That generator was itself checked against IEEE
     * 1619 XTS-AES vector 2 (key 1111.../2222..., sector 0x3333333333) before being used
     * here, so the oracle is not merely self-consistent.
     *
     * IEEE vector 1 is not usable as a check on this host: its two halves are identical and
     * OpenSSL refuses an XTS key whose halves match.
     */
    @Test
    public void aesXtsMatchesOpenssl() throws Exception
    {
        // AES-128 (32-byte XTS key), one partial data unit at sector 0.
        checkXts(new AESXTS(32), pattern(32, 11), 0, pattern(32, 3),
                "ce634c9d12258a2ee46c6520cd610254712581f4b0fcb4d3a30b51f728a596ae");

        // AES-128, two full data units at sector 5. The second unit's tweak is the first
        // unit's plus one, computed inside a single native call, so this is the arm that
        // fails if the sector number does not advance across a multi-sector buffer.
        checkXtsSha(new AESXTS(32), pattern(32, 11), 5, pattern(1024, 3),
                "acb20a7d0a06bf1a08cdd48fe7f193d17aa695a2ad911d1044752a81f88383f2");

        // AES-256 (64-byte XTS key), which is what every AES container in the fixture set uses.
        checkXts(new AESXTS(64), pattern(64, 11), 0, pattern(32, 3),
                "12e2a98f7bf5adae3809dc559bc79cd5f2392440a19014ad02d12e812bb0dc6b");
        checkXtsSha(new AESXTS(64), pattern(64, 11), 5, pattern(1024, 3),
                "c9acb7f306df9517202453f3a3bba6aaf03afce73dd05d7c280e314564946431");
    }

    /**
     * The two digests the KDF depends on, against OpenSSL. The empty input is included on
     * purpose: a digest that returns its initial state unchanged still produces a plausible
     * 20 or 64 bytes, and only a published empty-input value catches it.
     */
    @Test
    public void ripemd160MatchesOpenssl() throws Exception
    {
        checkDigest(new RIPEMD160(), new byte[0],
                "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        checkDigest(new RIPEMD160(), "abc".getBytes("UTF-8"),
                "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        // 1000 bytes spans several 64-byte blocks and ends mid-block, so the length encoding
        // and the final partial block are both exercised.
        checkDigest(new RIPEMD160(), pattern(1000, 3),
                "375738a38a6b00c02923e074582d9ef6bca8060b");
    }

    @Test
    public void whirlpoolMatchesOpenssl() throws Exception
    {
        checkDigest(new Whirlpool(), new byte[0],
                "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288feb"
                        + "cf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
        checkDigest(new Whirlpool(), "abc".getBytes("UTF-8"),
                "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e27"
                        + "7d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5");
        checkDigest(new Whirlpool(), pattern(1000, 3),
                "53f1c35ac61df022d140e71b352da8ad23a9f91ee07d6ae5976f8564eab65e6e3da6bec6ce0440e9"
                        + "b8e10ac355f70bf63350f17f71c43008411d5d0339cfc2ce");
    }

    /**
     * A digest must reset between uses. HashBasedPBKDF2 reuses one MessageDigest for every
     * one of 500000 iterations, so a reset that does not clear the native context would
     * produce a wrong key rather than an error, and every container would simply refuse to
     * open with no indication why.
     */
    @Test
    public void digestsResetBetweenUses() throws Exception
    {
        for (MessageDigest md : new MessageDigest[]{new RIPEMD160(), new Whirlpool()})
        {
            byte[] first = md.digest("abc".getBytes("UTF-8"));
            md.update("noise-that-must-not-carry-over".getBytes("UTF-8"));
            md.reset();
            byte[] afterReset = md.digest("abc".getBytes("UTF-8"));
            assertArrayEquals(md.getAlgorithm() + " did not reset", first, afterReset);
        }
    }

    /**
     * Serpent and Twofish have no second implementation on this host to check against, so
     * this asserts the two things that can be asserted without one.
     */
    @Test
    public void serpentAndTwofishRoundTripAndAreDistinct() throws Exception
    {
        byte[] plain = pattern(1024, 3);
        byte[] aes = encrypted(new AESXTS(64), pattern(64, 11), 5, plain);
        byte[] serpent = encrypted(new SerpentXTS(), pattern(64, 11), 5, plain);
        byte[] twofish = encrypted(new TwofishXTS(), pattern(64, 11), 5, plain);

        // Round trip. Done through a SECOND engine instance rather than by reusing the one
        // that encrypted, so a decrypt path that merely replays cached state cannot pass.
        assertArrayEquals("SerpentXTS decrypt did not invert encrypt",
                plain, decrypted(new SerpentXTS(), pattern(64, 11), 5, serpent));
        assertArrayEquals("TwofishXTS decrypt did not invert encrypt",
                plain, decrypted(new TwofishXTS(), pattern(64, 11), 5, twofish));

        // Distinctness. Same key, same sector, same plaintext: three different ciphers must
        // not agree. If any pair matches, the registry is handing out the wrong engine and
        // every "Serpent container opened" result in the suite is really an AES result.
        assertNotEquals("SerpentXTS produced AES ciphertext", hex(aes), hex(serpent));
        assertNotEquals("TwofishXTS produced AES ciphertext", hex(aes), hex(twofish));
        assertNotEquals("TwofishXTS produced Serpent ciphertext", hex(serpent), hex(twofish));
    }

    /**
     * The key sizes the layouts hand these engines. VeraCrypt keeps a 256-byte key area and
     * slices it; an engine that reported the wrong size would read the slice at the wrong
     * offset and fail to open with no error that names the cause.
     */
    @Test
    public void engineKeySizesAreWhatTheLayoutsAssume()
    {
        assertEquals("AESXTS(64)", 64, new AESXTS(64).getKeySize());
        assertEquals("AESXTS(32)", 32, new AESXTS(32).getKeySize());
        assertEquals("SerpentXTS", 64, new SerpentXTS().getKeySize());
        assertEquals("TwofishXTS", 64, new TwofishXTS().getKeySize());
        assertEquals("XTS data unit", 512, new AESXTS(64).getFileBlockSize());
        assertEquals("XTS block", 16, new AESXTS(64).getEncryptionBlockSize());
    }

    // ---- helpers -------------------------------------------------------------------

    /** byte i = (i*seed + 7) mod 256: the same generator the reference script used. */
    private static byte[] pattern(int n, int seed)
    {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++)
            b[i] = (byte) ((i * seed + 7) & 0xff);
        return b;
    }

    private static void checkDigest(MessageDigest md, byte[] data, String expectHex)
    {
        byte[] got = md.digest(data);
        assertEquals(md.getAlgorithm() + " output length", expectHex.length() / 2, got.length);
        assertEquals(md.getAlgorithm() + " of " + data.length + " bytes", expectHex, hex(got));
    }

    private static void checkXts(FileEncryptionEngine e, byte[] key, long sector,
                                 byte[] plain, String expectHex) throws Exception
    {
        byte[] ct = encrypted(e, key, sector, plain);
        assertEquals(e.getCipherName() + " keySize=" + key.length + " sector=" + sector,
                expectHex, hex(ct));
        assertArrayEquals("decrypt did not invert encrypt",
                plain, decrypted(newLike(e, key.length), key, sector, ct));
    }

    private static void checkXtsSha(FileEncryptionEngine e, byte[] key, long sector,
                                    byte[] plain, String expectSha) throws Exception
    {
        byte[] ct = encrypted(e, key, sector, plain);
        assertEquals(e.getCipherName() + " len=" + plain.length + " sector=" + sector,
                expectSha, hex(MessageDigest.getInstance("SHA-256").digest(ct)));
        assertArrayEquals("decrypt did not invert encrypt",
                plain, decrypted(newLike(e, key.length), key, sector, ct));
    }

    private static FileEncryptionEngine newLike(FileEncryptionEngine e, int keyLen)
    {
        if (e instanceof AESXTS) return new AESXTS(keyLen);
        if (e instanceof SerpentXTS) return new SerpentXTS();
        return new TwofishXTS();
    }

    private static byte[] encrypted(FileEncryptionEngine e, byte[] key, long sector, byte[] in)
            throws Exception
    {
        byte[] buf = Arrays.copyOf(in, in.length);
        run(e, key, sector, buf, true);
        assertTrue("ciphertext equals plaintext", !Arrays.equals(in, buf));
        return buf;
    }

    private static byte[] decrypted(FileEncryptionEngine e, byte[] key, long sector, byte[] in)
            throws Exception
    {
        byte[] buf = Arrays.copyOf(in, in.length);
        run(e, key, sector, buf, false);
        return buf;
    }

    private static void run(EncryptionEngine e, byte[] key, long sector, byte[] buf, boolean enc)
            throws Exception
    {
        try
        {
            // setKey copies and zeroes its own copy on close, and XTS.setIV reads the first
            // eight bytes big-endian into a long, so the sector number goes in there and the
            // remaining eight bytes of the 16-byte IV are unused by this engine.
            e.setKey(Arrays.copyOf(key, key.length));
            e.setIV(ByteBuffer.allocate(e.getIVSize()).putLong(sector).array());
            e.init();
            if (enc) e.encrypt(buf, 0, buf.length);
            else e.decrypt(buf, 0, buf.length);
        }
        finally
        {
            e.close();
        }
    }

    private static String hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
