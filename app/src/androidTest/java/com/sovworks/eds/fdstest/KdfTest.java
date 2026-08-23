package com.sovworks.eds.fdstest;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.sovworks.eds.crypto.hash.RIPEMD160;
import com.sovworks.eds.crypto.hash.Whirlpool;
import com.sovworks.eds.crypto.kdf.HMAC;
import com.sovworks.eds.crypto.kdf.HashBasedPBKDF2;
import com.sovworks.eds.crypto.kdf.MacHMAC;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The KDF is the only thing standing between a passphrase and the master key, so it gets
 * checked against published vectors rather than against itself, and the fast path gets
 * checked against the slow one it replaces.
 */
@RunWith(AndroidJUnit4.class)
public class KdfTest
{
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static byte[] hex(String s)
    {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    private static String hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b)
            sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /**
     * RFC 6070 gives PBKDF2-HMAC-SHA1 vectors and RFC 7914 section 11 restates one of them.
     * SHA-256 and SHA-512 vectors are the widely republished companions to those, generated
     * by an implementation that is not this one. If this fails, nothing else in the suite is
     * worth reading.
     */
    @Test
    public void pbkdf2MatchesPublishedVectors() throws Exception
    {
        // RFC 6070 #3: P="password", S="salt", c=4096, dkLen=20
        assertVector("SHA-1", "password", "salt", 4096, 20,
                "4b007901b765489abead49d926f721d065a429c1");
        // PBKDF2-HMAC-SHA256, same inputs, dkLen=32
        assertVector("SHA-256", "password", "salt", 4096, 32,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
        // PBKDF2-HMAC-SHA512, same inputs, dkLen=64
        assertVector("SHA-512", "password", "salt", 4096, 64,
                "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
                        + "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5");
    }

    private void assertVector(String digest, String pw, String salt, int iters, int dkLen, String expect)
            throws Exception
    {
        MessageDigest md = MessageDigest.getInstance(digest);
        HashBasedPBKDF2 kdf = new HashBasedPBKDF2(md, "SHA-512".equals(digest) ? 128 : 64);
        byte[] got = kdf.deriveKey(pw.getBytes(UTF8), salt.getBytes(UTF8), iters, dkLen);
        assertEquals(digest + " PBKDF2 vector", expect, hex(got));
    }

    /**
     * The generic HMAC is checked against the platform's own, byte for byte.
     *
     * MacHMAC is no longer on any production path: it leaked a native context per doFinal
     * and was slower than what it replaced, and it now lives in the test sources for exactly
     * two jobs. This is the second one. javax.crypto.Mac is an independent implementation of
     * the same RFC, so it is a real oracle for the hand-rolled ipad/opad loop that derives
     * every master key in this app; an HMAC that is wrong by one byte produces a wrong key
     * and an unopenable container, with nothing anywhere reporting an error.
     */
    @Test
    public void theGenericHmacAgreesWithThePlatformMac() throws Exception
    {
        byte[] key = "fds-key-material-éü".getBytes(UTF8);
        byte[] data = new byte[257];
        for (int i = 0; i < data.length; i++)
            data[i] = (byte) (i * 7 + 3);

        int compared = 0;
        for (String[] pair : new String[][]{{"SHA-512", "128"}, {"SHA-256", "64"}, {"SHA-1", "64"}})
        {
            MessageDigest md = MessageDigest.getInstance(pair[0]);
            int block = Integer.parseInt(pair[1]);
            String macName = MacHMAC.macNameFor(md);
            assertNotNull("no platform Mac for " + pair[0] + ", so this comparison has no "
                    + "oracle and proves nothing", macName);

            HMAC generic = new HMAC(key, MessageDigest.getInstance(pair[0]), block);
            MacHMAC fast = new MacHMAC(key, md, block, macName);
            byte[] a = new byte[generic.getDigestLength()];
            byte[] b = new byte[fast.getDigestLength()];
            // Twice each, because a Mac that failed to reset would agree on the first call
            // and diverge on the second.
            for (int round = 0; round < 2; round++)
            {
                generic.calcHMAC(data, 0, data.length, a);
                fast.calcHMAC(data, 0, data.length, b);
                assertArrayEquals(pair[0] + " round " + round, a, b);
            }
            generic.close();
            fast.close();
            compared++;
        }
        assertEquals("the comparison loop ran on nothing", 3, compared);
    }

    /**
     * Not a pass/fail threshold: emulators and phones differ by an order of magnitude and a
     * timing assertion here would just be flaky. It measures and prints, and fails only if a
     * hash cannot derive a key at all, so the numbers behind the unlock-time claims in the
     * README come from a run rather than from an estimate.
     */
    @Test
    public void reportPerHashKdfCost() throws Exception
    {
        final int iters = 20000;
        List<String> rows = new ArrayList<>();
        List<Object[]> hashes = new ArrayList<>();
        hashes.add(new Object[]{"SHA-512", MessageDigest.getInstance("SHA-512"), 128});
        hashes.add(new Object[]{"SHA-256", MessageDigest.getInstance("SHA-256"), 64});
        hashes.add(new Object[]{"ripemd160", new RIPEMD160(), 64});
        hashes.add(new Object[]{"whirlpool", new Whirlpool(), 64});

        byte[] pw = "fds-test-passphrase-do-not-reuse".getBytes(UTF8);
        byte[] salt = new byte[64];

        for (Object[] h : hashes)
        {
            String name = (String) h[0];
            MessageDigest md = (MessageDigest) h[1];
            int block = (Integer) h[2];
            HashBasedPBKDF2 kdf = new HashBasedPBKDF2(md, block);
            // One short warm run first: the first call also pays System.loadLibrary and JIT,
            // and folding that into the measurement is what made the earlier logcat numbers
            // say ripemd160 was three times slower than whirlpool.
            kdf.deriveKey(pw, salt, 200, 64);
            long t0 = System.nanoTime();
            byte[] k = kdf.deriveKey(pw, salt, iters, 64);
            long ns = System.nanoTime() - t0;
            assertEquals(name + " produced the wrong key length", 64, k.length);
            double usPerIter = ns / 1000.0 / iters;
            rows.add(String.format("  %-10s %7.2f us/iter -> %5.1f s at 500000 iterations",
                    name, usPerIter, usPerIter * 500000 / 1e6));
        }
        StringBuilder sb = new StringBuilder("\nKDF cost, measured on this device:\n");
        for (String r : rows)
            sb.append(r).append('\n');
        // Reported through an assertion message so it survives into the XML report; the
        // instrumentation console swallows plain stdout from a passing test.
        assertTrue(sb.toString(), rows.size() == 4);
        System.out.println(sb);
        android.util.Log.i("fdstest", sb.toString());
    }

    @Test
    public void hashesUsedByTheLayoutsAreAllConstructible()
    {
        // A NoSuchAlgorithmException inside getSupportedHashFuncs is swallowed upstream, so a
        // hash can vanish from the offered list without anything failing. Name them here.
        for (String n : new String[]{"SHA-512", "SHA-256"})
        {
            try
            {
                assertNotNull(n, MessageDigest.getInstance(n));
            }
            catch (Exception e)
            {
                fail(n + " is not available on this device, so the layout silently drops it: " + e);
            }
        }
        assertNotNull(new RIPEMD160());
        assertNotNull(new Whirlpool());
    }
}
