package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertTrue;

import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.sovworks.eds.crypto.kdf.HMAC;
import com.sovworks.eds.crypto.kdf.MacHMAC;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.MessageDigest;

/**
 * The PBKDF2 inner loop must not grow the native heap, measured rather than reasoned about.
 *
 * This exists because reasoning got it wrong once already. javax.crypto.Mac was put on the
 * PBKDF2 path as an optimisation and was in fact both slower and a native leak: Conscrypt
 * allocates an HMAC_CTX inside every doFinal() and the Java wrapper is too small to provoke
 * a GC, so an unhinted VeraCrypt open reached 1.5 GB RSS against a 108 MB Dalvik heap and
 * lmkd killed the app mid-unlock. Nothing on the Java side could see it: the leak is entirely
 * in [anon:scudo:primary], so a Runtime.totalMemory() check would have reported it absent.
 * RSS is therefore read from the process's own /proc/self/status.
 *
 * Both arms run in the same process in the same run: the generic HMAC that PBKDF2 actually
 * uses, and the Mac implementation as a positive control. The control is not decoration. A
 * bare "does not grow" assertion passes when the loop never ran, when /proc stops answering
 * and when the measurement is broken, and those look identical to success.
 */
@RunWith(AndroidJUnit4.class)
public class HmacNativeMemoryTest
{
    private static final int ITERATIONS = 200000;

    private static long rssKb() throws Exception
    {
        BufferedReader r = new BufferedReader(new FileReader("/proc/self/status"));
        try
        {
            String line;
            while ((line = r.readLine()) != null)
                if (line.startsWith("VmRSS:"))
                    return Long.parseLong(line.replaceAll("[^0-9]", ""));
        }
        finally
        {
            r.close();
        }
        throw new IllegalStateException("/proc/self/status has no VmRSS line");
    }

    /** {rss delta in kB, elapsed ms} */
    private static long[] runLoop(HMAC h, int digestLen) throws Exception
    {
        byte[] msg = new byte[digestLen];
        byte[] out = new byte[digestLen];
        long before = rssKb();
        long t0 = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++)
            h.calcHMAC(msg, 0, msg.length, out);
        long ms = (System.nanoTime() - t0) / 1000000L;
        long after = rssKb();
        h.close();
        return new long[]{after - before, ms};
    }

    /**
     * Three rounds, alternating, because one reading of either arm is not a measurement and
     * the first round pays for class loading and the provider lookup in whichever arm runs
     * first. The order is swapped on the middle round so that warm-up cannot be mistaken for
     * a property of the implementation.
     */
    @Test
    public void theProductionHmacDoesNotGrowTheNativeHeapAndTheMacControlDoes() throws Exception
    {
        long worstGeneric = 0, worstMac = 0;
        for (int round = 0; round < 3; round++)
        {
            long[] g, m;
            if (round == 1)
            {
                m = mac();
                g = generic();
            }
            else
            {
                g = generic();
                m = mac();
            }
            Log.i("fdstest", "hmac-rss round=" + round
                    + " generic delta=" + g[0] + " kB in " + g[1] + " ms"
                    + " | mac delta=" + m[0] + " kB in " + m[1] + " ms"
                    + " over " + ITERATIONS);
            worstGeneric = Math.max(worstGeneric, g[0]);
            worstMac = Math.max(worstMac, m[0]);
        }

        // The production gate. 32 MB over 200000 iterations is already an order of
        // magnitude more than a correct HMAC loop needs.
        assertTrue("the generic HMAC loop, which is the only one PBKDF2 uses, grew the "
                + "process by " + worstGeneric + " kB over " + ITERATIONS + " iterations",
                worstGeneric < 32 * 1024);

        // The positive control, and the reason the arm above is worth anything. A gate on
        // "does not grow" reads green when the measurement is broken, when the loop never
        // ran, and when /proc stops reporting. javax.crypto.Mac leaks a native HMAC_CTX per
        // doFinal, so it MUST show growth in the same process, in the same run, through the
        // same rssKb(). If this ever stops holding, the instrument has stopped working and
        // the arm above is no longer evidence of anything.
        assertTrue("the javax.crypto.Mac control grew the process by only " + worstMac
                + " kB, so this run cannot detect a native leak at all and the assertion "
                + "above is not evidence", worstMac > 32 * 1024);
    }

    private static long[] generic() throws Exception
    {
        return runLoop(new HMAC(new byte[32], MessageDigest.getInstance("SHA-256"), 64), 32);
    }

    private static long[] mac() throws Exception
    {
        return runLoop(new MacHMAC(new byte[32], MessageDigest.getInstance("SHA-256"),
                64, "HmacSHA256"), 32);
    }
}
