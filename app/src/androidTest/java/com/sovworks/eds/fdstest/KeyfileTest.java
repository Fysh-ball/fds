package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.LargeTest;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.fs.std.StdFs;
import com.sovworks.eds.truecrypt.Keyfiles;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Keyfiles, against a desktop VeraCrypt.
 *
 * The keyfile algorithm is fixed by the on-disk format, and getting it wrong has a
 * particularly nasty symptom: the container simply refuses the credential, exactly as it
 * would for a mistyped passphrase. There is no error that says "your keyfile handling is
 * wrong". So this class does not check the algorithm against a description of itself. It
 * opens containers that /usr/bin/veracrypt created with keyfiles, and requires the same
 * containers to stay shut without them.
 *
 * There is also a golden pool vector, and it is honestly a weaker oracle: it came from an
 * independent Python implementation, but one written by the same author from the same
 * source, so it catches Java-idiom mistakes (signed bytes, >> where >>> is meant, a
 * finalised CRC) and would not catch a shared misreading of the format. It earns its place
 * by localising a failure. When the container arm goes red the vector says whether the pool
 * or the wiring is at fault.
 */
@RunWith(AndroidJUnit4.class)
public class KeyfileTest
{
    private static final Charset UTF8 = Charset.forName("UTF-8");

    /** From tools/mkkeyfilefixture.sh, computed independently in Python. kf1.bin alone. */
    private static final byte[] POOL_KF1 = {
        (byte)0x59,(byte)0xfb,(byte)0x4b,(byte)0xa8,(byte)0x2d,(byte)0x04,(byte)0xe1,(byte)0x05,
        (byte)0x4e,(byte)0x31,(byte)0x16,(byte)0x98,(byte)0xd1,(byte)0xf2,(byte)0x59,(byte)0x0d,
        (byte)0x4a,(byte)0x1c,(byte)0x42,(byte)0x3b,(byte)0xa5,(byte)0xda,(byte)0xd4,(byte)0x0d,
        (byte)0xec,(byte)0x0c,(byte)0x9e,(byte)0xd1,(byte)0x62,(byte)0x26,(byte)0xea,(byte)0xed,
        (byte)0x4c,(byte)0xd4,(byte)0xe5,(byte)0xe2,(byte)0x37,(byte)0xb6,(byte)0x83,(byte)0x1a,
        (byte)0xcd,(byte)0x0b,(byte)0x69,(byte)0x1f,(byte)0x32,(byte)0x40,(byte)0xee,(byte)0xe4,
        (byte)0x04,(byte)0x45,(byte)0x92,(byte)0xef,(byte)0x07,(byte)0x4d,(byte)0xb7,(byte)0x53,
        (byte)0x44,(byte)0x25,(byte)0xc7,(byte)0x5e,(byte)0xf8,(byte)0x32,(byte)0xb2,(byte)0x30 };

    /** kf1.bin then kf2.bin, folded into one pool. */
    private static final byte[] POOL_KF12 = {
        (byte)0x59,(byte)0xb1,(byte)0x44,(byte)0x92,(byte)0x3b,(byte)0xc4,(byte)0x5a,(byte)0x92,
        (byte)0xa2,(byte)0x0a,(byte)0x5e,(byte)0x98,(byte)0xd2,(byte)0xb3,(byte)0x0e,(byte)0x03,
        (byte)0x10,(byte)0x8b,(byte)0xbe,(byte)0xa8,(byte)0xb4,(byte)0x61,(byte)0x37,(byte)0xc3,
        (byte)0x6f,(byte)0x9f,(byte)0x8f,(byte)0x5a,(byte)0x71,(byte)0x5d,(byte)0x13,(byte)0x7d,
        (byte)0xb4,(byte)0x30,(byte)0x50,(byte)0x89,(byte)0x07,(byte)0xcd,(byte)0x42,(byte)0x50,
        (byte)0x1d,(byte)0x25,(byte)0x4c,(byte)0x6d,(byte)0xcc,(byte)0xea,(byte)0xaf,(byte)0x8a,
        (byte)0x6d,(byte)0x32,(byte)0x51,(byte)0xd3,(byte)0x88,(byte)0x9e,(byte)0xa3,(byte)0x40,
        (byte)0xff,(byte)0xfb,(byte)0x69,(byte)0x37,(byte)0x1c,(byte)0x42,(byte)0xfe,(byte)0xa7 };

    private static File sDir;
    /** name -> {password, comma separated keyfile basenames} */
    private static final Map<String, String[]> sRows = new LinkedHashMap<>();

    @BeforeClass
    public static void loadManifest() throws Exception
    {
        Context ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        sDir = FixtureSet.locate(ctx);
        assertNotNull("no external files dir on this device", sDir);
        File m = new File(sDir, "keyfile-manifest.tsv");
        if(!m.isFile())
            throw new IOException("keyfile manifest missing: " + m.getAbsolutePath()
                    + " (run tools/mkkeyfilefixture.sh then tools/run-fixture-tests.sh)");
        for(String line: readLines(m))
        {
            String[] p = line.split("\t", -1);
            if(p.length < 3 || "name".equals(p[0]))
                continue;
            sRows.put(p[0], new String[]{ p[1], p[2] });
        }
        // A manifest that parsed to nothing must fail here, not leave every test below with
        // an empty work list and a green result.
        if(sRows.isEmpty())
            throw new IOException("keyfile-manifest.tsv has no data rows");
    }

    /**
     * The fixtures and their keyfiles must be on the device. Without this the container arms
     * would have nothing to open and would say so as a confusing NPE somewhere else.
     */
    @Test
    public void theFixturesAndTheirKeyfilesArePresent()
    {
        List<String> missing = new ArrayList<>();
        for(Map.Entry<String, String[]> e: sRows.entrySet())
        {
            File c = new File(sDir, e.getKey() + ".hc");
            if(!c.isFile() || c.length() == 0)
                missing.add(c.getName());
            for(String kf: e.getValue()[1].split(","))
                if(!kf.isEmpty() && !new File(sDir, kf).isFile())
                    missing.add(kf);
        }
        assertEquals("keyfile fixtures missing from " + sDir + ": " + missing,
                0, missing.size());
    }

    @Test
    public void thePoolForOneKeyfileMatchesTheGoldenVector() throws Exception
    {
        byte[] pool = new byte[Keyfiles.POOL_SIZE];
        try (InputStream is = new FileInputStream(new File(sDir, "kf1.bin")))
        {
            Keyfiles.mixInto(pool, is);
        }
        assertArrayEquals("the one keyfile pool does not match the independent implementation",
                POOL_KF1, pool);
    }

    @Test
    public void thePoolForTwoKeyfilesMatchesTheGoldenVector() throws Exception
    {
        byte[] pool = new byte[Keyfiles.POOL_SIZE];
        for(String n: new String[]{ "kf1.bin", "kf2.bin" })
            try (InputStream is = new FileInputStream(new File(sDir, n)))
            {
                Keyfiles.mixInto(pool, is);
            }
        assertArrayEquals("the two keyfile pool does not match the independent implementation",
                POOL_KF12, pool);
    }

    /**
     * The pool is a sum, so the order of the keyfiles cannot matter. Worth pinning because
     * the natural way to break it is to carry the CRC across files instead of restarting it,
     * which makes the result order dependent and still looks like a pool.
     */
    @Test
    public void theOrderOfTheKeyfilesDoesNotMatter() throws Exception
    {
        byte[] a = new byte[Keyfiles.POOL_SIZE];
        byte[] b = new byte[Keyfiles.POOL_SIZE];
        mixFiles(a, "kf1.bin", "kf2.bin");
        mixFiles(b, "kf2.bin", "kf1.bin");
        assertArrayEquals("swapping the keyfiles changed the pool, so the CRC is carrying "
                + "across files instead of restarting", a, b);
    }

    /**
     * Only the first mebibyte counts. Checked with a synthetic stream rather than a 1 MiB
     * fixture, because the property is about the reader and not about any particular file.
     */
    @Test
    public void bytesPastOneMebibyteAreIgnored() throws Exception
    {
        byte[] capped = new byte[Keyfiles.MAX_READ];
        for(int i = 0; i < capped.length; i++)
            capped[i] = (byte) (i * 31 + 7);
        byte[] longer = Arrays.copyOf(capped, Keyfiles.MAX_READ + 4096);
        for(int i = Keyfiles.MAX_READ; i < longer.length; i++)
            longer[i] = (byte) 0xa5;

        byte[] p1 = new byte[Keyfiles.POOL_SIZE];
        byte[] p2 = new byte[Keyfiles.POOL_SIZE];
        Keyfiles.mixInto(p1, new ByteArrayInputStream(capped));
        Keyfiles.mixInto(p2, new ByteArrayInputStream(longer));
        assertArrayEquals("bytes past 1 MiB changed the pool", p1, p2);

        // And the cap must not be doing nothing: a byte INSIDE the window has to matter, or
        // the test above would pass against a reader that ignored the file entirely.
        byte[] tweaked = capped.clone();
        tweaked[Keyfiles.MAX_READ - 1] ^= 0xff;
        byte[] p3 = new byte[Keyfiles.POOL_SIZE];
        Keyfiles.mixInto(p3, new ByteArrayInputStream(tweaked));
        assertFalse("changing the last byte inside the window changed nothing, so the reader "
                + "is not reading", Arrays.equals(p1, p3));
    }

    /**
     * A keyfile with no passphrase is legal and is how a keyfile-only credential works: the
     * derived password is exactly the 64 byte pool.
     */
    @Test
    public void anEmptyPassphraseBecomesThePoolItself()
    {
        byte[] mixed = Keyfiles.mixIntoPassword(new byte[0], POOL_KF1);
        assertArrayEquals("an empty passphrase did not become the pool", POOL_KF1, mixed);
        assertEquals(Keyfiles.POOL_SIZE, mixed.length);
    }

    /** A passphrase shorter than the pool is padded to 64 bytes, not left short. */
    @Test
    public void aShortPassphraseGrowsToThePoolSize()
    {
        byte[] mixed = Keyfiles.mixIntoPassword("abc".getBytes(UTF8), POOL_KF1);
        assertEquals(Keyfiles.POOL_SIZE, mixed.length);
        assertEquals((byte) ('a' + POOL_KF1[0]), mixed[0]);
        assertEquals(POOL_KF1[3], mixed[3]);
    }

    /** A passphrase longer than the pool keeps its tail untouched. */
    @Test
    public void alongPassphraseKeepsItsTail()
    {
        byte[] pw = new byte[100];
        Arrays.fill(pw, (byte) 'z');
        byte[] mixed = Keyfiles.mixIntoPassword(pw, POOL_KF1);
        assertEquals(100, mixed.length);
        assertEquals((byte) ('z' + POOL_KF1[63]), mixed[63]);
        assertEquals((byte) 'z', mixed[64]);
        assertEquals((byte) 'z', mixed[99]);
    }

    /** No keyfiles at all must be a no-op, so an ordinary unlock is not silently altered. */
    @Test
    public void noKeyfilesLeavesThePassphraseAlone() throws Exception
    {
        byte[] pw = "plain".getBytes(UTF8);
        assertArrayEquals(pw, Keyfiles.apply(pw, null));
        assertArrayEquals(pw, Keyfiles.apply(pw, new ArrayList<InputStream>()));
    }

    // ---- the real oracle: containers a desktop VeraCrypt made -------------------------

    @Test
    public void everyKeyfileContainerOpensWithItsKeyfiles() throws Exception
    {
        int checked = 0;
        for(Map.Entry<String, String[]> e: sRows.entrySet())
        {
            String name = e.getKey();
            byte[] pw = mixedFor(e.getValue()[0], e.getValue()[1]);
            EdsContainer c = new EdsContainer(
                    StdFs.makePath(new File(sDir, name + ".hc").getAbsolutePath()));
            try
            {
                c.open(pw);
                checked++;
            }
            catch (Throwable t)
            {
                fail(name + " did not open with its own keyfiles (" + e.getValue()[1]
                        + "): " + t);
            }
            finally
            {
                ContainerPayload.closeQuietly(c);
            }
        }
        assertTrue("no keyfile containers were opened, so this measured nothing", checked > 0);
    }

    /**
     * The control. Without it every arm above would pass just as happily against a build
     * that ignored keyfiles entirely, because the passphrase is correct on its own.
     */
    /**
     * Measured at 29 minutes on the emulator, and that is the whole reason for the annotation:
     * three containers, each swept over every layout and every hash before the app is entitled
     * to say no. A negative open has no early exit, so it always pays the full matrix.
     *
     * Excluded from the default run the same way UnsupportedMatrixTest is. What stays in the
     * default run is theWrongKeyfileDoesNotOpenIt, one container at about seven minutes, which
     * is enough to catch a keyfile pool that is being ignored. This arm is the stronger claim,
     * that NO hash and NO layout opens these three with the passphrase alone, and the fixture
     * script already checked the same thing against desktop VeraCrypt at creation time.
     */
    @LargeTest
    @Test
    public void aKeyfileContainerStaysShutWithoutItsKeyfiles() throws Exception
    {
        int checked = 0;
        for(Map.Entry<String, String[]> e: sRows.entrySet())
        {
            String name = e.getKey();
            EdsContainer c = new EdsContainer(
                    StdFs.makePath(new File(sDir, name + ".hc").getAbsolutePath()));
            try
            {
                c.open(e.getValue()[0].getBytes(UTF8));
                fail(name + " opened with the passphrase alone, so its keyfile is doing "
                        + "nothing");
            }
            catch (AssertionError ae)
            {
                throw ae;
            }
            catch (Throwable expected)
            {
                checked++;
            }
            finally
            {
                ContainerPayload.closeQuietly(c);
            }
        }
        assertTrue("no containers were checked", checked > 0);
    }

    /** And the wrong keyfile must be as useless as none at all. */
    @Test
    public void theWrongKeyfileDoesNotOpenIt() throws Exception
    {
        String name = "keyfile_single";
        assertTrue("fixture " + name + " not in the manifest", sRows.containsKey(name));
        byte[] pw = mixedFor(sRows.get(name)[0], "kf2.bin");
        EdsContainer c = new EdsContainer(
                StdFs.makePath(new File(sDir, name + ".hc").getAbsolutePath()));
        try
        {
            c.open(pw);
            fail(name + " opened with the wrong keyfile");
        }
        catch (AssertionError ae)
        {
            throw ae;
        }
        catch (Throwable expected)
        {
            // correct
        }
        finally
        {
            ContainerPayload.closeQuietly(c);
        }
    }

    // ---- helpers ----------------------------------------------------------------------

    private static byte[] mixedFor(String password, String keyfileNames) throws IOException
    {
        List<InputStream> streams = new ArrayList<>();
        try
        {
            for(String n: keyfileNames.split(","))
                if(!n.isEmpty())
                    streams.add(new FileInputStream(new File(sDir, n)));
            return Keyfiles.apply(password.getBytes(UTF8), streams);
        }
        finally
        {
            for(InputStream is: streams)
                try { is.close(); } catch (IOException ignored) { }
        }
    }

    private static void mixFiles(byte[] pool, String... names) throws IOException
    {
        for(String n: names)
            try (InputStream is = new FileInputStream(new File(sDir, n)))
            {
                Keyfiles.mixInto(pool, is);
            }
    }

    private static List<String> readLines(File f) throws IOException
    {
        List<String> res = new ArrayList<>();
        try (java.io.BufferedReader r = new java.io.BufferedReader(
                new java.io.InputStreamReader(new FileInputStream(f), UTF8)))
        {
            String line;
            while((line = r.readLine()) != null)
                if(!line.trim().isEmpty())
                    res.add(line);
        }
        return res;
    }
}
