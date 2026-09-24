package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.net.Uri;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.LargeTest;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.android.R;
import com.sovworks.eds.android.errors.UserException;
import com.sovworks.eds.android.locations.ExternalStorageLocation;
import com.sovworks.eds.android.locations.VeraCryptLocation;
import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.crypto.SecureBuffer;
import com.sovworks.eds.fs.std.StdFs;
import com.sovworks.eds.locations.Location;
import com.sovworks.eds.truecrypt.KeyfilePool;
import com.sovworks.eds.truecrypt.Keyfiles;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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

    /*
     * Passphrase = the first N bytes of "abcd...zabcd...", mixed with kf1.bin (and kf2.bin for
     * the last one). From an independent Python port of VeraCrypt's Volume/Keyfile.cpp, which
     * sizes the pool from the passphrase: 64 bytes up to a 64 byte passphrase, 128 above it.
     * Before this was known, Keyfiles.java always used 64, and the three vectors over 64
     * bytes are exactly the ones it got wrong.
     */
    private static final String MIXED_64_KF1 =
            "ba5dae0c926a486db79b81043e60c87dbb8eb5af1a504b856586ff33c58a4f53"
          + "b33c4e4ca222f0883c7bda91a5b4635a7bbd0b6968af1ab7a98b2ec6619c1d9c";
    private static final String MIXED_100_KF1 =
            "22328bf3f636da06f305c66f06adb9b1e42e42e38c57720135344fdb82c7cac3"
          + "f1ff9e04e476d6e33f7b3912e29a857ec781a314a92ab6a47d185aec2cc95881"
          + "059992890da6e1db390c320db12d702e3ac4d832f56142ee9bbe1dc6b233f602"
          + "35b125bebeac1aa5fd00a17fc31adedcb43c6855bf8564132c73d4da35d3c51b";
    private static final String MIXED_128_KF1 =
            "22328bf3f636da06f305c66f06adb9b1e42e42e38c57720135344fdb82c7cac3"
          + "f1ff9e04e476d6e33f7b3912e29a857ec781a314a92ab6a47d185aec2cc95881"
          + "059992890da6e1db390c320db12d702e3ac4d832f56142ee9bbe1dc6b233f602"
          + "35b125be3524931f5e6204e3288045441da6d3c12cf3d3839de5474eaa493c93";
    private static final String MIXED_65_KF12 =
            "53cb40b149794019612f567cccbbe0722af756d48bee6a5a7cac9d74ddd09561"
          + "c890c1823bc13e7d3db04fdee56dbe4040cb42e5493d316ec3a4715bfef1ac8f"
          + "d448674557b181e1aa45738873669d015706db489ee944e16c6d5348f7f1e382"
          + "5308f871377871414fe56e015af166c0a4df8868a0c3d536a1bd5f4487bbbd84";

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

    // ---- the pool size follows the passphrase length ----------------------------------

    /**
     * The boundary, from below. A passphrase of exactly 64 bytes still uses the 64 byte pool,
     * which is the only size this class knew about before and is what every existing
     * container with a short passphrase depends on.
     */
    @Test
    public void aSixtyFourBytePassphraseStillUsesTheSmallPool() throws Exception
    {
        assertArrayEquals("a 64 byte passphrase did not mix like VeraCrypt",
                unhex(MIXED_64_KF1), mixedFor(passphrase(64), "kf1.bin"));
    }

    /**
     * Above 64 bytes VeraCrypt switches to a 128 byte pool, and the write position wraps at
     * 128, so the result is not the small pool padded out: every byte from 0 to 127 differs.
     * The 65 byte case is the boundary from above and uses two keyfiles, so the wraparound
     * and the per-file CRC restart are both exercised at the new size.
     */
    @Test
    public void aPassphraseOverSixtyFourBytesUsesTheLargePool() throws Exception
    {
        assertArrayEquals("a 65 byte passphrase with two keyfiles did not mix like VeraCrypt",
                unhex(MIXED_65_KF12), mixedFor(passphrase(65), "kf1.bin,kf2.bin"));
        assertArrayEquals("a 100 byte passphrase did not mix like VeraCrypt",
                unhex(MIXED_100_KF1), mixedFor(passphrase(100), "kf1.bin"));
        assertArrayEquals("a 128 byte passphrase did not mix like VeraCrypt",
                unhex(MIXED_128_KF1), mixedFor(passphrase(128), "kf1.bin"));
    }

    /**
     * The open path does not call Keyfiles.apply. It builds both pools up front with
     * KeyfilePool, before the passphrase is cut per format, and picks one per format. Both
     * routes must give the same bytes at every length, including either side of the boundary.
     */
    @Test
    public void thePoolTheOpenPathUsesAgreesWithApplyAtEveryLength() throws Exception
    {
        for(int len: new int[]{ 0, 3, 64, 65, 100, 128 })
        {
            byte[] pw = passphrase(len);
            byte[] expected = mixedFor(pw, "kf1.bin,kf2.bin");
            KeyfilePool pool = poolFor("kf1.bin", "kf2.bin");
            try
            {
                assertArrayEquals("KeyfilePool and Keyfiles.apply disagree for a " + len
                        + " byte passphrase", expected, pool.applyTo(pw));
            }
            finally
            {
                pool.close();
            }
        }
    }

    /**
     * VeraCrypt refuses a keyfile with no bytes. An empty one adds nothing to the pool, so
     * accepting it would let a user believe a keyfile is in play when the credential is the
     * passphrase alone.
     */
    @Test
    public void anEmptyKeyfileIsRefused() throws Exception
    {
        List<InputStream> streams = new ArrayList<>();
        streams.add(new FileInputStream(new File(sDir, "kf1.bin")));
        streams.add(new ByteArrayInputStream(new byte[0]));
        try
        {
            KeyfilePool.read(streams);
            fail("an empty keyfile was accepted");
        }
        catch (KeyfilePool.EmptyKeyfileException expected)
        {
            assertEquals("the refusal named the wrong keyfile", 1, expected.getIndex());
        }
        finally
        {
            for(InputStream is: streams)
                is.close();
        }
    }

    /** No keyfiles has one representation, null, so the container never sees an empty pool. */
    @Test
    public void noKeyfilesIsNoPool() throws Exception
    {
        assertNull(KeyfilePool.read(null));
        assertNull(KeyfilePool.read(new ArrayList<InputStream>()));
    }

    /**
     * close() zeroes the pools. A closed pool that still mixed would mix zeros, and zeros are
     * a valid-looking pool: the open would then fail as a wrong passphrase.
     */
    @Test
    public void aClosedPoolRefusesToMix() throws Exception
    {
        KeyfilePool pool = poolFor("kf1.bin");
        pool.close();
        try
        {
            pool.applyTo(new byte[3]);
            fail("a closed keyfile pool was used");
        }
        catch (IllegalStateException expected)
        {
            // correct
        }
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
     * The same containers through the hook the app uses: the PLAIN passphrase goes to open()
     * and the keyfiles go in as a pool beside it, so EdsContainerBase mixes them per format
     * after the format's own length cut. The arm above mixes before open() and would pass
     * against a container that ignored setKeyfiles entirely.
     */
    @Test
    public void everyKeyfileContainerOpensThroughTheContainerHook() throws Exception
    {
        int checked = 0;
        for(Map.Entry<String, String[]> e: sRows.entrySet())
        {
            String name = e.getKey();
            EdsContainer c = new EdsContainer(
                    StdFs.makePath(new File(sDir, name + ".hc").getAbsolutePath()));
            KeyfilePool pool = poolFor(e.getValue()[1].split(","));
            try
            {
                c.setKeyfiles(pool);
                c.open(e.getValue()[0].getBytes(UTF8));
                checked++;
            }
            catch (Throwable t)
            {
                fail(name + " did not open with its keyfiles given through setKeyfiles ("
                        + e.getValue()[1] + "): " + t);
            }
            finally
            {
                pool.close();
                ContainerPayload.closeQuietly(c);
            }
        }
        assertTrue("no keyfile containers were opened, so this measured nothing", checked > 0);
    }

    /**
     * The path the unlock dialog takes: content URIs on the location, read through the
     * ContentResolver. file:// URIs stand in for the picker's content:// ones, because the
     * resolver opens both and the location does not look at the scheme.
     */
    @Test
    public void aKeyfileContainerOpensThroughTheLocation() throws Exception
    {
        ProbeLocation loc = locationFor("keyfile_single", "loc");
        try
        {
            loc.setPassword(new SecureBuffer(sRows.get("keyfile_single")[0].toCharArray()));
            loc.setKeyfiles(uris("kf1.bin"));
            loc.open();
            assertTrue("the location reports closed after a successful open", loc.isOpen());
        }
        finally
        {
            closeQuietly(loc);
        }
        assertNull("close() left the keyfiles on the location, so the next open would reuse "
                + "them without being asked", loc.keyfiles());
    }

    /**
     * An empty keyfile must fail as a message about that keyfile, before any KDF runs. The
     * alternative is "wrong password", and the user retypes a passphrase that was right.
     */
    @Test
    public void anEmptyKeyfileFailsTheOpenByName() throws Exception
    {
        File empty = new File(sCtx().getCacheDir(), "fds-empty-keyfile.bin");
        new FileOutputStream(empty).close();
        ProbeLocation loc = locationFor("keyfile_single", "empty");
        try
        {
            loc.setPassword(new SecureBuffer(sRows.get("keyfile_single")[0].toCharArray()));
            List<Uri> kf = uris("kf1.bin");
            kf.add(Uri.fromFile(empty));
            loc.setKeyfiles(kf);
            try
            {
                loc.open();
                fail("the container opened with an empty keyfile in the list");
            }
            catch (UserException expected)
            {
                assertEquals(sCtx().getString(R.string.keyfile_empty, empty.getName()),
                        expected.getLocalizedMessage());
            }
            assertFalse(loc.isOpen());
            assertNull("a refused open kept the keyfiles for the next attempt", loc.keyfiles());
        }
        finally
        {
            closeQuietly(loc);
            empty.delete();
        }
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

    /** Exposes the keyfile list the location holds, which is otherwise write-only. */
    static class ProbeLocation extends VeraCryptLocation
    {
        ProbeLocation(Location container, Context ctx) throws IOException
        {
            super(container, ctx);
        }

        List<Uri> keyfiles()
        {
            return getSharedData().keyfiles;
        }
    }

    private static Context sCtx()
    {
        return InstrumentationRegistry.getInstrumentation().getTargetContext();
    }

    /**
     * Over a COPY of the fixture, because a location may write to what it opens, and hash
     * pinned to the fixtures' SHA-512 so a positive open is one derivation, not a sweep.
     */
    private static ProbeLocation locationFor(String fixture, String tag) throws Exception
    {
        File dir = new File(sCtx().getCacheDir(), "keyfileloc");
        assertTrue(dir.isDirectory() || dir.mkdirs());
        File copy = new File(dir, fixture + "-" + tag + ".hc");
        try (InputStream in = new FileInputStream(new File(sDir, fixture + ".hc"));
             FileOutputStream out = new FileOutputStream(copy))
        {
            byte[] buf = new byte[65536];
            int n;
            while((n = in.read(buf)) > 0)
                out.write(buf, 0, n);
        }
        Location file = new ExternalStorageLocation(
                sCtx(), "fdstest", copy.getParent(), copy.getName());
        ProbeLocation loc = new ProbeLocation(file, sCtx());
        loc.getExternalSettings().setHashFuncName("SHA-512");
        return loc;
    }

    private static List<Uri> uris(String... names)
    {
        List<Uri> res = new ArrayList<>();
        for(String n: names)
            res.add(Uri.fromFile(new File(sDir, n)));
        return res;
    }

    private static void closeQuietly(VeraCryptLocation loc)
    {
        try
        {
            if(loc != null)
                loc.close(true);
        }
        catch (Throwable ignored)
        {
        }
    }

    private static KeyfilePool poolFor(String... names) throws IOException
    {
        List<InputStream> streams = new ArrayList<>();
        try
        {
            for(String n: names)
                if(!n.isEmpty())
                    streams.add(new FileInputStream(new File(sDir, n)));
            return KeyfilePool.read(streams);
        }
        finally
        {
            for(InputStream is: streams)
                try { is.close(); } catch (IOException ignored) { }
        }
    }

    private static byte[] passphrase(int len)
    {
        byte[] res = new byte[len];
        for(int i = 0; i < len; i++)
            res[i] = (byte) ('a' + i % 26);
        return res;
    }

    private static byte[] unhex(String h)
    {
        byte[] res = new byte[h.length() / 2];
        for(int i = 0; i < res.length; i++)
            res[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return res;
    }

    private static byte[] mixedFor(byte[] password, String keyfileNames) throws IOException
    {
        List<InputStream> streams = new ArrayList<>();
        try
        {
            for(String n: keyfileNames.split(","))
                if(!n.isEmpty())
                    streams.add(new FileInputStream(new File(sDir, n)));
            return Keyfiles.apply(password, streams);
        }
        finally
        {
            for(InputStream is: streams)
                try { is.close(); } catch (IOException ignored) { }
        }
    }

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
