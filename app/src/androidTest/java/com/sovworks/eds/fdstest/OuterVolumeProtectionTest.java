package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.container.HiddenVolumeProtectedException;
import com.sovworks.eds.container.HiddenVolumeProtectingIO;
import com.sovworks.eds.container.HiddenVolumeProtectionFailedException;
import com.sovworks.eds.fs.RandomAccessIO;
import com.sovworks.eds.fs.std.StdFs;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Outer-volume protection, end to end, against a real two-volume container.
 *
 * The claim under test is not "a write was refused". It is "the hidden volume is still there
 * afterwards", so every assertion here ends by reopening the hidden volume and comparing its
 * payload to the manifest.
 *
 * The reason that distinction matters is theDestructiveControl below. It performs the SAME
 * write at the SAME offset with protection off, and requires the hidden volume to be
 * destroyed. Without it, the protected test would pass just as happily if the offset were
 * wrong, if the write never reached the disk, or if the container refused writes for some
 * entirely unrelated reason: a green result would mean nothing at all. Every copy is a scratch
 * copy; the fixture itself is never written to.
 */
@RunWith(AndroidJUnit4.class)
public class OuterVolumeProtectionTest
{
    private static final Charset UTF8 = Charset.forName("UTF-8");
    /** One FAT cluster's worth, aligned to the 512-byte XTS sector. */
    private static final int WRITE_LEN = 4096;

    private static File sFixture;
    private static File sScratchDir;
    private static String sOuterPw;
    private static String sHiddenPw;
    private static Map<String, String> sHiddenExpected;

    @BeforeClass
    public static void loadFixture() throws Exception
    {
        Context ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File dir = FixtureSet.locate(ctx);
        if (dir == null)
            throw new IOException("no external files dir on this device");
        sFixture = new File(dir, "hidden_AES_SHA_512.hc");
        sScratchDir = new File(ctx.getCacheDir(), "protection");
        if (!sScratchDir.isDirectory() && !sScratchDir.mkdirs())
            throw new IOException("cannot create " + sScratchDir);

        File manifest = new File(dir, "hidden-manifest.tsv");
        if (!manifest.isFile())
            throw new IOException("hidden fixture manifest missing: " + manifest.getAbsolutePath()
                    + " (run tools/mkhiddenfixture.sh then tools/run-fixture-tests.sh)"
                    + FixtureSet.describePath(manifest));

        Map<String, String> hidden = new LinkedHashMap<>();
        BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(manifest), UTF8));
        try
        {
            String line;
            boolean header = true;
            while ((line = r.readLine()) != null)
            {
                if (header) { header = false; continue; }
                if (line.trim().isEmpty()) continue;
                String[] f = line.split("\t", -1);
                if (f.length != 4)
                    throw new IOException("hidden-manifest.tsv needs 4 columns: " + line);
                if ("outer".equals(f[0]))
                    sOuterPw = f[1];
                else if ("hidden".equals(f[0]))
                {
                    sHiddenPw = f[1];
                    hidden.put(f[2], f[3]);
                }
            }
        }
        finally
        {
            r.close();
        }
        sHiddenExpected = hidden;
    }

    @Before
    public void requireTheFixture()
    {
        assertTrue("hidden fixture container missing: " + sFixture, sFixture.isFile());
        assertTrue("no outer passphrase in the manifest", sOuterPw != null && !sOuterPw.isEmpty());
        assertTrue("no hidden passphrase in the manifest", sHiddenPw != null && !sHiddenPw.isEmpty());
        assertFalse("the manifest lists no files for the hidden volume, so 'the hidden volume "
                + "survived' would be true of an empty volume too", sHiddenExpected.isEmpty());
    }

    /**
     * The one that matters. Protection on, a write aimed squarely at the first byte of the
     * hidden volume, and the hidden volume intact afterwards.
     */
    @Test
    public void aWriteAimedAtTheHiddenVolumeIsRefusedAndTheHiddenVolumeSurvives() throws Exception
    {
        File scratch = copyFixture("protected");
        long protectedStart;
        EdsContainer c = openOuter(scratch, sHiddenPw.getBytes(UTF8));
        try
        {
            RandomAccessIO io = c.getEncryptedFile(false);
            assertTrue("getEncryptedFile returned a " + io.getClass().getSimpleName()
                    + ", not a HiddenVolumeProtectingIO, so nothing in this test is protected "
                    + "by anything and the refusal below would have to come from elsewhere",
                    io instanceof HiddenVolumeProtectingIO);
            HiddenVolumeProtectingIO p = (HiddenVolumeProtectingIO) io;
            protectedStart = p.getProtectedStart();
            Log.i("fdstest", "protected outer range [" + p.getProtectedStart() + ", "
                    + p.getProtectedEnd() + ") of " + io.length());
            assertTrue("the protected range starts at " + protectedStart
                    + ", which is not inside the outer volume", protectedStart > 0);

            // First a write that must be ALLOWED, immediately before the hidden volume. A
            // wrapper that refused everything would satisfy the assertion below without
            // protecting anything, and this is the cheapest way to rule that out in situ.
            io.seek(protectedStart - WRITE_LEN);
            io.write(filled(WRITE_LEN, 0x11), 0, WRITE_LEN);
            io.flush();
            assertFalse("a write ending exactly where the hidden volume begins was refused",
                    p.isTripped());

            io.seek(protectedStart);
            try
            {
                io.write(filled(WRITE_LEN, 0x22), 0, WRITE_LEN);
                io.flush();
                fail("a " + WRITE_LEN + "-byte write at " + protectedStart
                        + ", the first byte of the hidden volume, was allowed");
            }
            catch (HiddenVolumeProtectedException expected)
            {
                // correct
            }
            assertTrue("the refusal did not latch", p.isTripped());
        }
        finally
        {
            ContainerPayload.closeQuietly(c);
        }

        assertEquals("the hidden volume changed even though the write was refused",
                new TreeMap<>(sHiddenExpected),
                new TreeMap<>(ContainerPayload.read(scratch, sHiddenPw.getBytes(UTF8))));
        scratch.delete();
    }

    /**
     * The control, and the only reason the test above is evidence of anything.
     *
     * Same container, same offset, same bytes, protection off. The hidden volume must come out
     * damaged. If this test ever goes green while asserting survival, the write is not landing
     * where this suite believes it lands and the protected result is measuring nothing.
     */
    @Test
    public void theSameWriteWithoutProtectionDestroysTheHiddenVolume() throws Exception
    {
        // Learn the offset from a protected open, then use it on a second, unprotected copy.
        long protectedStart;
        File probe = copyFixture("probe");
        EdsContainer c = openOuter(probe, sHiddenPw.getBytes(UTF8));
        try
        {
            protectedStart = ((HiddenVolumeProtectingIO) c.getEncryptedFile(false)).getProtectedStart();
        }
        finally
        {
            ContainerPayload.closeQuietly(c);
            probe.delete();
        }

        File scratch = copyFixture("unprotected");
        c = openOuter(scratch, null);
        try
        {
            RandomAccessIO io = c.getEncryptedFile(false);
            assertFalse("the container wrapped its IO in a protector even though no protection "
                    + "passphrase was given, so this control cannot damage anything",
                    io instanceof HiddenVolumeProtectingIO);
            io.seek(protectedStart);
            io.write(filled(WRITE_LEN, 0x22), 0, WRITE_LEN);
            io.flush();
        }
        finally
        {
            ContainerPayload.closeQuietly(c);
        }

        Map<String, String> after;
        try
        {
            after = ContainerPayload.read(scratch, sHiddenPw.getBytes(UTF8));
        }
        catch (Throwable damaged)
        {
            // The hidden volume no longer mounts at all, which is the strongest form of the
            // result this control is asserting.
            Log.i("fdstest", "unprotected write destroyed the hidden volume: " + damaged);
            scratch.delete();
            return;
        }
        assertNotEquals("an unprotected " + WRITE_LEN + "-byte write at " + protectedStart
                        + " left the hidden volume byte-identical, so that offset is not "
                        + "inside the hidden volume and the protected test proves nothing",
                new TreeMap<>(sHiddenExpected), new TreeMap<>(after));
        scratch.delete();
    }

    /**
     * A protection passphrase that opens nothing must refuse the MOUNT, not warn.
     *
     * Mounting the outer volume read-write with protection silently off is indistinguishable
     * from a protected mount right up to the moment the hidden volume is overwritten, and by
     * then there is nothing to undo.
     */
    @Test
    public void aWrongProtectionPassphraseRefusesTheMount() throws Exception
    {
        File scratch = copyFixture("wrongpw");
        EdsContainer c = new EdsContainer(StdFs.makePath(scratch.getAbsolutePath()));
        try
        {
            c.setContainerFormat(new com.sovworks.eds.veracrypt.FormatInfo());
            c.setHiddenVolumeProtectionPassword("fds-not-the-hidden-passphrase".getBytes(UTF8));
            c.open(sOuterPw.getBytes(UTF8));
            fail("the container mounted with a protection passphrase that opens no hidden volume");
        }
        catch (HiddenVolumeProtectionFailedException expected)
        {
            // correct
        }
        finally
        {
            ContainerPayload.closeQuietly(c);
            scratch.delete();
        }
    }

    private static EdsContainer openOuter(File container, byte[] protectionPw) throws Exception
    {
        EdsContainer c = new EdsContainer(StdFs.makePath(container.getAbsolutePath()));
        // Pinned purely for speed: the fixture is VeraCrypt, and leaving the format unpinned
        // makes every open in this class sweep TrueCrypt first. It does not pin the hash, so
        // the hidden header is still found by search the way it would be in the app.
        c.setContainerFormat(new com.sovworks.eds.veracrypt.FormatInfo());
        if (protectionPw != null)
            c.setHiddenVolumeProtectionPassword(protectionPw);
        c.open(sOuterPw.getBytes(UTF8));
        return c;
    }

    private static File copyFixture(String tag) throws IOException
    {
        File out = new File(sScratchDir, tag + "_" + sFixture.getName());
        InputStream in = new FileInputStream(sFixture);
        try
        {
            OutputStream os = new FileOutputStream(out);
            try
            {
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0)
                    os.write(buf, 0, n);
                os.flush();
            }
            finally
            {
                os.close();
            }
        }
        finally
        {
            in.close();
        }
        if (out.length() != sFixture.length())
            throw new IOException("scratch copy is " + out.length() + " bytes, fixture is "
                    + sFixture.length());
        return out;
    }

    private static byte[] filled(int n, int v)
    {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) v);
        return b;
    }
}
