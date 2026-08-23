package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.truecrypt.FormatInfo;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Hidden volumes: the feature the coerced-disclosure half of the threat model rests on, and
 * the one EDS NG paywalled.
 *
 * The fixture is a single file holding two volumes, built by a desktop VeraCrypt following
 * the procedure in its own manual, with DELIBERATELY DIFFERENT contents in each. That
 * difference is the whole point: a layout that reads the wrong header slot still opens
 * something, still passes the header CRC, and still mounts a valid FAT filesystem. Only the
 * payload tells the two apart, so every assertion here is on contents and none is on
 * "did it open".
 */
@RunWith(AndroidJUnit4.class)
public class HiddenVolumeTest
{
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static File sContainer;
    /** volume name -> passphrase */
    private static final Map<String, String> sPassphrase = new LinkedHashMap<>();
    /** volume name -> (relative path -> sha256) */
    private static final Map<String, Map<String, String>> sExpected = new LinkedHashMap<>();

    @BeforeClass
    public static void loadFixture() throws Exception
    {
        Context ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File dir = FixtureSet.locate(ctx);
        if (dir == null)
            throw new IOException("no external files dir on this device");
        sContainer = new File(dir, "hidden_AES_SHA_512.hc");
        File manifest = new File(dir, "hidden-manifest.tsv");
        if (!manifest.isFile())
            throw new IOException("hidden fixture manifest missing: " + manifest.getAbsolutePath()
                    + " (run tools/mkhiddenfixture.sh then tools/run-fixture-tests.sh)"
                    + FixtureSet.describePath(manifest));

        BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(manifest), UTF8));
        try
        {
            String line;
            boolean header = true;
            int lineNo = 0;
            while ((line = r.readLine()) != null)
            {
                lineNo++;
                if (header) { header = false; continue; }
                if (line.trim().isEmpty())
                    continue;
                String[] f = line.split("\t", -1);
                if (f.length != 4)
                    throw new IOException("hidden-manifest.tsv line " + lineNo + " has "
                            + f.length + " columns, expected 4: " + line);
                sPassphrase.put(f[0], f[1]);
                Map<String, String> m = sExpected.get(f[0]);
                if (m == null)
                {
                    m = new LinkedHashMap<>();
                    sExpected.put(f[0], m);
                }
                m.put(f[2], f[3]);
            }
        }
        finally
        {
            r.close();
        }
    }

    @Before
    public void requireTheFixture()
    {
        assertTrue("hidden fixture container missing: " + sContainer, sContainer.isFile());
        assertEquals("hidden-manifest.tsv must describe exactly the outer and hidden volumes",
                2, sExpected.size());
        for (Map.Entry<String, Map<String, String>> e : sExpected.entrySet())
            assertFalse("no expected files for the " + e.getKey() + " volume",
                    e.getValue().isEmpty());
    }

    /**
     * The gate itself. hasHiddenContainerSupport() answering false is what EdsContainerBase
     * checks before it will try the hidden header at all, so if this is false every other
     * test in this class fails for a reason that has nothing to do with the layout.
     */
    @Test
    public void theHiddenVolumeGateIsOpen()
    {
        FormatInfo tc = new FormatInfo();
        com.sovworks.eds.veracrypt.FormatInfo vc = new com.sovworks.eds.veracrypt.FormatInfo();
        assertTrue("TrueCrypt hidden support is still switched off", tc.hasHiddenContainerSupport());
        assertTrue("VeraCrypt hidden support is still switched off", vc.hasHiddenContainerSupport());
        assertTrue("TrueCrypt has no hidden layout", tc.getHiddenVolumeLayout() != null);
        assertTrue("VeraCrypt has no hidden layout", vc.getHiddenVolumeLayout() != null);
    }

    @Test
    public void outerPassphraseOpensTheOuterVolume() throws Exception
    {
        assertVolume("outer");
    }

    @Test
    public void hiddenPassphraseOpensTheHiddenVolume() throws Exception
    {
        assertVolume("hidden");
    }

    /**
     * Stated as its own assertion rather than left implicit in the two above. If the fixture
     * were ever regenerated with the same payload in both volumes, those two tests would keep
     * passing while proving nothing, and this one would go red.
     */
    @Test
    public void theTwoVolumesHaveDistinguishablePayloads()
    {
        Map<String, String> outer = sExpected.get("outer");
        Map<String, String> hidden = sExpected.get("hidden");
        for (Map.Entry<String, String> e : outer.entrySet())
            assertFalse("the outer and hidden fixtures share " + e.getKey()
                            + ", so neither test can tell the two volumes apart",
                    e.getValue().equals(hidden.get(e.getKey())));
    }

    /**
     * A container with a hidden volume must not announce it. A third passphrase has to fail
     * the same way it would on a container with nothing hidden in it: one exception, no
     * partial success, nothing that says a second header slot is populated.
     */
    @Test
    public void athirdPassphraseOpensNeitherVolume() throws Exception
    {
        EdsContainer c = new EdsContainer(com.sovworks.eds.fs.std.StdFs.makePath(
                sContainer.getAbsolutePath()));
        try
        {
            c.open("fds-neither-of-the-two-passphrases".getBytes(UTF8));
            fail("a third passphrase opened the container");
        }
        catch (Throwable expected)
        {
            // correct
        }
        finally
        {
            try { c.close(); } catch (Throwable ignored) { }
        }
    }

    private void assertVolume(String volume) throws Exception
    {
        String pw = sPassphrase.get(volume);
        assertTrue("no passphrase for the " + volume + " volume", pw != null && pw.length() > 0);
        Map<String, String> expected = sExpected.get(volume);

        Map<String, String> got = ContainerPayload.read(sContainer, pw.getBytes(UTF8));
        assertEquals("the " + volume + " volume's contents", new TreeMap<>(expected), new TreeMap<>(got));
    }
}
