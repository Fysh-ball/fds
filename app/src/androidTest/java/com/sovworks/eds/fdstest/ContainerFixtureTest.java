package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.fs.std.StdFs;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * M1 test oracle: open real VeraCrypt containers built by a desktop VeraCrypt and check
 * that what comes out is byte for byte what went in.
 *
 * Both arms matter. The supported combinations MUST open and MUST yield the exact payload;
 * the unsupported ones MUST fail to open. A bug that made open() always succeed and a bug
 * that made it always throw each turn exactly one of those two arms red, so neither can
 * hide behind the other.
 */
@RunWith(AndroidJUnit4.class)
public class ContainerFixtureTest
{
    private static FixtureSet sSet;
    private static File sDir;

    @BeforeClass
    public static void loadFixtures() throws Exception
    {
        Context ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        sDir = FixtureSet.locate(ctx);
        assertNotNull("no external files dir on this device", sDir);
        sSet = FixtureSet.load(sDir);
    }

    @Before
    public void requireRealFixtures()
    {
        // Guard against the whole suite passing while measuring nothing. Every other test
        // in this class is only meaningful if these hold.
        assertTrue("fixture dir missing: " + sDir, sDir.isDirectory());
        assertTrue("no fixture rows parsed", sSet.fixtures.size() > 0);
        assertTrue("no expected payload entries", sSet.expectedPayload.size() > 0);
    }

    /**
     * The manifest describes a matrix; the disk must actually hold the containers it claims
     * were created. A push that silently copied nothing would otherwise leave every other
     * test with an empty work list and a green result.
     */
    @Test
    public void manifestAgreesWithWhatWasPushed()
    {
        List<String> missing = new ArrayList<>();
        int claimed = 0;
        for (FixtureSet.Fixture f : sSet.fixtures)
        {
            if (!"yes".equals(f.created))
                continue;
            claimed++;
            if (!f.isOnDisk())
                missing.add(f.name);
        }
        assertTrue("manifest claims no containers were created at all", claimed > 0);
        assertEquals("containers named in manifest but absent on device: " + missing,
                0, missing.size());
    }

    /**
     * The claim the app exists to make. Nothing here trusts our own writer: the containers
     * were created and filled by a desktop VeraCrypt, and the expected hashes come from
     * the host filesystem before the payload ever entered a container.
     */
    @Test
    public void supportedCombinationsOpenAndRoundTrip() throws Exception
    {
        List<FixtureSet.Fixture> targets = new ArrayList<>();
        for (FixtureSet.Fixture f : sSet.fixtures)
            if (f.expectFds && "yes".equals(f.created) && f.isOnDisk())
                targets.add(f);

        assertTrue("no supported fixture is present on the device: the oracle is empty, "
                + "which is a broken fixture push and not a passing test", targets.size() > 0);

        Map<String, String> failures = new LinkedHashMap<>();
        for (FixtureSet.Fixture f : targets)
        {
            try
            {
                Map<String, String> got = readContainerPayload(f.file);
                if (!new TreeMap<>(sSet.expectedPayload).equals(new TreeMap<>(got)))
                    failures.put(f.name, "payload mismatch: expected " + sSet.expectedPayload
                            + " got " + got);
            }
            catch (Throwable t)
            {
                failures.put(f.name, t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        assertEquals(targets.size() + " supported fixtures, failures: " + failures,
                0, failures.size());
    }

    /**
     * The measured coverage gap, asserted rather than described. A container built with a
     * cipher or hash this fork has no implementation for must NOT open. If one of these ever
     * starts opening, the registry gained something and the README is stale: that is a
     * result worth failing for, not a silent improvement.
     *
     * A SAMPLE, one fixture per distinct reason for being unsupported, because a failed open
     * costs the entire hash sweep against both the normal and the hidden header and there
     * are 41 of these. UnsupportedMatrixTest runs all of them and is excluded from the
     * default run rather than deleted. What this skips is printed by name below: a coverage
     * cut that leaves no trace reads afterwards as coverage.
     */
    @Test
    public void unsupportedCombinationsDoNotOpen()
    {
        List<FixtureSet.Fixture> everything = UnsupportedMatrix.all(sSet);
        assertTrue("no unsupported fixture present, so this arm measured nothing",
                everything.size() > 0);

        Map<String, FixtureSet.Fixture> sample = UnsupportedMatrix.sample(sSet);
        assertFalse("the sample is empty although " + everything.size()
                + " unsupported fixtures are present", sample.isEmpty());
        assertFalse("a fixture is marked unsupported and neither its cipher nor its hash "
                        + "explains why, so the manifest contradicts itself",
                sample.containsKey("unexplained"));

        List<FixtureSet.Fixture> targets = new ArrayList<>(sample.values());
        List<String> skipped = new ArrayList<>();
        for (FixtureSet.Fixture f : everything)
            if (!targets.contains(f))
                skipped.add(f.name);
        Log.i("fdstest", "unsupported arm: testing " + sample.keySet() + " as " + targets
                + "; skipping " + skipped.size() + " covered by UnsupportedMatrixTest: "
                + skipped);

        List<String> opened = UnsupportedMatrix.whichOpened(targets);
        assertEquals(targets.size() + " sampled unsupported fixtures (" + sample.keySet()
                + "); these opened anyway: " + opened, 0, opened.size());
    }

    /** A wrong passphrase must be indistinguishable from a wrong format: it must not open. */
    @Test
    public void wrongPassphraseIsRejected() throws Exception
    {
        FixtureSet.Fixture f = firstSupportedOnDisk();
        EdsContainer c = new EdsContainer(StdFs.makePath(f.file.getAbsolutePath()));
        try
        {
            c.open(("not-" + FixtureSet.PASSPHRASE).getBytes(Charset.forName("UTF-8")));
            fail("container " + f.name + " opened with the wrong passphrase");
        }
        catch (Throwable expected)
        {
            // correct
        }
        finally
        {
            closeQuietly(c);
        }
    }

    /**
     * Honest measurement of a capability the fork inherited broken rather than a claim that
     * it works. ExFat.java declares 23 native methods and loads a library that no CMake
     * target in this tree has ever produced, so the module is Absent and any exFAT-formatted
     * container is unreadable. Asserted so that a future build which DOES produce the
     * library turns this red and gets the README updated.
     */
    @Test
    public void exfatModuleIsAbsent()
    {
        assertFalse("the exFAT native module is now present: the fork gained exFAT support "
                        + "and README.MD still says it does not work",
                com.sovworks.eds.fs.exfat.ExFat.isModuleInstalled());
    }

    private FixtureSet.Fixture firstSupportedOnDisk()
    {
        for (FixtureSet.Fixture f : sSet.fixtures)
            if (f.expectFds && "yes".equals(f.created) && f.isOnDisk())
                return f;
        throw new AssertionError("no supported fixture on device");
    }

    /** Opens the container read-only and returns relative path -> sha256 of every file in it. */
    private Map<String, String> readContainerPayload(File container) throws Exception
    {
        return ContainerPayload.read(container, FixtureSet.PASSPHRASE.getBytes(Charset.forName("UTF-8")));
    }

    private static void closeQuietly(EdsContainer c)
    {
        ContainerPayload.closeQuietly(c);
    }
}
