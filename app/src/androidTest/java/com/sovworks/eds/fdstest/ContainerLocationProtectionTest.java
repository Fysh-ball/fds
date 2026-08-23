package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.android.errors.UserException;
import com.sovworks.eds.android.locations.ContainerBasedLocation;
import com.sovworks.eds.android.locations.ExternalStorageLocation;
import com.sovworks.eds.android.locations.VeraCryptLocation;
import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.crypto.SecureBuffer;
import com.sovworks.eds.locations.Location;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;

/**
 * The wiring between the unlock dialog and the container, tested at the LOCATION rather than
 * at the container.
 *
 * OuterVolumeProtectionTest proves the protection itself works when EdsContainerBase is
 * handed a second passphrase directly. That leaves the entire path the app actually uses
 * unmeasured: the dialog puts a SecureBuffer in a bundle, the opener fragment copies it onto
 * the location, the location hands the bytes to the container and zeroes them. Every one of
 * those steps can drop the passphrase silently, and the symptom of dropping it is not an
 * error: it is an outer volume that mounts read-write with no protection at all, which is
 * exactly the state the feature exists to prevent and looks identical to success.
 *
 * So the assertion here is never "open() did not throw". It is "the container came back with
 * protection ACTIVE", with a control that opens the same fixture the same way without the
 * second passphrase and requires protection to be OFF.
 */
@RunWith(AndroidJUnit4.class)
public class ContainerLocationProtectionTest
{
    private static Context sCtx;
    private static HiddenFixture sFixture;
    private static File sScratchDir;

    @BeforeClass
    public static void loadFixture() throws Exception
    {
        sCtx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        sFixture = HiddenFixture.load(sCtx);
        sScratchDir = new File(sCtx.getCacheDir(), "locprotection");
    }

    @Before
    public void requireTheFixture()
    {
        assertNull(sFixture.whatIsMissing(), sFixture.whatIsMissing());
    }

    /**
     * The path the app takes. Both passphrases go in through the public Openable/
     * ContainerLocation setters, exactly as LocationOpenerFragmentCommon sets them.
     */
    @Test
    public void theSecondPassphraseReachesTheContainerAndSwitchesProtectionOn() throws Exception
    {
        ContainerBasedLocation loc = locationFor(sFixture.copy(sScratchDir, "wired"));
        try
        {
            loc.setPassword(pass(sFixture.outerPassphrase));
            loc.setHiddenVolumeProtectionPassword(pass(sFixture.hiddenPassphrase));
            loc.open();

            EdsContainer cnt = loc.getEdsContainer();
            assertNotNull("the location opened without producing a container", cnt);
            assertTrue("the location opened, but the container reports no protected range: the "
                            + "second passphrase was lost somewhere between the setter and the open, "
                            + "and this outer volume would be writable straight through the hidden one",
                    cnt.isHiddenVolumeProtectionEnabled());
        }
        finally
        {
            closeQuietly(loc);
        }
    }

    /**
     * The control. Without it the assertion above could pass on a container that switches
     * protection on for every open, which would be a different bug wearing the same green.
     */
    @Test
    public void withoutTheSecondPassphraseTheSameOpenHasNoProtection() throws Exception
    {
        ContainerBasedLocation loc = locationFor(sFixture.copy(sScratchDir, "unwired"));
        try
        {
            loc.setPassword(pass(sFixture.outerPassphrase));
            loc.open();

            EdsContainer cnt = loc.getEdsContainer();
            assertNotNull("the location opened without producing a container", cnt);
            assertFalse("protection is on for a mount that was never given a second passphrase",
                    cnt.isHiddenVolumeProtectionEnabled());
        }
        finally
        {
            closeQuietly(loc);
        }
    }

    /**
     * An empty field is the user declining protection this time, not a broken container. It
     * has to reach the location so a value typed on a previous attempt is cleared, and it has
     * to mean "no protection" once it gets there.
     */
    @Test
    public void anEmptySecondPassphraseMeansNoProtectionRatherThanAFailedMount() throws Exception
    {
        ContainerBasedLocation loc = locationFor(sFixture.copy(sScratchDir, "empty"));
        try
        {
            loc.setPassword(pass(sFixture.outerPassphrase));
            loc.setHiddenVolumeProtectionPassword(new SecureBuffer(new char[0]));
            loc.open();
            assertFalse("an empty protection field switched protection on",
                    loc.getEdsContainer().isHiddenVolumeProtectionEnabled());
        }
        finally
        {
            closeQuietly(loc);
        }
    }

    /**
     * A wrong second passphrase must refuse the mount, and it must refuse it as something the
     * UI can show. The container throws HiddenVolumeProtectionFailedException; the location is
     * the layer that turns it into a UserException, and it must not be swallowed into the
     * WrongFileFormatException retry above it, because that retry would open the container
     * with protection off.
     */
    @Test
    public void aWrongSecondPassphraseRefusesTheMountThroughTheLocation() throws Exception
    {
        ContainerBasedLocation loc = locationFor(sFixture.copy(sScratchDir, "wrongprot"));
        try
        {
            loc.setPassword(pass(sFixture.outerPassphrase));
            loc.setHiddenVolumeProtectionPassword(pass(sFixture.hiddenPassphrase + "-not-this-one"));
            try
            {
                loc.open();
                fail("the mount was allowed with a protection passphrase that opened no hidden "
                        + "volume, so the outer volume is mounted unprotected");
            }
            catch (UserException expected)
            {
                assertEquals("the refusal did not carry the message the UI shows",
                        sCtx.getString(com.sovworks.eds.android.R.string.hidden_volume_protection_failed),
                        expected.getMessage());
            }
            assertFalse("the location is open after a refused mount", loc.isOpen());
        }
        finally
        {
            closeQuietly(loc);
        }
    }

    /**
     * The location must not hold the second passphrase after the mount is over. It is the
     * only long-lived object in this path, and a SharedData that keeps it alive keeps a
     * hidden volume's passphrase in the process for as long as the app runs.
     */
    @Test
    public void closingTheLocationDropsTheSecondPassphrase() throws Exception
    {
        ContainerBasedLocation loc = locationFor(sFixture.copy(sScratchDir, "dropped"));
        loc.setPassword(pass(sFixture.outerPassphrase));
        SecureBuffer prot = pass(sFixture.hiddenPassphrase);
        loc.setHiddenVolumeProtectionPassword(prot);
        loc.open();
        assertTrue(loc.getEdsContainer().isHiddenVolumeProtectionEnabled());
        loc.close(true);

        // Reopening with the outer passphrase alone must come back unprotected. If the buffer
        // survived the close it would still be applied here, which reads as the feature
        // working and is in fact the passphrase outliving the mount that needed it.
        loc.setPassword(pass(sFixture.outerPassphrase));
        try
        {
            loc.open();
            assertFalse("protection is still on after close(), so the second passphrase "
                    + "outlived the mount", loc.getEdsContainer().isHiddenVolumeProtectionEnabled());
        }
        finally
        {
            closeQuietly(loc);
        }
    }

    private static VeraCryptLocation locationFor(File containerFile) throws Exception
    {
        // mountPath is the root and currentPath is RELATIVE to it: passing the absolute path
        // as the second argument concatenates the two and opens a path that does not exist.
        Location file = new ExternalStorageLocation(
                sCtx, "fdstest", containerFile.getParent(), containerFile.getName());

        // VeraCryptLocation rather than the generic base, and the hash pinned, purely for
        // cost: the wiring under test lives in ContainerBasedLocation and VeraCryptLocation
        // inherits every line of it, but an unpinned open sweeps four hash functions at
        // 500,000 iterations each on a device that is already the slowest thing in the loop.
        // The hint is only ever applied to the OUTER header. The hidden header keeps its full
        // search, because VeraCrypt lets a hidden volume use a different hash from its outer
        // volume, and pinning it here would make the wrong-passphrase test pass for a reason
        // that has nothing to do with the passphrase.
        VeraCryptLocation loc = new VeraCryptLocation(file, sCtx);
        loc.getExternalSettings().setHashFuncName("SHA-512");
        return loc;
    }

    private static SecureBuffer pass(String s)
    {
        return new SecureBuffer(s.toCharArray());
    }

    private static void closeQuietly(ContainerBasedLocation loc)
    {
        try
        {
            if (loc != null)
                loc.close(true);
        }
        catch (Throwable ignored)
        {
            // The test's own verdict has already been decided by this point; a close failure
            // here would replace a real assertion message with a teardown one.
        }
    }
}
