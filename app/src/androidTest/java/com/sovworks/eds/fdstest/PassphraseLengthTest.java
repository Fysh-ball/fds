package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.android.locations.ExternalStorageLocation;
import com.sovworks.eds.android.locations.VeraCryptLocation;
import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.container.EdsContainerBase;
import com.sovworks.eds.crypto.SecureBuffer;
import com.sovworks.eds.exceptions.WrongFileFormatException;
import com.sovworks.eds.locations.Location;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;

/**
 * How long a passphrase survives the trip from the location to the container.
 *
 * ContainerBasedLocation used to cut every passphrase to 64 bytes, TrueCrypt's limit, before
 * the container saw it, whatever the format. VeraCrypt allows 128 and LUKS far more, and
 * creation cuts per format rather than through the location, so a VeraCrypt or LUKS container
 * this app created with a passphrase over 64 bytes could not be reopened by it. The only cut
 * now is the per-format one inside EdsContainerBase.
 *
 * No container is opened and no KDF runs. The location is given a container whose open()
 * records what it was handed and refuses, which is the one observation that matters here:
 * the bytes the location passes down. A real open would only add minutes and a fixture
 * without making the assertion any sharper.
 */
@RunWith(AndroidJUnit4.class)
public class PassphraseLengthTest
{
    /** A VeraCryptLocation whose container records the passphrase instead of using it. */
    static class CapturingLocation extends VeraCryptLocation
    {
        CapturingLocation(Location container, Context ctx) throws IOException
        {
            super(container, ctx);
        }

        @Override
        protected EdsContainer initEdsContainer() throws IOException
        {
            return new EdsContainer(getLocation().getCurrentPath())
            {
                @Override
                public synchronized void open(byte[] password) throws WrongFileFormatException
                {
                    seen = password == null ? null : password.clone();
                    throw new WrongFileFormatException();
                }
            };
        }

        byte[] seen;
    }

    private static Context sCtx;
    private static File sFile;

    @BeforeClass
    public static void setUp() throws Exception
    {
        sCtx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        sFile = new File(sCtx.getCacheDir(), "passphrase_length_probe.hc");
        // Exists so that resolving the path cannot fail for a reason of its own. It is never
        // read: the capturing container refuses before touching it.
        if(!sFile.exists() && !sFile.createNewFile())
            throw new IOException("could not create " + sFile);
    }

    /**
     * The regression. With the old cut in place this saw 64 bytes, the first 64 of the 100.
     */
    @Test
    public void aLongVeraCryptPassphraseReachesTheContainerWhole() throws Exception
    {
        byte[] seen = passDown(100);
        assertNotNull("the container was never asked to open", seen);
        assertEquals("the location cut the passphrase before the container saw it",
                100, seen.length);
        assertArrayEquals(ascii(100), seen);
    }

    /** The boundary: 64 bytes was always passed whole and still must be. */
    @Test
    public void aSixtyFourBytePassphraseIsUnchanged() throws Exception
    {
        assertArrayEquals(ascii(64), passDown(64));
    }

    /**
     * With the location's cut gone, the per-format cut is the only thing enforcing each
     * format's limit, so the limits it reads are pinned here: TrueCrypt 64, VeraCrypt 128.
     * If VeraCrypt's ever fell back to the inherited 64, the regression above would come back
     * one layer down and the test above would not see it.
     */
    @Test
    public void theFormatsStillCutToTheirOwnLimits()
    {
        byte[] pw = ascii(200);
        assertEquals(64, EdsContainerBase.cutPassword(pw,
                new com.sovworks.eds.truecrypt.FormatInfo().getMaxPasswordLength()).length);
        assertEquals(128, EdsContainerBase.cutPassword(pw,
                new com.sovworks.eds.veracrypt.FormatInfo().getMaxPasswordLength()).length);
    }

    private static byte[] passDown(int len) throws Exception
    {
        Location file = new ExternalStorageLocation(
                sCtx, "fdstest", sFile.getParent(), sFile.getName());
        CapturingLocation loc = new CapturingLocation(file, sCtx);
        char[] pw = new char[len];
        for(int i = 0; i < len; i++)
            pw[i] = (char) ('a' + i % 26);
        loc.setPassword(new SecureBuffer(pw));
        try
        {
            loc.open();
            fail("the capturing container refuses every open");
        }
        catch (Exception expected)
        {
            // WrongPasswordOrBadContainerException, from the refusal above
        }
        return loc.seen;
    }

    private static byte[] ascii(int len)
    {
        byte[] res = new byte[len];
        for(int i = 0; i < len; i++)
            res[i] = (byte) ('a' + i % 26);
        return res;
    }
}
