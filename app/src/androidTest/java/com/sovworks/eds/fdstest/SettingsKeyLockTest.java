package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.android.EdsApplicationBase;
import com.sovworks.eds.android.settings.UserSettings;
import com.sovworks.eds.crypto.SecureBuffer;
import com.sovworks.eds.settings.SettingsCommon.InvalidSettingsPassword;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * What a screen-off lock has to forget, and what it must NOT break by forgetting it.
 *
 * Closing every container is not the whole of a lock. The master password and the 32 byte
 * settings protection key derived from it outlive every location, so the service now clears
 * both. The clear is only correct if the key comes back on the next read, and the obvious
 * wrong way to write it is the one this class demonstrates rather than describes.
 *
 * ACTION_SCREEN_OFF is a protected broadcast, so a test cannot drive the receiver itself.
 * These tests drive the two calls the receiver makes, which is where the whole risk lives:
 * the receiver body is two lines and a log.
 */
@RunWith(AndroidJUnit4.class)
public class SettingsKeyLockTest
{
    private static final String KEY = "fdstest_protected_probe";
    private static final String VALUE = "correct horse battery staple";

    private UserSettings _s;

    @Before
    public void setUp()
    {
        Context ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        _s = UserSettings.getSettings(ctx);
        EdsApplicationBase.clearMasterPassword();
        _s.clearSettingsProtectionKey();
    }

    @After
    public void tearDown()
    {
        // Leave no probe behind, and leave the singleton in the state every other test
        // expects: no master password, no cached key.
        try
        {
            EdsApplicationBase.clearMasterPassword();
            _s.clearSettingsProtectionKey();
        }
        catch (Throwable ignored)
        {
        }
    }

    @Test
    public void aProtectedFieldRoundTripsThroughTheDerivedKey() throws Exception
    {
        _s.setProtectedField(KEY, VALUE);
        assertArrayEquals(
                "a protected field did not come back as it went in",
                VALUE.getBytes(), _s.getProtectedData(KEY));
    }

    /**
     * The positive arm of the lock. Dropping the cached key must cost nothing but a
     * re-derivation, because with no master password set the key is re-derived from the
     * device-local automatic password with nothing for the user to type.
     */
    @Test
    public void clearingTheCachedKeyStillLetsProtectedSettingsBeRead() throws Exception
    {
        _s.setProtectedField(KEY, VALUE);
        _s.clearSettingsProtectionKey();
        assertArrayEquals(
                "clearing the cached key made a protected setting unreadable",
                VALUE.getBytes(), _s.getProtectedData(KEY));
    }

    @Test
    public void clearingTheCachedKeyGivesADifferentBufferBack() throws Exception
    {
        SecureBuffer before = _s.getSettingsProtectionKey();
        assertNotNull("no settings protection key at all", before);
        _s.clearSettingsProtectionKey();
        SecureBuffer after = _s.getSettingsProtectionKey();
        assertNotNull("the key did not come back after being cleared", after);
        assertTrue("the same buffer came back, so the cache was never dropped", before != after);
    }

    /**
     * The known-bad, run as a test rather than as a reverted build, because it is the exact
     * thing SecureBuffer.closeAll() would do and closeAll() is one line away from looking
     * like the right call at a lock point.
     *
     * close() erases the bytes and removes the id from the static registry, but it cannot
     * reach UserSettingsCommon's field. getSettingsProtectionKey memoises on "field is null",
     * so the cache still reads as populated while pointing at a dead id. The next protected
     * read reaches SimpleCrypto.decrypt, which throws "key is closed", and getProtectedData
     * converts that into InvalidSettingsPassword: the app reports a wrong settings password
     * to a user who never had one.
     *
     * If this test ever stops throwing, the memoisation has changed and the comment on
     * forgetResidentKeys is stale.
     */
    @Test
    public void erasingTheBufferWithoutDroppingTheCacheBreaksProtectedReads() throws Exception
    {
        _s.setProtectedField(KEY, VALUE);
        _s.getSettingsProtectionKey().close();
        try
        {
            _s.getProtectedData(KEY);
            fail("a protected read succeeded against an erased key, so the hazard "
                    + "forgetResidentKeys is written to avoid no longer exists");
        }
        catch (InvalidSettingsPassword expected)
        {
            // This is the symptom the user would see: a wrong-password report with no
            // wrong password anywhere in it.
        }
        // And the supported clear is the repair, which is the other half of the point.
        _s.clearSettingsProtectionKey();
        assertArrayEquals(
                "clearSettingsProtectionKey did not recover the broken state",
                VALUE.getBytes(), _s.getProtectedData(KEY));
    }

    @Test
    public void theMasterPasswordIsGoneAfterAClear()
    {
        EdsApplicationBase.setMasterPassword(new SecureBuffer("a master password".toCharArray()));
        assertNotNull("the master password did not take", EdsApplicationBase.getMasterPassword());
        EdsApplicationBase.clearMasterPassword();
        assertNull("the master password survived the lock", EdsApplicationBase.getMasterPassword());
    }

    @Test
    public void clearingTheMasterPasswordErasesItRatherThanDroppingTheReference()
    {
        SecureBuffer mp = new SecureBuffer("a master password".toCharArray());
        EdsApplicationBase.setMasterPassword(mp);
        EdsApplicationBase.clearMasterPassword();
        // length() is null-tolerant by design and answers 0 for an erased buffer, so this
        // asks the buffer itself whether its bytes are gone, not whether the field is.
        assertEquals("the master password buffer still holds its contents", 0, mp.length());
    }
}
