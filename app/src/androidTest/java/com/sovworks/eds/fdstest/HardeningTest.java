package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.android.helpers.WipeFilesTask;
import com.sovworks.eds.android.settings.UserSettings;
import com.sovworks.eds.android.settings.UserSettingsCommon;
import com.sovworks.eds.fs.std.StdFs;
import com.sovworks.eds.settings.DefaultSettings;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;

/**
 * The M4 hardening, asserted rather than described.
 *
 * Everything here is about a state the app is in when nobody is looking at it: a screen
 * that just turned off, a task swiped out of recents, a temp file that used to hold
 * plaintext. None of it has a visible symptom when it regresses, which is exactly why it
 * needs a test that fails.
 */
@RunWith(AndroidJUnit4.class)
public class HardeningTest
{
    private static Context ctx()
    {
        return InstrumentationRegistry.getInstrumentation().getTargetContext();
    }

    @After
    public void restoreSettings()
    {
        SharedPreferences.Editor e = UserSettings.getSettings(ctx()).getSharedPreferences().edit();
        e.remove(UserSettingsCommon.LOCK_ON_SCREEN_OFF);
        e.remove(UserSettingsCommon.LOCK_ON_TASK_REMOVED);
        e.commit();
    }

    /**
     * Both locks default ON. Asserted on the DEFAULTS object, not on the live settings,
     * because the live one answers from a preference file that a previous test could have
     * written: reading it back would confirm the write, not the default.
     */
    @Test
    public void bothAutomaticLocksAreOnOutOfTheBox()
    {
        DefaultSettings d = new DefaultSettings();
        assertTrue("screen-off lock must default on: the threat model starts with a device "
                + "that left its owner's hands", d.lockOnScreenOff());
        assertTrue("task-removed lock must default on", d.lockOnTaskRemoved());
    }

    /**
     * A default that cannot be turned off is a different bug from a default that is wrong.
     * The negative direction is the one that matters here: if the preference were ignored,
     * the getter would keep answering true and the test above would still pass.
     */
    @Test
    public void bothAutomaticLocksCanBeTurnedOff()
    {
        UserSettings s = UserSettings.getSettings(ctx());
        assertTrue("precondition: lock starts on", s.lockOnScreenOff());
        assertTrue("precondition: lock starts on", s.lockOnTaskRemoved());

        s.getSharedPreferences().edit()
                .putBoolean(UserSettingsCommon.LOCK_ON_SCREEN_OFF, false)
                .putBoolean(UserSettingsCommon.LOCK_ON_TASK_REMOVED, false)
                .commit();

        assertFalse("the screen-off preference is not read", s.lockOnScreenOff());
        assertFalse("the task-removed preference is not read", s.lockOnTaskRemoved());
    }

    /**
     * The wipe must not truncate and must not extend.
     *
     * The old implementation opened the file through getOutputStream(), which truncates to
     * zero, and then wrote whole 4 KiB blocks until it had covered the original length. For
     * any size that is not a multiple of 4096 that OVERSHOOTS: a 10000-byte file came back
     * 12288 bytes long. The length assertion below is what catches that, and it fails
     * against the old code.
     */
    @Test
    public void overwritingDoesNotChangeTheFileLength() throws Exception
    {
        File f = new File(ctx().getCacheDir(), "wipe-len.bin");
        final int size = 10000;   // deliberately not a multiple of the 4096 block
        byte[] zeros = new byte[size];
        try (FileOutputStream os = new FileOutputStream(f))
        {
            os.write(zeros);
        }
        assertEquals("precondition: fixture written at the wrong size", size, f.length());

        WipeFilesTask.overwriteFileRnd(StdFs.getStdFs().getPath(f.getAbsolutePath()).getFile(), null);

        assertTrue("the overwrite deleted the file; overwriteFileRnd must not", f.exists());
        assertEquals("the overwrite changed the file length: it either truncated the file or "
                + "wrote past its end, and in both cases some of the original bytes were "
                + "never covered", size, f.length());
    }

    /** The bytes actually change, over the whole file including the partial last block. */
    @Test
    public void overwritingReplacesEveryByteIncludingTheTail() throws Exception
    {
        File f = new File(ctx().getCacheDir(), "wipe-content.bin");
        final int size = 10000;
        byte[] plain = new byte[size];
        Arrays.fill(plain, (byte) 0x41);
        try (FileOutputStream os = new FileOutputStream(f))
        {
            os.write(plain);
        }

        WipeFilesTask.overwriteFileRnd(StdFs.getStdFs().getPath(f.getAbsolutePath()).getFile(), null);

        byte[] after = new byte[size];
        try (RandomAccessFile raf = new RandomAccessFile(f, "r"))
        {
            raf.readFully(after);
        }
        assertNotEquals("nothing was written at all", 0, countDifferent(plain, after));

        // The tail is the interesting part: it is the region the block loop is most likely
        // to skip, and it is checked separately so that a wipe covering only the first 8192
        // bytes cannot pass on the strength of what it did cover.
        int tailStart = (size / 4096) * 4096;
        boolean tailUntouched = true;
        for (int i = tailStart; i < size; i++)
            if (after[i] != 0x41)
            {
                tailUntouched = false;
                break;
            }
        assertFalse("the last partial block (bytes " + tailStart + ".." + size
                + ") still holds the original plaintext", tailUntouched);
    }

    /** wipeFileRnd still deletes. The split into overwrite + delete must not have lost it. */
    @Test
    public void wipingStillRemovesTheFile() throws Exception
    {
        File f = new File(ctx().getCacheDir(), "wipe-delete.bin");
        try (FileOutputStream os = new FileOutputStream(f))
        {
            os.write(new byte[1024]);
        }
        assertTrue("precondition", f.exists());
        WipeFilesTask.wipeFileRnd(StdFs.getStdFs().getPath(f.getAbsolutePath()).getFile());
        assertFalse("wipeFileRnd left the file behind", f.exists());
    }

    private static int countDifferent(byte[] a, byte[] b)
    {
        int n = 0;
        for (int i = 0; i < a.length; i++)
            if (a[i] != b[i])
                n++;
        return n;
    }
}
