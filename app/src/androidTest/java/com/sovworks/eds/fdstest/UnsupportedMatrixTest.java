package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.LargeTest;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.List;

/**
 * The whole negative matrix, every unsupported fixture, no sampling.
 *
 * Excluded from the default run by tools/run-fixture-tests.sh, which passes
 * notAnnotation=androidx.test.filters.LargeTest when it is given no explicit class. Run it
 * on purpose:
 *
 *     tools/run-fixture-tests.sh com.sovworks.eds.fdstest.UnsupportedMatrixTest
 *
 * Naming a class explicitly drops the exclusion, so this is not unreachable, only off the
 * hot path. Expect hours: every fixture here pays the full hash sweep against both the
 * normal and the hidden header.
 */
@LargeTest
@RunWith(AndroidJUnit4.class)
public class UnsupportedMatrixTest
{
    private static FixtureSet sSet;

    @BeforeClass
    public static void loadFixtures() throws Exception
    {
        Context ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File dir = FixtureSet.locate(ctx);
        assertNotNull("no external files dir on this device", dir);
        sSet = FixtureSet.load(dir);
    }

    @Test
    public void everyUnsupportedCombinationFailsToOpen()
    {
        List<FixtureSet.Fixture> targets = UnsupportedMatrix.all(sSet);
        assertTrue("no unsupported fixture present, so this measured nothing",
                targets.size() > 0);

        List<String> opened = UnsupportedMatrix.whichOpened(targets);
        assertEquals(targets.size() + " unsupported fixtures; these opened anyway: " + opened,
                0, opened.size());
    }
}
