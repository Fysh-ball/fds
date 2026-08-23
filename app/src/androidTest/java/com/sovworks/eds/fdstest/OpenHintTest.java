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

import com.sovworks.eds.android.helpers.ContainerOpeningProgressReporter;
import com.sovworks.eds.android.locations.ContainerBasedLocation;
import com.sovworks.eds.android.locations.ExternalStorageLocation;
import com.sovworks.eds.container.ContainerFormatInfo;
import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.container.VolumeLayout;
import com.sovworks.eds.container.VolumeLayoutBase;
import com.sovworks.eds.crypto.SecureBuffer;
import com.sovworks.eds.fs.std.StdFs;
import com.sovworks.eds.locations.Location;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The open hints, and the flag that decides when it is safe to record one.
 *
 * Unlocking an unhinted VeraCrypt container is a linear scan of the hash list, and at
 * 500000 iterations that scan is the entire cost of an unlock: measured on this emulator,
 * a wrong passphrase against an unhinted container takes about fifteen minutes because it
 * pays four hashes against the normal header and four more against the hidden one.
 * ContainerBasedLocation now writes down which format, cipher and hash actually opened a
 * container so that the second unlock is one derivation instead of a search.
 *
 * The cost is measured here as a COUNT OF HASHES TRIED, read out of the container's own
 * progress reporter, not as elapsed time. A timing assertion on a shared emulator would be
 * the kind of check that goes green because the machine was fast that minute.
 *
 * The other half is the refusal. A hidden open must record nothing, because a recorded hash
 * that disagrees with the outer volume's own header is proof to anyone holding the outer
 * passphrase that a second volume exists. That is the exact scenario hidden volumes are for,
 * so isHiddenVolumeOpened() is asserted in both directions against the two-volume fixture.
 */
@RunWith(AndroidJUnit4.class)
public class OpenHintTest
{
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static FixtureSet sSet;
    private static File sHiddenContainer;
    /** volume name -> passphrase, from the hidden fixture's own manifest */
    private static final Map<String, String> sHiddenPassphrase = new LinkedHashMap<>();

    @BeforeClass
    public static void loadFixtures() throws Exception
    {
        Context ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File dir = FixtureSet.locate(ctx);
        assertNotNull("no external files dir on this device", dir);
        sSet = FixtureSet.load(dir);

        sHiddenContainer = new File(dir, "hidden_AES_SHA_512.hc");
        File manifest = new File(dir, "hidden-manifest.tsv");
        if (!manifest.isFile())
            throw new IOException("hidden fixture manifest missing: " + manifest.getAbsolutePath()
                    + " (run tools/mkhiddenfixture.sh then tools/run-fixture-tests.sh)");
        BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(manifest), UTF8));
        try
        {
            String line;
            boolean header = true;
            while ((line = r.readLine()) != null)
            {
                if (header) { header = false; continue; }
                if (line.trim().isEmpty())
                    continue;
                String[] f = line.split("\t", -1);
                if (f.length != 4)
                    throw new IOException("hidden-manifest.tsv row has " + f.length
                            + " columns, expected 4: " + line);
                sHiddenPassphrase.put(f[0], f[1]);
            }
        }
        finally
        {
            r.close();
        }
    }

    /**
     * The hint is in force, measured rather than assumed.
     *
     * A SHA-256 container is used on purpose: SHA-256 is second in the sweep, so an unhinted
     * open MUST try SHA-512 first and fail on it. Hinted, it must try exactly one. If the
     * hint were quietly ignored both numbers would be two and this fails; if the sweep were
     * broken and only ever tried one hash, the unhinted arm would be one and this fails too.
     * Neither arm can pass by the mechanism doing nothing.
     */
    @Test
    public void aHashHintReplacesTheSearchWithOneDerivation() throws Exception
    {
        FixtureSet.Fixture f = supported("AES", "SHA-256");

        HashCounter unhinted = new HashCounter();
        openVeraCrypt(f.file, null, unhinted);
        HashCounter hinted = new HashCounter();
        openVeraCrypt(f.file, "SHA-256", hinted);

        Log.i("fdstest", "hash attempts on " + f.name + ": unhinted=" + unhinted.hashes
                + " hinted=" + hinted.hashes);
        assertEquals("an unhinted open of a SHA-256 container must try SHA-512 first and then "
                        + "SHA-256; it tried " + unhinted.hashes,
                2, unhinted.hashes.size());
        assertEquals("a hinted open must derive exactly once; it tried " + hinted.hashes,
                1, hinted.hashes.size());
        assertTrue("the hinted open did not use the hash it was given: " + hinted.hashes,
                hinted.hashes.iterator().next().toLowerCase().contains("sha"));
    }

    /**
     * What ContainerBasedLocation.learnHintsFrom() reads back after an open has succeeded.
     * If either getter returned null the hint would silently never be recorded and the
     * feature would be a no-op that no other test could see.
     */
    @Test
    public void aSuccessfulOpenReportsTheFormatCipherAndHashItUsed() throws Exception
    {
        FixtureSet.Fixture f = supported("Twofish", "Whirlpool");
        EdsContainer c = new EdsContainer(StdFs.makePath(f.file.getAbsolutePath()));
        try
        {
            c.open(FixtureSet.PASSPHRASE.getBytes(UTF8));
            ContainerFormatInfo cfi = c.getContainerFormat();
            VolumeLayout vl = c.getVolumeLayout();
            assertNotNull("the container opened but reports no format", cfi);
            assertNotNull("the container opened but reports no volume layout", vl);
            assertNotNull("the layout reports no encryption engine", vl.getEngine());
            assertNotNull("the layout reports no hash function", vl.getHashFunc());

            assertEquals("format", "VeraCrypt", cfi.getFormatName());
            assertEquals("cipher", "twofish-xts-plain64",
                    VolumeLayoutBase.getEncEngineName(vl.getEngine()).toLowerCase());
            assertTrue("the hash the layout reports (" + vl.getHashFunc().getAlgorithm()
                            + ") is not the whirlpool this container was built with",
                    vl.getHashFunc().getAlgorithm().toLowerCase().contains("whirlpool"));
        }
        finally
        {
            ContainerPayload.closeQuietly(c);
        }
    }

    /**
     * A recorded hint has to survive a round trip through the settings file, because that is
     * the only reason to record it. Asserted against the same JSON the app writes, and the
     * negative arm asserts an untouched settings object reports no learned hints: without
     * that, a bug making hasLearnedHints() always true would leave the stale-hint recovery
     * path firing on every failed open and this test still green.
     */
    @Test
    public void learnedHintsSurviveTheSettingsRoundTrip() throws Exception
    {
        com.sovworks.eds.android.locations.ContainerBasedLocation.ExternalSettings a =
                new com.sovworks.eds.android.locations.ContainerBasedLocation.ExternalSettings();
        assertFalse("a fresh settings object claims to already hold learned hints",
                a.hasLearnedHints());

        a.setLearnedHints("VeraCrypt", "aes-xts-plain64", "SHA-512");
        assertTrue("setLearnedHints did not register", a.hasLearnedHints());

        org.json.JSONObject jo = new org.json.JSONObject();
        a.saveToJSONObject(jo);

        com.sovworks.eds.android.locations.ContainerBasedLocation.ExternalSettings b =
                new com.sovworks.eds.android.locations.ContainerBasedLocation.ExternalSettings();
        b.loadFromJSONOjbect(jo);
        assertEquals("format did not survive", "VeraCrypt", b.getLearnedFormatName());
        assertEquals("cipher did not survive", "aes-xts-plain64", b.getLearnedEncEngineName());
        assertEquals("hash did not survive", "SHA-512", b.getLearnedHashFuncName());

        // The user's own hints are a separate channel and must not have been written by any
        // of the above. If the two shared storage, clearing a stale inference would silently
        // throw away what the user typed, and the app would be overruling an answer the user
        // gave it.
        assertTrue("recording an inferred format also wrote the user's format field: "
                + b.getContainerFormatName(), isEmpty(b.getContainerFormatName()));
        assertTrue("recording an inferred cipher also wrote the user's cipher field: "
                + b.getEncEngineName(), isEmpty(b.getEncEngineName()));
        assertTrue("recording an inferred hash also wrote the user's hash field: "
                + b.getHashFuncName(), isEmpty(b.getHashFuncName()));

        b.setLearnedHints(null, null, null);
        assertFalse("clearing the learned hints left hasLearnedHints() true",
                b.hasLearnedHints());
    }

    /**
     * The security half. A hidden open must be reportable as hidden, because that flag is the
     * only thing stopping the app from writing the hidden volume's hash into a settings file
     * that someone with the OUTER passphrase can compare against the outer header.
     *
     * Both directions are asserted on the SAME file. A flag stuck at false passes the first
     * assertion and fails the second; stuck at true, the reverse.
     */
    @Test
    public void theHiddenFlagDistinguishesTheTwoVolumes() throws Exception
    {
        assertTrue("hidden fixture missing: " + sHiddenContainer, sHiddenContainer.isFile());
        assertEquals("hidden-manifest.tsv must name exactly the outer and hidden volumes",
                2, sHiddenPassphrase.size());

        assertFalse("opening the OUTER volume reported itself as a hidden open, so the app "
                        + "would refuse to record a hint that is safe to record",
                openAndReportHidden(sHiddenContainer, sHiddenPassphrase.get("outer")));
        assertTrue("opening the HIDDEN volume did NOT report itself as hidden, so the app "
                        + "would write the hidden volume's hash into the container settings "
                        + "and anyone given the outer passphrase could detect it",
                openAndReportHidden(sHiddenContainer, sHiddenPassphrase.get("hidden")));
    }

    /**
     * A container with no hidden volume must also report false, and this is not the same
     * assertion as the outer volume above. open() runs the normal pass and then the hidden
     * pass; on a single-volume container the hidden pass runs and FAILS, and the flag is set
     * at the top of each attempt. If it were never reset on the way out of a failed attempt,
     * a later successful open on the same object would report hidden and the app would stop
     * recording hints for ordinary containers, silently.
     */
    @Test
    public void anOrdinaryContainerNeverReportsAHiddenOpen() throws Exception
    {
        FixtureSet.Fixture f = supported("AES", "SHA-512");
        assertFalse("a single-volume container reported a hidden open",
                openAndReportHidden(f.file, FixtureSet.PASSPHRASE));
    }

    private static boolean openAndReportHidden(File container, String passphrase) throws Exception
    {
        assertTrue("no passphrase for " + container.getName(),
                passphrase != null && !passphrase.isEmpty());
        EdsContainer c = new EdsContainer(StdFs.makePath(container.getAbsolutePath()));
        try
        {
            c.open(passphrase.getBytes(UTF8));
            return c.isHiddenVolumeOpened();
        }
        finally
        {
            ContainerPayload.closeQuietly(c);
        }
    }

    /** Opens as VeraCrypt only, optionally with a hash hint, counting the hashes tried. */
    private static void openVeraCrypt(File container, String hashHint, HashCounter counter)
            throws Exception
    {
        ContainerFormatInfo cfi = EdsContainer.findFormatByName("VeraCrypt");
        assertNotNull("no VeraCrypt format is registered", cfi);
        EdsContainer c = new EdsContainer(StdFs.makePath(container.getAbsolutePath()));
        try
        {
            c.setContainerFormat(cfi);
            c.setProgressReporter(counter);
            if (hashHint != null)
            {
                // Resolved against the layout's own list rather than by a spelling written
                // here. VolumeLayoutBase.findHashFunc is a substring match on the algorithm
                // name, and the VeraCrypt layout registers SHA-256 through
                // MessageDigest.getInstance("SHA256"), so getAlgorithm() answers "SHA256"
                // with no hyphen and a literal "SHA-256" finds nothing. That is not a defect
                // in the app: every caller feeds findHashFunc a name taken out of this same
                // list, and LUKS, which really does use "SHA-256", overrides the lookup. It
                // was a defect in this test, which invented a spelling.
                MessageDigest md = findHashLoosely(
                        cfi.getVolumeLayout().getSupportedHashFuncs(), hashHint);
                assertNotNull("no hash resembling " + hashHint + " is offered by the VeraCrypt "
                        + "layout; it offers " + hashNames(cfi.getVolumeLayout().getSupportedHashFuncs()),
                        md);
                c.setHashFuncHint(md);
            }
            c.open(FixtureSet.PASSPHRASE.getBytes(UTF8));
        }
        finally
        {
            ContainerPayload.closeQuietly(c);
        }
    }

    /**
     * The glue, exercised through the class the app actually calls: open a container the way
     * the file manager does, then open it again and prove the second unlock derived once.
     *
     * Everything above this test measures a mechanism. This one measures the feature. It runs
     * against the real settings store, so it clears its own learned hints before AND after:
     * a leftover hint from a previous run would make the "second open derives once" assertion
     * pass without the first open having recorded anything.
     */
    @Test
    public void aContainerLocationLearnsItsHintOnTheFirstOpenAndUsesItOnTheSecond() throws Exception
    {
        FixtureSet.Fixture f = supported("AES", "SHA-256");
        forgetLearnedHints(f.file);
        try
        {
            HashCounter first = new HashCounter();
            ContainerBasedLocation a = locationFor(f.file);
            a.setOpeningProgressReporter(first);
            a.open();
            try
            {
                assertEquals("the first open did not record the format it used",
                        "VeraCrypt", a.getExternalSettings().getLearnedFormatName());
                assertEquals("the first open did not record the cipher it used",
                        "aes-xts-plain64",
                        String.valueOf(a.getExternalSettings().getLearnedEncEngineName()).toLowerCase());
                assertTrue("the first open recorded the hash as "
                                + a.getExternalSettings().getLearnedHashFuncName(),
                        String.valueOf(a.getExternalSettings().getLearnedHashFuncName())
                                .toLowerCase().contains("sha"));
            }
            finally
            {
                a.close(true);
            }
            // Not a literal count, and the run that produced this comment is why. The first
            // draft asserted 2, reasoning about the VeraCrypt sweep alone. A location does
            // not pin a format: EdsContainer.SUPPORTED_FORMATS is TrueCrypt, VeraCrypt,
            // LUKS in that order, so the TrueCrypt pass runs first and contributes SHA-512,
            // whirlpool and ripemd160 before VeraCrypt is reached. It measured
            // [SHA-512, whirlpool, ripemd160, SHA256]: four, and correct. That is cheap,
            // 1000 iterations against VeraCrypt's 500000, which is why it never showed up
            // on the stopwatch.
            //
            // Asserting 4 instead would just re-encode the format registry order in a test
            // that is not about it. What this arm is for is that an unhinted open SEARCHES
            // and a hinted one does not, so it asserts the shape: more than one hash tried,
            // the last of them the one the container was built with.
            List<String> tried = new ArrayList<>(first.hashes);
            assertTrue("the unhinted open did not search at all; it tried " + tried,
                    tried.size() > 1);
            assertTrue("the unhinted open did not finish on the hash the container was built "
                            + "with; it tried " + tried,
                    squash(tried.get(tried.size() - 1)).contains("sha256"));

            // A separate instance, so the hint has to come back out of the settings store
            // rather than out of a field the first location still happens to be holding.
            HashCounter second = new HashCounter();
            ContainerBasedLocation b = locationFor(f.file);
            b.setOpeningProgressReporter(second);
            b.open();
            b.close(true);
            Log.i("fdstest", "location-level hash attempts: first=" + first.hashes
                    + " second=" + second.hashes);
            assertEquals("the second open did not use the recorded hint; it tried "
                            + second.hashes, 1, second.hashes.size());
            assertTrue("the second open derived once but with the wrong hash: " + second.hashes,
                    squash(second.hashes.iterator().next()).contains("sha256"));
        }
        finally
        {
            forgetLearnedHints(f.file);
        }
    }

    /**
     * A recorded hint that stops matching must not be able to lock the user out.
     *
     * The stale hint used here names TrueCrypt for a VeraCrypt container on purpose: it is
     * the cheap failure. TrueCrypt runs 1000 iterations against VeraCrypt's 500000, so the
     * doomed first attempt costs about a second instead of the ten minutes a wrong-hash hint
     * would cost, and the recovery is what is being measured, not the arithmetic.
     *
     * Without the recovery this test does not merely fail an assertion, it throws: the open
     * itself is the check.
     */
    @Test
    public void aStaleLearnedHintIsDiscardedAndTheOpenSucceedsAnyway() throws Exception
    {
        FixtureSet.Fixture f = supported("AES", "SHA-512");
        forgetLearnedHints(f.file);
        try
        {
            ContainerBasedLocation a = locationFor(f.file);
            a.getExternalSettings().setLearnedHints("TrueCrypt", "aes-xts-plain64", "SHA-512");
            a.saveExternalSettings();

            ContainerBasedLocation b = locationFor(f.file);
            assertEquals("the stale hint was not stored, so this test would have measured "
                            + "an ordinary open", "TrueCrypt",
                    b.getExternalSettings().getLearnedFormatName());
            b.open();
            try
            {
                assertEquals("the stale hint was discarded but the correct format was not "
                                + "recorded in its place", "VeraCrypt",
                        b.getExternalSettings().getLearnedFormatName());
            }
            finally
            {
                b.close(true);
            }
        }
        finally
        {
            forgetLearnedHints(f.file);
        }
    }

    private static ContainerBasedLocation locationFor(File container) throws Exception
    {
        Context ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        Location file = new ExternalStorageLocation(ctx, "fdstest", "/",
                container.getAbsolutePath());
        ContainerBasedLocation loc = new ContainerBasedLocation(file, ctx);
        loc.setPassword(new SecureBuffer(FixtureSet.PASSPHRASE.getBytes(UTF8)));
        return loc;
    }

    /** Leaves the real settings store as this test found it, in both directions. */
    private static void forgetLearnedHints(File container) throws Exception
    {
        ContainerBasedLocation loc = locationFor(container);
        loc.getExternalSettings().setLearnedHints(null, null, null);
        loc.saveExternalSettings();
    }

    private static boolean isEmpty(String s)
    {
        return s == null || s.isEmpty();
    }

    private static FixtureSet.Fixture supported(String cipher, String hash)
    {
        List<String> present = new ArrayList<>();
        for (FixtureSet.Fixture f : sSet.fixtures)
        {
            if (!f.expectFds || !"yes".equals(f.created) || !f.isOnDisk())
                continue;
            present.add(f.cipher + "/" + f.hash);
            if (cipher.equals(f.cipher) && hash.equals(f.hash))
                return f;
        }
        fail("no " + cipher + "/" + hash + " fixture on the device; supported fixtures present: "
                + present);
        throw new AssertionError("unreachable");
    }

    /** Matches ignoring case and any punctuation, so "SHA-256" finds "SHA256". */
    private static MessageDigest findHashLoosely(Iterable<MessageDigest> algs, String name)
    {
        String want = squash(name);
        for (MessageDigest md : algs)
            if (squash(md.getAlgorithm()).equals(want))
                return md;
        return null;
    }

    private static String squash(String s)
    {
        return s.toLowerCase().replaceAll("[^a-z0-9]", "");
    }

    private static List<String> hashNames(Iterable<MessageDigest> algs)
    {
        List<String> l = new ArrayList<>();
        for (MessageDigest md : algs)
            l.add(md.getAlgorithm());
        return l;
    }

    /**
     * Counts the DISTINCT hash functions the open path derived a key with. The reporter is
     * called once per (hash, cipher) pair, so the cipher sweep would inflate a raw call
     * count while costing almost nothing: only the KDF is expensive, and only the distinct
     * hashes measure it.
     */
    private static final class HashCounter implements ContainerOpeningProgressReporter
    {
        final Set<String> hashes = new LinkedHashSet<>();

        @Override public void setCurrentKDFName(String name) { if (name != null) hashes.add(name); }
        @Override public void setCurrentEncryptionAlgName(String name) { }
        @Override public void setContainerFormatName(String name) { }
        @Override public void setIsHidden(boolean val) { }
        @Override public void setText(CharSequence text) { }
        @Override public void setProgress(int progress) { }
        @Override public boolean isCancelled() { return false; }
    }
}
