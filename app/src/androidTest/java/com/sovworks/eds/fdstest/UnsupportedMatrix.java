package com.sovworks.eds.fdstest;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The negative arm of the oracle: containers this fork has no engine or no hash for, which
 * must therefore fail to open.
 *
 * Split out of ContainerFixtureTest because of what it costs. A container that DOES open
 * stops at the hash that works; a container that does not opens nothing, so it pays the
 * whole hash sweep, and since hidden volumes were unlocked it pays it twice, once for the
 * normal header and once for the hidden one. At the KDF costs measured on this emulator
 * that is minutes per fixture and there are 41 of them.
 *
 * So the default run checks a sample and the full sweep is a separate @LargeTest class. The
 * sample is not a shortcut past the question: it is one fixture per distinct REASON for
 * being unsupported, and the reasons are derived from the manifest rather than listed here.
 * What is skipped is printed by name, because a coverage cut nobody can see reads as
 * coverage.
 */
final class UnsupportedMatrix
{
    static final String CIPHER = "unsupported-cipher";
    static final String HASH = "unsupported-hash";
    static final String BOTH = "unsupported-cipher-and-hash";

    /** Every unsupported fixture the manifest says was created and that is on the device. */
    static List<FixtureSet.Fixture> all(FixtureSet set)
    {
        List<FixtureSet.Fixture> out = new ArrayList<>();
        for (FixtureSet.Fixture f : set.fixtures)
            if (!f.expectFds && "yes".equals(f.created) && f.isOnDisk())
                out.add(f);
        return out;
    }

    /**
     * Why this fixture is expected not to open, derived from the manifest and not from a
     * list kept here. A cipher counts as supported if ANY row the manifest marks supported
     * uses it; same for a hash. A hardcoded roster would rot in both directions: it would
     * keep naming a cipher that was dropped and miss one that was added.
     */
    static String reason(FixtureSet set, FixtureSet.Fixture f)
    {
        Set<String> ciphers = new LinkedHashSet<>(), hashes = new LinkedHashSet<>();
        for (FixtureSet.Fixture s : set.fixtures)
            if (s.expectFds)
            {
                ciphers.add(s.cipher);
                hashes.add(s.hash);
            }
        boolean badCipher = !ciphers.contains(f.cipher);
        boolean badHash = !hashes.contains(f.hash);
        if (badCipher && badHash) return BOTH;
        if (badCipher) return CIPHER;
        if (badHash) return HASH;
        // expect_fds said no and neither half explains it. That is a manifest that
        // contradicts itself, not a fixture to quietly test anyway.
        return "unexplained";
    }

    /**
     * One fixture per reason, first in manifest order so the choice is deterministic and a
     * rerun tests the same thing.
     */
    static Map<String, FixtureSet.Fixture> sample(FixtureSet set)
    {
        Map<String, FixtureSet.Fixture> picked = new LinkedHashMap<>();
        for (FixtureSet.Fixture f : all(set))
        {
            String r = reason(set, f);
            if (!picked.containsKey(r))
                picked.put(r, f);
        }
        return picked;
    }

    /** Returns the fixtures that opened when they should not have. Empty means correct. */
    static List<String> whichOpened(List<FixtureSet.Fixture> targets)
    {
        byte[] pw = FixtureSet.PASSPHRASE.getBytes(Charset.forName("UTF-8"));
        List<String> opened = new ArrayList<>();
        for (FixtureSet.Fixture f : targets)
        {
            try
            {
                ContainerPayload.read(f.file, pw);
                opened.add(f.toString());
            }
            catch (Throwable expected)
            {
                // correct: no engine for this cipher, or no implementation of this hash
            }
        }
        return opened;
    }

    private UnsupportedMatrix()
    {
    }
}
