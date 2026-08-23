package com.sovworks.eds.fdstest;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the fixture manifests produced on the host by tools/mkfixtures.sh.
 *
 * The manifests are the ORACLE. They were written by a desktop VeraCrypt, not by this
 * codebase, so a test built on them cannot pass by agreeing with our own implementation
 * of the format.
 *
 * Nothing here tolerates a missing or empty manifest. A fixture set that cannot be read
 * must make the test FAIL, never make it measure zero containers and report green.
 */
public final class FixtureSet
{
    public static final String PASSPHRASE = "fds-test-passphrase-do-not-reuse";

    /** One row of manifest.tsv. */
    public static final class Fixture
    {
        public final String name;
        public final String cipher;
        public final String hash;
        /** yes | no | created_unfilled */
        public final String created;
        /** yes | no: what the fork's cipher/hash registry claims to support */
        public final boolean expectFds;
        public final File file;

        Fixture(String name, String cipher, String hash, String created, boolean expectFds, File dir)
        {
            this.name = name;
            this.cipher = cipher;
            this.hash = hash;
            this.created = created;
            this.expectFds = expectFds;
            this.file = new File(dir, name + ".hc");
        }

        public boolean isOnDisk()
        {
            return file.isFile() && file.length() > 0;
        }

        @Override
        public String toString()
        {
            return name + " (" + cipher + "/" + hash + ", created=" + created
                    + ", expect_fds=" + expectFds + ")";
        }
    }

    public final File dir;
    public final List<Fixture> fixtures;
    /** relative path inside the container -> sha256 of its content */
    public final Map<String, String> expectedPayload;

    private FixtureSet(File dir, List<Fixture> fixtures, Map<String, String> expectedPayload)
    {
        this.dir = dir;
        this.fixtures = fixtures;
        this.expectedPayload = expectedPayload;
    }

    /**
     * Fixtures are pushed by tools/run-fixture-tests.sh into the app's own external files
     * directory. That location needs no storage permission and no legacy-storage opt-in,
     * so a failure here is a missing push and never a permission puzzle.
     */
    public static File locate(Context appContext)
    {
        File ext = appContext.getExternalFilesDir(null);
        return ext == null ? null : new File(ext, "fixtures");
    }


    /**
     * "Not there" has several causes that look identical from a boolean: the push never
     * happened, it landed somewhere else, or the process cannot read a directory that does
     * exist. Report which one, from inside the app, so the failure names its own cause
     * instead of handing back a path and a guess.
     */
    static String describePath(File leaf)
    {
        StringBuilder sb = new StringBuilder("\n  -- as seen by the app process --");
        List<File> chain = new ArrayList<>();
        for (File f = leaf; f != null; f = f.getParentFile())
            chain.add(0, f);
        for (File f : chain)
            sb.append("\n  ").append(f.getAbsolutePath())
              .append("  exists=").append(f.exists())
              .append(" dir=").append(f.isDirectory())
              .append(" file=").append(f.isFile())
              .append(" read=").append(f.canRead());
        File parent = leaf.getParentFile();
        if (parent != null)
        {
            String[] kids = parent.list();
            sb.append("\n  listing of ").append(parent.getAbsolutePath()).append(": ");
            if (kids == null)
                sb.append("null (list() failed, which is a read denial and not an empty dir)");
            else
            {
                Arrays.sort(kids);
                sb.append(kids.length).append(" entries");
                for (int i = 0; i < kids.length && i < 12; i++)
                    sb.append("\n    ").append(kids[i]);
                if (kids.length > 12)
                    sb.append("\n    ... ").append(kids.length - 12).append(" more");
            }
        }
        return sb.toString();
    }

    public static FixtureSet load(File dir) throws IOException
    {
        File manifest = new File(dir, "manifest.tsv");
        File payload = new File(dir, "payload-manifest.tsv");
        if (!manifest.isFile())
            throw new IOException("fixture manifest missing: " + manifest.getAbsolutePath()
                    + " (run tools/mkfixtures.sh then tools/run-fixture-tests.sh)"
                    + describePath(manifest));
        if (!payload.isFile())
            throw new IOException("payload manifest missing: " + payload.getAbsolutePath()
                    + describePath(payload));

        List<Fixture> fixtures = new ArrayList<>();
        for (String[] f : readTsv(manifest, 6, true))
            fixtures.add(new Fixture(f[0], f[1], f[2], f[3], "yes".equals(f[4]), dir));

        Map<String, String> expected = new LinkedHashMap<>();
        for (String[] f : readTsv(payload, 2, false))
            expected.put(f[0], f[1]);

        if (fixtures.isEmpty())
            throw new IOException("manifest.tsv has no data rows");
        if (expected.isEmpty())
            throw new IOException("payload-manifest.tsv has no rows");

        return new FixtureSet(dir, fixtures, expected);
    }

    private static List<String[]> readTsv(File f, int cols, boolean skipHeader) throws IOException
    {
        List<String[]> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8")))
        {
            String line;
            boolean first = true;
            while ((line = r.readLine()) != null)
            {
                if (line.trim().isEmpty())
                    continue;
                if (first && skipHeader)
                {
                    first = false;
                    continue;
                }
                first = false;
                String[] parts = line.split("\t", -1);
                if (parts.length < cols)
                    throw new IOException(f.getName() + ": expected " + cols
                            + " columns, got " + parts.length + " in: " + line);
                out.add(parts);
            }
        }
        return out;
    }

    public static String sha256(InputStream in) throws IOException
    {
        MessageDigest md;
        try
        {
            md = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IOException("SHA-256 unavailable", e);
        }
        byte[] buf = new byte[64 * 1024];
        int n;
        while ((n = in.read(buf)) > 0)
            md.update(buf, 0, n);
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest())
            sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        return sb.toString();
    }
}
