package com.sovworks.eds.truecrypt;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

/**
 * TrueCrypt and VeraCrypt keyfiles.
 *
 * A keyfile is not a second passphrase and it is not hashed with the password. The format
 * folds every keyfile into a 64 byte pool and then ADDS that pool into the first 64 bytes of
 * the passphrase, byte by byte with wraparound, before anything reaches the KDF. Everything
 * downstream, the header derivation included, sees an ordinary password of at least 64 bytes
 * and needs no knowledge that a keyfile was ever involved. That is why this class hooks in
 * at the point the password is set and nothing in StdLayout changes.
 *
 * The algorithm is fixed by the on-disk format and is not a design choice here. It is
 * VeraCrypt's Common/Keyfile.c, reproduced exactly:
 *
 *   pool = 64 zero bytes
 *   for each keyfile, independently:
 *       crc = 0xffffffff
 *       for each of the first 1048576 bytes b:
 *           crc = table[(crc ^ b) & 0xff] ^ (crc >>> 8)
 *           pool[w++] += crc >>> 24; pool[w++] += crc >>> 16
 *           pool[w++] += crc >>>  8; pool[w++] += crc
 *           if w >= 64 then w = 0
 *   for i in 0..63:
 *       password[i] = i < length ? password[i] + pool[i] : pool[i]
 *   length = max(length, 64)
 *
 * Three details are easy to get wrong and each one produces a container that this app and
 * desktop VeraCrypt disagree about, which is the worst possible failure: it looks like a
 * wrong passphrase.
 *
 * The CRC is never finalised. java.util.zip.CRC32 XORs 0xffffffff into the value when you
 * ask for it, and the running value here is used raw, so the platform class cannot be used
 * even though it computes the same polynomial. The table is built here instead.
 *
 * The CRC restarts at 0xffffffff for every keyfile while the pool carries over, so the set
 * of keyfiles is unordered in its effect on the pool only because addition commutes. Reset
 * the pool per file, or carry the CRC across files, and both produce a plausible-looking
 * pool that is wrong.
 *
 * The additions are modulo 256 and deliberately overflow. Java has no unsigned byte, so the
 * arithmetic is done in int and cast back, which is the same thing.
 */
public final class Keyfiles
{
    public static final int POOL_SIZE = 64;

    /**
     * Only the first mebibyte of each keyfile counts. This is the format's rule, not a
     * performance guard: a keyfile larger than this has bytes past the cap that change
     * nothing, so a user who appends to their keyfile past 1 MiB still opens the container.
     */
    public static final int MAX_READ = 1024 * 1024;

    private Keyfiles()
    {
    }

    /**
     * @param password the passphrase bytes, which are NOT modified
     * @param keyfiles streams to fold in, read in order and never closed here: the caller
     *                 owns them, because the caller is the only one that knows whether a
     *                 stream is a file it opened or a document it was handed
     * @return a new array of max(password.length, 64) bytes, or the password unchanged when
     *         there are no keyfiles at all
     */
    public static byte[] apply(byte[] password, List<InputStream> keyfiles) throws IOException
    {
        if(keyfiles == null || keyfiles.isEmpty())
            return password;
        byte[] pool = new byte[POOL_SIZE];
        try
        {
            for(InputStream is: keyfiles)
                mixInto(pool, is);
            return mixIntoPassword(password, pool);
        }
        finally
        {
            // The pool is key material in its own right: with it an attacker needs only the
            // passphrase, not the keyfile.
            Arrays.fill(pool, (byte) 0);
        }
    }

    /**
     * Folds one keyfile into an existing pool. Exposed for the test that checks a two keyfile
     * pool equals the two one keyfile pools added together, which is the property that says
     * the CRC really does restart per file.
     */
    public static void mixInto(byte[] pool, InputStream is) throws IOException
    {
        int crc = 0xffffffff;
        int w = 0;
        long total = 0;
        byte[] buf = new byte[8192];
        while(total < MAX_READ)
        {
            int want = (int) Math.min(buf.length, MAX_READ - total);
            int n = is.read(buf, 0, want);
            if(n <= 0)
                break;
            for(int i = 0; i < n; i++)
            {
                crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
                pool[w] = (byte) (pool[w] + (crc >>> 24)); w++;
                pool[w] = (byte) (pool[w] + (crc >>> 16)); w++;
                pool[w] = (byte) (pool[w] + (crc >>> 8));  w++;
                pool[w] = (byte) (pool[w] + crc);          w++;
                if(w >= POOL_SIZE)
                    w = 0;
            }
            total += n;
        }
        Arrays.fill(buf, (byte) 0);
    }

    /**
     * An empty passphrase with a keyfile is legal and common: the keyfile IS the credential,
     * and the result is a 64 byte password that is exactly the pool.
     */
    public static byte[] mixIntoPassword(byte[] password, byte[] pool)
    {
        int len = password == null ? 0 : password.length;
        byte[] res = new byte[Math.max(len, POOL_SIZE)];
        if(len > 0)
            System.arraycopy(password, 0, res, 0, len);
        for(int i = 0; i < POOL_SIZE; i++)
            res[i] = i < len ? (byte) (res[i] + pool[i]) : pool[i];
        return res;
    }

    private static final int[] CRC_TABLE = new int[256];

    static
    {
        // The reflected CRC-32 polynomial, the same one zlib uses. Built rather than pasted
        // so there is no 256 entry literal to mistype.
        for(int i = 0; i < 256; i++)
        {
            int c = i;
            for(int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
            CRC_TABLE[i] = c;
        }
    }
}
