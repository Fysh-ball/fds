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
 *   n = length <= 64 ? 64 : 128
 *   pool = n zero bytes
 *   for each keyfile, independently:
 *       crc = 0xffffffff
 *       for each of the first 1048576 bytes b:
 *           crc = table[(crc ^ b) & 0xff] ^ (crc >>> 8)
 *           pool[w++] += crc >>> 24; pool[w++] += crc >>> 16
 *           pool[w++] += crc >>>  8; pool[w++] += crc
 *           if w >= n then w = 0
 *   for i in 0..n-1:
 *       password[i] = i < length ? password[i] + pool[i] : pool[i]
 *   length = max(length, n)
 *
 * The pool size depends on the PASSPHRASE. VeraCrypt raised the passphrase limit from 64 to
 * 128 bytes and, to keep every existing container opening, kept the 64 byte pool for any
 * passphrase that fits the old limit and uses a 128 byte one only above it
 * (Common/Keyfiles.c: keyPoolSize = Length <= MAX_LEGACY_PASSWORD ? 64 : 128; the Linux
 * build's Volume/Keyfile.cpp has the same rule). The write position wraps at the pool size,
 * so the two pools are different functions of the same keyfile, not one a prefix of the
 * other. TrueCrypt caps passphrases at 64 bytes and so only ever uses the smaller one.
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
    /** The pool for any passphrase of up to 64 bytes, which is every TrueCrypt one. */
    public static final int POOL_SIZE = 64;

    /** The pool for a VeraCrypt passphrase longer than 64 bytes. */
    public static final int LARGE_POOL_SIZE = 128;

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
     * The pool size the format uses for a passphrase of this many bytes. See the class comment.
     */
    public static int poolSizeFor(int passwordLength)
    {
        return passwordLength <= POOL_SIZE ? POOL_SIZE : LARGE_POOL_SIZE;
    }

    /**
     * @param password the passphrase bytes, which are NOT modified
     * @param keyfiles streams to fold in, read in order and never closed here: the caller
     *                 owns them, because the caller is the only one that knows whether a
     *                 stream is a file it opened or a document it was handed
     * @return a new array of max(password.length, pool size) bytes, or the password unchanged
     *         when there are no keyfiles at all
     */
    public static byte[] apply(byte[] password, List<InputStream> keyfiles) throws IOException
    {
        if(keyfiles == null || keyfiles.isEmpty())
            return password;
        byte[] pool = new byte[poolSizeFor(password == null ? 0 : password.length)];
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
     *
     * The write position wraps at pool.length, so this serves both pool sizes.
     *
     * @return how many bytes of the keyfile were read, at most MAX_READ
     */
    public static long mixInto(byte[] pool, InputStream is) throws IOException
    {
        return mixInto(is, pool);
    }

    /**
     * Folds one keyfile into every pool given, in a single read of the stream. The CRC is the
     * same for all of them; only the wraparound differs. This exists so that a keyfile the
     * user picked is read once, when the passphrase length and therefore the pool size is
     * not known yet: it is cut per container format, after the keyfiles have been read.
     */
    static long mixInto(InputStream is, byte[]... pools) throws IOException
    {
        int crc = 0xffffffff;
        int[] w = new int[pools.length];
        long total = 0;
        byte[] buf = new byte[8192];
        try
        {
            while(total < MAX_READ)
            {
                int want = (int) Math.min(buf.length, MAX_READ - total);
                int n = is.read(buf, 0, want);
                if(n <= 0)
                    break;
                for(int i = 0; i < n; i++)
                {
                    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
                    for(int p = 0; p < pools.length; p++)
                    {
                        byte[] pool = pools[p];
                        int j = w[p];
                        pool[j] = (byte) (pool[j] + (crc >>> 24)); j++;
                        pool[j] = (byte) (pool[j] + (crc >>> 16)); j++;
                        pool[j] = (byte) (pool[j] + (crc >>> 8));  j++;
                        pool[j] = (byte) (pool[j] + crc);          j++;
                        w[p] = j >= pool.length ? 0 : j;
                    }
                }
                total += n;
            }
        }
        finally
        {
            Arrays.fill(buf, (byte) 0);
        }
        return total;
    }

    /**
     * An empty passphrase with a keyfile is legal and common: the keyfile IS the credential,
     * and the result is a password that is exactly the pool.
     *
     * Mixes the whole of the pool it is given. Choosing the right pool for the passphrase is
     * the caller's job (poolSizeFor), because this method cannot tell a deliberate choice from
     * a mistake.
     */
    public static byte[] mixIntoPassword(byte[] password, byte[] pool)
    {
        int len = password == null ? 0 : password.length;
        byte[] res = new byte[Math.max(len, pool.length)];
        if(len > 0)
            System.arraycopy(password, 0, res, 0, len);
        for(int i = 0; i < pool.length; i++)
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
