package com.sovworks.eds.truecrypt;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

/**
 * The keyfiles the user picked, already folded into pools, for one open.
 *
 * Keyfiles.apply() wants the passphrase before it reads the keyfiles, because the pool size
 * depends on the passphrase length. At open time that length is not known yet: the container
 * cuts the passphrase per format (64 bytes for TrueCrypt, 128 for VeraCrypt) inside the
 * format search. So both pools are built here, in one read of each keyfile, and the right
 * one is picked per format once the cut passphrase exists. The keyfiles themselves are never
 * held in memory, only the two pools derived from them.
 *
 * The pools are key material: with one, an attacker needs only the passphrase and not the
 * keyfile. close() zeroes them and every caller must reach it.
 */
public final class KeyfilePool implements Closeable
{
    /**
     * A keyfile with no bytes in it. VeraCrypt refuses these (Keyfile.cpp, MinProcessedLength)
     * rather than treating them as no keyfile, and so does this: an empty file contributes
     * nothing to the pool, so accepting it would let a container that needs a real keyfile
     * appear to have been given one.
     */
    public static class EmptyKeyfileException extends IOException
    {
        public EmptyKeyfileException(int index)
        {
            super("keyfile " + (index + 1) + " is empty");
            _index = index;
        }

        /** Position of the offending keyfile in the list given to read(). */
        public int getIndex()
        {
            return _index;
        }

        private final int _index;
    }

    /**
     * @param keyfiles read in order and never closed here, for the same reason Keyfiles.apply
     *                 leaves them open: the caller knows what they are
     * @return null when the list is null or empty, so "no keyfiles" has one representation
     */
    public static KeyfilePool read(List<InputStream> keyfiles) throws IOException
    {
        if(keyfiles == null || keyfiles.isEmpty())
            return null;
        KeyfilePool res = new KeyfilePool();
        boolean ok = false;
        try
        {
            for(int i = 0; i < keyfiles.size(); i++)
                if(Keyfiles.mixInto(keyfiles.get(i), res._legacy, res._large) == 0)
                    throw new EmptyKeyfileException(i);
            ok = true;
            return res;
        }
        finally
        {
            if(!ok)
                res.close();
        }
    }

    /**
     * Mixes the pool the format prescribes for this passphrase into a copy of it.
     *
     * @param password the passphrase AFTER the format's length cut, not modified
     * @return a new array the caller owns
     */
    public byte[] applyTo(byte[] password)
    {
        if(_legacy == null)
            throw new IllegalStateException("keyfile pool is closed");
        int len = password == null ? 0 : password.length;
        return Keyfiles.mixIntoPassword(password,
                Keyfiles.poolSizeFor(len) == Keyfiles.POOL_SIZE ? _legacy : _large);
    }

    @Override
    public void close()
    {
        if(_legacy != null)
            Arrays.fill(_legacy, (byte) 0);
        if(_large != null)
            Arrays.fill(_large, (byte) 0);
        _legacy = _large = null;
    }

    private KeyfilePool()
    {
    }

    private byte[] _legacy = new byte[Keyfiles.POOL_SIZE];
    private byte[] _large = new byte[Keyfiles.LARGE_POOL_SIZE];
}
