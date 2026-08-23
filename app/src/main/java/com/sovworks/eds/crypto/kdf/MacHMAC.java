package com.sovworks.eds.crypto.kdf;

import java.security.DigestException;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.sovworks.eds.crypto.EncryptionEngineException;

/**
 * HMAC computed by the platform provider in one call instead of by six MessageDigest calls.
 *
 * PBKDF2 is a tight loop around HMAC, and at VeraCrypt's 500000 iterations the cost is not
 * the hashing. The generic {@link HMAC} rebuilds the ipad and opad blocks and crosses the
 * JCA boundary six times per iteration, so three million boundary crossings dominate a
 * single unlock. javax.crypto.Mac keeps the key schedule and does the whole HMAC natively.
 *
 * This is an optimisation only where the platform actually has a native HMAC for the digest:
 * {@link #macNameFor} returns null for the two hashes this app carries its own JNI code for
 * (ripemd160, whirlpool), and those keep the generic path. Both paths must produce identical
 * bytes, which is what KdfEquivalenceTest asserts rather than assumes.
 */
public class MacHMAC extends HMAC
{
    /**
     * The JCE Mac name for a digest, or null when the platform has none and the caller must
     * keep the generic implementation. Matches on the digest's own reported algorithm, which
     * is why both "SHA-512" and "SHA512" have to be accepted: veracrypt.VolumeLayout asks for
     * "SHA256" and truecrypt.StdLayout asks for "SHA-512", and a provider is free to report
     * either spelling back.
     */
    public static String macNameFor(MessageDigest md)
    {
        String n = md.getAlgorithm();
        if (n == null)
            return null;
        n = n.toLowerCase(java.util.Locale.ROOT).replace("-", "");
        if (n.equals("sha512"))
            return "HmacSHA512";
        if (n.equals("sha256"))
            return "HmacSHA256";
        if (n.equals("sha1"))
            return "HmacSHA1";
        return null;
    }

    public MacHMAC(byte[] key, MessageDigest md, int blockSize, String macName) throws EncryptionEngineException
    {
        super(key, md, blockSize);
        if (key.length == 0)
            throw new EncryptionEngineException("Mac rejects an empty key");
        try
        {
            _mac = Mac.getInstance(macName);
            _mac.init(new SecretKeySpec(key, macName));
        }
        catch (Exception e)
        {
            throw new EncryptionEngineException("Failed initialising " + macName, e);
        }
        _out = new byte[_mac.getMacLength()];
        if (_out.length != md.getDigestLength())
            throw new EncryptionEngineException(macName + " returns " + _out.length
                    + " bytes but " + md.getAlgorithm() + " digests are " + md.getDigestLength());
    }

    @Override
    public void calcHMAC(byte[] data, int dataOffset, int dataLen, byte[] out) throws DigestException, EncryptionEngineException
    {
        _mac.update(data, dataOffset, dataLen);
        try
        {
            // doFinal(buf, off) resets the Mac, so the key schedule survives into the next
            // iteration and the loop never re-keys.
            _mac.doFinal(_out, 0);
        }
        catch (ShortBufferException e)
        {
            throw new EncryptionEngineException("HMAC output buffer too small", e);
        }
        System.arraycopy(_out, 0, out, 0, _out.length);
    }

    @Override
    public void close()
    {
        java.util.Arrays.fill(_out, (byte) 0);
        super.close();
    }

    private final Mac _mac;
    private final byte[] _out;
}
