package com.sovworks.eds.crypto.kdf;

import java.security.DigestException;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.sovworks.eds.crypto.EncryptionEngineException;

/**
 * HMAC through javax.crypto.Mac. TEST-ONLY, and deliberately not on any production path.
 *
 * It shipped briefly as an optimisation on the PBKDF2 loop, on the reasoning that one native
 * call per iteration must beat the generic {@link HMAC}'s six MessageDigest calls. Measured,
 * both halves of that were false: Conscrypt allocates a fresh native HMAC_CTX inside every
 * doFinal() and nothing collects it (the Java wrapper is too small to provoke a GC), so a
 * 200000-iteration loop grows the process by 109 to 140 MB, and it is also about 23% SLOWER
 * than the path it was meant to replace. At VeraCrypt's 500000 iterations across a four-hash
 * sweep that reached 1.5 GB RSS and the app was killed by lmkd mid-unlock.
 *
 * It is kept, out of the shipped APK, as the positive control in HmacNativeMemoryTest: that
 * test asserts the production path does not grow the native heap, and an assertion like that
 * is worthless without something in the same run that does grow it. It is also still the
 * byte-for-byte oracle KdfTest compares the generic HMAC against.
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
