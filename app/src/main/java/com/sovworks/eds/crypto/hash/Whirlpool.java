package com.sovworks.eds.crypto.hash;

import java.security.DigestException;
import java.security.MessageDigest;

public class Whirlpool extends MessageDigest
{
	public Whirlpool()
	{
		super("whirlpool");
		_contextPtr = initContext();
		engineReset();
	}	
	
	public void close()
	{
		if(_contextPtr!=0)
		{
			freeContext(_contextPtr);
			_contextPtr = 0;
		}
	}
	
	@Override
	protected void finalize() throws Throwable 
	{
		close();		
	}
	
	@Override
	protected int engineGetDigestLength()
	{
		return DIGEST_LENGTH;
	}	

	@Override
	protected byte[] engineDigest()
	{
		byte[] res = new byte[DIGEST_LENGTH];
		finishDigest(_contextPtr, res);
		engineReset();
		return res;
	}

	/**
	 * Write the digest straight into the caller's buffer.
	 *
	 * MessageDigestSpi's default for this allocates a fresh array, copies out of it and drops
	 * it. PBKDF2 calls it twice per iteration and VeraCrypt asks for 655331 iterations of
	 * ripemd160, so the default costs about 1.3 million short-lived arrays for ONE unlock
	 * attempt: measured on the emulator as a background GC freeing 770006 objects and 21 MB
	 * in the middle of a single derivation. The native finishDigest already writes into an
	 * array it is handed, so there was never a reason to allocate one here.
	 *
	 * Only the exact-fit case is taken, because that is what finishDigest can honour: it
	 * writes 64 bytes starting at index 0 of whatever it is given. Anything else falls
	 * through to the default, which is correct and merely allocates. HMAC.calcHMAC passes a
	 * byte[getDigestLength()] at offset 0, so the hot path is the exact-fit one.
	 */
	@Override
	protected int engineDigest(byte[] buf, int offset, int len) throws DigestException
	{
		if(len < DIGEST_LENGTH)
			throw new DigestException("partial digests not returned");
		if(offset != 0 || buf.length != DIGEST_LENGTH)
			return super.engineDigest(buf, offset, len);
		finishDigest(_contextPtr, buf);
		engineReset();
		return DIGEST_LENGTH;
	}

	@Override
	protected void engineReset()
	{
		resetDigest(_contextPtr);
	}

	@Override
	protected void engineUpdate(byte input)
	{
		updateDigestByte(_contextPtr, input);		
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len)
	{
		updateDigest(_contextPtr, input, offset, len);		
	}
	
	static
	{
		System.loadLibrary("edswhirlpool");
	}
	
	private static final int DIGEST_LENGTH = 64;
	
	private long _contextPtr;
	
	private native long initContext();
	private native void freeContext(long contextPtr);
	private native void resetDigest(long contextPtr);
	private native void updateDigestByte(long contextPtr,byte data);
	private native void updateDigest(long contextPtr,byte[] data,int offset,int len);
	private native void finishDigest(long contextPtr,byte[] result);

	
	
	
}