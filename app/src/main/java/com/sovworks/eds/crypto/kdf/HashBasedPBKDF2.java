package com.sovworks.eds.crypto.kdf;

import android.annotation.SuppressLint;

import java.security.MessageDigest;

import com.sovworks.eds.android.Logger;
import com.sovworks.eds.crypto.EncryptionEngineException;

@SuppressLint("DefaultLocale")
public class HashBasedPBKDF2 extends PBKDF
{
	public HashBasedPBKDF2(MessageDigest md)
	{
		this(md, guessMDBlockSize(md));
	}
	
	public HashBasedPBKDF2(MessageDigest md, int blockSize)
	{
		_md = md;
		_blockSize = blockSize;
	}

	@Override
	protected HMAC initHMAC(byte[] password) throws EncryptionEngineException
	{
		_md.reset();
		String macName = MacHMAC.macNameFor(_md);
		if(macName != null && password.length > 0)
		{
			try
			{
				return new MacHMAC(password, _md, _blockSize, macName);
			}
			catch(EncryptionEngineException e)
			{
				// A missing or disagreeing provider must not make the container unopenable,
				// only slower, so fall back. It is logged because a silent fallback would
				// turn a 4-second unlock into a 25-second one with nothing to point at.
				Logger.log("MacHMAC unavailable for " + macName + ", using the generic HMAC: " + e.getMessage());
			}
		}
		return new HMAC(password, _md, _blockSize);
	}
	
	private final MessageDigest _md;
	private final int _blockSize;	
	
	@SuppressLint("DefaultLocale")
	private static int guessMDBlockSize(MessageDigest md)
	{
		String mdn = md.getAlgorithm().toLowerCase();
		if(mdn.equals("sha-512") || mdn.equals("sha512"))
			return 128;
		return 64;
		/*
		if(mdn.equals("md5") 
				|| mdn.equals("sha-0") 
				|| mdn.equals("sha-1") 
				|| mdn.equals("sha-224") 
				|| mdn.equals("sha-256")
				|| mdn.equals("whirlpool")
				|| mdn.equals("ripemd160"))
			return 64;*/
				
		
	}

}
