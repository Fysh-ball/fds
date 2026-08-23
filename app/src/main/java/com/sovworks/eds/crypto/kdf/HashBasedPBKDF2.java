package com.sovworks.eds.crypto.kdf;

import android.annotation.SuppressLint;

import java.security.MessageDigest;


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

	/**
	 * Always the MessageDigest-based HMAC, and the javax.crypto.Mac shortcut that used to be
	 * tried first is gone. It was wrong on both counts it was added for.
	 *
	 * Conscrypt's Mac allocates a fresh native HMAC_CTX inside every doFinal(), and PBKDF2
	 * calls doFinal once per iteration. The Java wrapper around that context is a few dozen
	 * bytes, so nothing provokes a GC while the native heap fills: measured on the emulator
	 * at 200000 iterations, the Mac path grew the process by 109 to 140 MB on every one of
	 * three rounds while this path grew by 4 MB and then went NEGATIVE as the collector
	 * caught up. VeraCrypt asks for 500000 iterations and an unhinted open sweeps four
	 * hashes, so that is roughly a gigabyte of native heap per unlock attempt. It is what
	 * the low-memory killer was killing: 1.5 GB RSS against a 108 MB Dalvik heap, the whole
	 * balance in [anon:scudo:primary].
	 *
	 * It was not even faster. Same three rounds, same iterations: 9169/7338/6112 ms here
	 * against 11301/9452/8629 ms through Mac, about 23% slower including the round whose
	 * order was swapped to rule out warm-up. Six JCA crossings per iteration cost less than
	 * one context allocation.
	 *
	 * HmacNativeMemoryTest measures both and keeps the Mac arm as a positive control, so
	 * this comment stays checkable rather than becoming folklore.
	 */
	@Override
	protected HMAC initHMAC(byte[] password)
	{
		_md.reset();
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
