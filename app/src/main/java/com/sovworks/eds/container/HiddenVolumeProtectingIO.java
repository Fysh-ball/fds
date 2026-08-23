package com.sovworks.eds.container;

import com.sovworks.eds.fs.RandomAccessIO;
import com.sovworks.eds.fs.util.RandomAccessIOWrapper;

import java.io.IOException;

/**
 * Refuses any write to the outer volume that would land on the hidden volume.
 *
 * Without this, mounting the outer volume of a container that has a hidden one and writing a
 * single file destroys the hidden volume, silently and unrecoverably. The outer filesystem has
 * no idea the hidden volume exists: that is the entire point of the design, and it is also why
 * nothing else in the stack can stop this. The hidden volume occupies free space as far as the
 * outer FAT is concerned, so the allocator will hand it out.
 *
 * That is not a corner case. It is what happens the first time a user does the thing the
 * feature exists for: opens the outer volume under coercion and lets someone add a file to it.
 *
 * Positions here are volume-relative, because this wraps the DECRYPTED view returned by
 * EdsContainerBase.initEncryptedFile, where offset 0 is the first byte of the outer data area.
 * The caller converts the hidden volume's absolute container offset into that frame once, at
 * construction, so nothing on the hot path does arithmetic.
 *
 * Reads are never refused. Reading the hidden volume's ciphertext through the outer volume
 * yields the random-looking bytes the outer FAT thinks are free space, which is exactly what an
 * adversary examining the mounted outer volume would see anyway. Refusing reads would be a
 * distinguisher: it would tell the outer filesystem that a region it believes is free behaves
 * differently from the rest, which is the one thing hidden volumes must never do.
 *
 * A refused write LATCHES: every subsequent write fails too, whether or not it intersects.
 * VeraCrypt does the same thing and the reason is not politeness. A filesystem that has had one
 * write refused mid-operation has already lost the invariant between its metadata and its data,
 * and letting the next writes through produces a corrupt outer volume on top of the refusal.
 * Failing everything from that point turns a corrupted filesystem into a mount that stopped.
 */
public class HiddenVolumeProtectingIO extends RandomAccessIOWrapper
{
	/**
	 * @param base            the decrypted outer volume
	 * @param protectedStart  first protected byte, outer-volume-relative
	 * @param protectedEnd    one past the last protected byte, outer-volume-relative
	 */
	public HiddenVolumeProtectingIO(RandomAccessIO base, long protectedStart, long protectedEnd)
	{
		super(base);
		if(protectedStart < 0 || protectedEnd <= protectedStart)
			throw new IllegalArgumentException(
					"empty or negative protected range [" + protectedStart + ", " + protectedEnd
					+ "), which would protect nothing while looking like protection");
		_protectedStart = protectedStart;
		_protectedEnd = protectedEnd;
	}

	@Override
	public void write(int b) throws IOException
	{
		checkRange(getFilePointer(), 1);
		super.write(b);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException
	{
		checkRange(getFilePointer(), len);
		super.write(b, off, len);
	}

	/**
	 * Truncation is guarded too. Shrinking the outer volume below the end of the hidden one
	 * does not overwrite the hidden data, but it hands the underlying file back to the
	 * filesystem, which is free to reuse those blocks for anything at all. The hidden volume
	 * is gone either way and there is no reason to distinguish the two.
	 */
	@Override
	public void setLength(long newLength) throws IOException
	{
		if(newLength < _protectedEnd)
		{
			trip();
			throw new HiddenVolumeProtectedException(
					"truncating the outer volume to " + newLength
					+ " would release the hidden volume, which ends at " + _protectedEnd);
		}
		super.setLength(newLength);
	}

	/** True once a write has been refused, at which point every later write is refused too. */
	public boolean isTripped()
	{
		return _tripped;
	}

	public long getProtectedStart()
	{
		return _protectedStart;
	}

	public long getProtectedEnd()
	{
		return _protectedEnd;
	}

	private void checkRange(long pos, int len) throws IOException
	{
		if(_tripped)
			throw new HiddenVolumeProtectedException(
					"the outer volume is read-only: a previous write was refused to protect "
					+ "the hidden volume, and continuing to write would corrupt this filesystem");
		if(len <= 0)
			return;
		// Intersection, not containment. A write that starts before the hidden volume and runs
		// into it is the common case: the outer FAT allocates forward and does not stop at a
		// boundary it cannot see.
		if(pos < _protectedEnd && pos + len > _protectedStart)
		{
			trip();
			throw new HiddenVolumeProtectedException(
					"refused a write of " + len + " bytes at " + pos
					+ ", which intersects the hidden volume at [" + _protectedStart + ", "
					+ _protectedEnd + "). The outer volume is now read-only.");
		}
	}

	private void trip()
	{
		_tripped = true;
	}

	private final long _protectedStart;
	private final long _protectedEnd;
	private volatile boolean _tripped;
}
