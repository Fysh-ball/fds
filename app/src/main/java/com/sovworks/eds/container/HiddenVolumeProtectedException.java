package com.sovworks.eds.container;

import java.io.IOException;

/**
 * A write to the outer volume was refused because it would have destroyed the hidden volume.
 *
 * An IOException rather than an ApplicationException because it has to travel out through
 * java.io write paths that the filesystem calls, and those declare IOException and nothing
 * else. It is a distinct type so a caller can tell "your write hit the hidden volume" from
 * "the SD card went away", which are the same class of failure to the FAT driver and very
 * different to the person holding the phone.
 */
public class HiddenVolumeProtectedException extends IOException
{
	public HiddenVolumeProtectedException(String msg)
	{
		super(msg);
	}

	private static final long serialVersionUID = 1L;
}
