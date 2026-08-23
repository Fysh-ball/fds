package com.sovworks.eds.container;

import com.sovworks.eds.exceptions.ApplicationException;

/**
 * Outer-volume protection was asked for and could not be set up, so the mount was refused.
 *
 * Refusing the mount is the whole point of this type existing. The alternative, mounting the
 * outer volume read-write with protection quietly off, produces a session that looks exactly
 * like a protected one right up to the moment the hidden volume is overwritten. There is no
 * safe way to report this as a warning, because the user cannot undo the write afterwards.
 */
public class HiddenVolumeProtectionFailedException extends ApplicationException
{
	public HiddenVolumeProtectionFailedException(String msg)
	{
		super(msg);
	}

	private static final long serialVersionUID = 1L;
}
