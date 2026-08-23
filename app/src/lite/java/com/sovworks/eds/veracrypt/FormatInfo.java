package com.sovworks.eds.veracrypt;

import com.sovworks.eds.container.VolumeLayout;


public class FormatInfo extends com.sovworks.eds.truecrypt.FormatInfo 
{

	public static final String FORMAT_NAME = "VeraCrypt";

	@Override
	public String getFormatName()
	{
		return FORMAT_NAME;
	}

	@Override
	public VolumeLayout getVolumeLayout()
	{
		return new com.sovworks.eds.veracrypt.VolumeLayout();
	}

	@Override
	public int getOpeningPriority()
	{		
		return 3;
	}

	@Override
	public boolean hasCustomKDFIterationsSupport()
	{
		return true;
	}

	@Override
	public VolumeLayout getHiddenVolumeLayout()
	{
		return new HiddenVolumeLayout();
	}

	@Override
	public int getMaxPasswordLength()
	{
		// VeraCrypt's limit is 128 bytes; the inherited answer was TrueCrypt's 64. Inheriting
		// it capped VeraCrypt passphrases at half their allowed length, and a passphrase
		// silently truncated to 64 bytes derives a different key, so the container would not
		// open and nothing would say why.
		return 128;
	}

}
