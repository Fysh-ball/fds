package com.sovworks.eds.truecrypt;

import com.sovworks.eds.container.ContainerFormatInfo;
import com.sovworks.eds.container.VolumeLayout;
import com.sovworks.eds.crypto.EncryptedFileWithCache;
import com.sovworks.eds.exceptions.ApplicationException;
import com.sovworks.eds.fs.FileSystemInfo;
import com.sovworks.eds.fs.RandomAccessIO;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;


public class FormatInfo implements ContainerFormatInfo
{
	public static final String FORMAT_NAME = "TrueCrypt";

	@Override
	public String getFormatName()
	{
		return FORMAT_NAME;
	}

	@Override
	public VolumeLayout getVolumeLayout()
	{
		return new StdLayout();
	}

	@Override
	public boolean hasHiddenContainerSupport()
	{
		// Unpaywalled. EdsContainerBase.tryLayout consults this before it will even try the
		// hidden header, and nothing on the container CREATION path reads it, so turning it on
		// widens what can be opened and cannot produce a malformed container. The cost is that
		// a failed unlock now also scans the hidden header slot, which is what VeraCrypt itself
		// does and is the reason a hidden volume is deniable in the first place.
		return true;
	}
	
	@Override
	public boolean hasKeyfilesSupport()
	{
		// For OPENING. The unlock dialog offers a keyfile picker when this is true, and
		// EdsContainerBase mixes the keyfiles into the passphrase for this format (and for
		// VeraCrypt, which inherits it). Nothing on the container CREATION path reads this:
		// creating a container with keyfiles is not implemented, and the create dialog does
		// not offer the picker.
		return true;
	}

	@Override
	public boolean hasCustomKDFIterationsSupport()
	{
		return false;
	}

	@Override
	public int getMaxPasswordLength()
	{
		// The TrueCrypt format's real limit, not a paywall. VeraCrypt raised it and overrides
		// this.
		return 64;
	}

	@Override
	public VolumeLayout getHiddenVolumeLayout()
	{
		return new HiddenLayout();
	}
	
	@Override
	public int getOpeningPriority()
	{		
		return 3;
	}

	@Override
	public void formatContainer(RandomAccessIO io, VolumeLayout layout, FileSystemInfo fsType) throws IOException, ApplicationException
	{
		StdLayout tcLayout = ((StdLayout)layout);
		io.seek(tcLayout.getEncryptedDataSize(io.length()) + tcLayout.getEncryptedDataOffset() - 1);
		io.write(0);
		prepareHeaderLocations(getRandom(), io, tcLayout);
		tcLayout.writeHeader(io);
		RandomAccessIO et = getEncryptedRandomAccessIO(io,tcLayout);
		tcLayout.formatFS(et, fsType);
		et.close();
	}
	
	@Override
	public String toString()
	{
		return getFormatName();
	}

	protected Random getRandom()
	{
		return new SecureRandom();
	}

    protected RandomAccessIO getEncryptedRandomAccessIO(RandomAccessIO base, VolumeLayout layout) throws IOException
    {
        return new EncryptedFileWithCache(base, layout)
        {
            @Override
            public void close() throws IOException
            {
                close(false);
            }
        };
    }
	
	protected void prepareHeaderLocations(Random sr, RandomAccessIO io, StdLayout layout) throws IOException
	{
		writeRandomData(sr, io, layout.getHeaderOffset(), getReservedHeadersSpace(layout));
	}
	
	protected void writeRandomData(Random sr, RandomAccessIO io, long start, long length) throws IOException
	{
		io.seek(start);
		byte[] tbuf = new byte[8*512];
		for(int i=0;i<length;i+=tbuf.length)
		{
			sr.nextBytes(tbuf);
			io.write(tbuf,0,tbuf.length);
		}
	}
	
	protected int getReservedHeadersSpace(StdLayout layout)
	{
		return 2*layout.getHeaderSize();
	}
}
