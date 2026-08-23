package com.sovworks.eds.container;


import com.sovworks.eds.android.Logger;
import com.sovworks.eds.android.R;
import com.sovworks.eds.android.errors.UserException;
import com.sovworks.eds.android.helpers.ContainerOpeningProgressReporter;
import com.sovworks.eds.crypto.EncryptedFileWithCache;
import com.sovworks.eds.crypto.EncryptionEngine;
import com.sovworks.eds.crypto.FileEncryptionEngine;
import com.sovworks.eds.crypto.LocalEncryptedFileXTS;
import com.sovworks.eds.crypto.modes.XTS;
import com.sovworks.eds.exceptions.ApplicationException;
import com.sovworks.eds.exceptions.WrongFileFormatException;
import com.sovworks.eds.fs.File.AccessMode;
import com.sovworks.eds.fs.FileSystem;
import com.sovworks.eds.fs.Path;
import com.sovworks.eds.fs.RandomAccessIO;
import com.sovworks.eds.fs.exfat.ExFat;
import com.sovworks.eds.fs.fat.FatFS;
import com.sovworks.eds.fs.std.StdFs;
import com.sovworks.eds.fs.std.StdFsPath;

import java.io.Closeable;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public abstract class EdsContainerBase implements Closeable
{

	public static ContainerFormatInfo findFormatByName(List<ContainerFormatInfo> supportedFormats, String name)
	{
		if(name != null)
			for(ContainerFormatInfo cfi: supportedFormats)
			{
				if(cfi.getFormatName().equalsIgnoreCase(name))
					return cfi;
			}
		return null;
	}

	public static byte[] cutPassword(byte[] pass, int maxLength)
	{
		if(pass!=null)
		{
			if (maxLength > 0 && pass.length > maxLength)
			{
				byte[] tmp = pass;
				pass = new byte[maxLength];
				System.arraycopy(tmp, 0, pass, 0, maxLength);
			}
			else
				pass = pass.clone();
		}
		return pass;
	}

	public static FileSystem loadFileSystem(RandomAccessIO io, boolean isReadOnly) throws IOException, UserException
	{
		if(ExFat.isExFATImage(io))
		{
			if(ExFat.isModuleInstalled())
				return new ExFat(io, isReadOnly);
			if(ExFat.isModuleIncompatible())
				throw new UserException("Please update the exFAT module.", R.string.update_exfat_module);
			throw new UserException("Please install the exFAT module", R.string.exfat_module_required);
		}

		FatFS fs = FatFS.getFat(io);
		if (isReadOnly)
			fs.setReadOnlyMode(true);
		return fs;
	}


	public EdsContainerBase(Path path, ContainerFormatInfo containerFormat, VolumeLayout layout)
	{			
		_pathToContainer = path;
		_layout = layout;
		_containerFormat = containerFormat;
	}
	
	public static final short COMPATIBLE_TC_VERSION = 0x700;
	
	public synchronized void open(byte[] password) throws IOException, ApplicationException
	{
		Logger.debug("Opening container at " + _pathToContainer.getPathString());
		_isHiddenVolumeOpened = false;
		RandomAccessIO t = openFile();
		try
		{
			if(_containerFormat == null)
			{
				if(tryLayout(t, password, false) || tryLayout(t, password, true))
					return;
			}
			else
			{
				if(tryLayout(_containerFormat, t, password, false) || tryLayout(_containerFormat, t, password, true))
					return;
			}
		}
		finally
		{
			t.close();
		}

		throw new WrongFileFormatException();
	}
	
	public FileSystem getEncryptedFS() throws IOException, UserException
	{
		return getEncryptedFS(false);
	}

	public RandomAccessIO initEncryptedFile(boolean isReadOnly) throws IOException
	{
		if(_layout == null)
			throw new IOException("The container is closed");
		EncryptionEngine enc = _layout.getEngine();
		return allowLocalXTS() ?
				new LocalEncryptedFileXTS(_pathToContainer.getPathString(), isReadOnly, _layout.getEncryptedDataOffset(), (XTS)enc)
				:
				new EncryptedFileWithCache(_pathToContainer,isReadOnly ? AccessMode.Read : AccessMode.ReadWrite,_layout);
	}

	public synchronized FileSystem getEncryptedFS(boolean isReadOnly) throws IOException, UserException
	{
		if(_fileSystem == null)
		{
			RandomAccessIO io = getEncryptedFile(isReadOnly);
			_fileSystem = loadFileSystem(io, isReadOnly);
		}
		return _fileSystem;
	}
		
	/**
	 * Closing the layout is what ZEROES the master key and the password, and it used to be
	 * the last of three unguarded statements: an IOException from the filesystem or from the
	 * container file skipped it and left the key resident for the life of the process. The
	 * key material is released first for that reason, and every step now runs even when an
	 * earlier one throws. The first exception is the one reported; a later one is attached
	 * to it rather than replacing it, so a failure to flush is never hidden by a failure to
	 * close.
	 */
	public synchronized void close() throws IOException
	{
		IOException first = null;
		try
		{
			if(_fileSystem!=null)
				_fileSystem.close(true);
		}
		catch(IOException e)
		{
			first = e;
		}
		finally
		{
			_fileSystem = null;
		}

		try
		{
			if(_encryptedFile!=null)
				_encryptedFile.close();
		}
		catch(IOException e)
		{
			if(first == null)
				first = e;
			else
				first.addSuppressed(e);
		}
		finally
		{
			_encryptedFile = null;
		}

		try
		{
			if(_layout!=null)
				_layout.close();
		}
		catch(IOException e)
		{
			if(first == null)
				first = e;
			else
				first.addSuppressed(e);
		}
		finally
		{
			_layout = null;
		}

		if(first != null)
			throw first;
	}
	
	public Path getPathToContainer()
	{
		return _pathToContainer;
	}
	
	public VolumeLayout getVolumeLayout()
	{
		return _layout;
	}
	
	/**
	 * Whether the volume that opened was the HIDDEN one.
	 *
	 * Exists so that callers which cache "this container is VeraCrypt with whirlpool" to skip
	 * the search next time can refuse to cache it for a hidden open. Caching it there would
	 * write down a fact that contradicts the outer volume: someone who is handed the outer
	 * passphrase under duress can mount the outer volume, read its real hash out of its own
	 * header, compare it with the cached hint, and learn that a hidden volume exists. That is
	 * the one thing the feature is for, so the flag is part of the open contract and not an
	 * afterthought in the caller.
	 *
	 * Meaningful only after a successful open; reset at the start of each one.
	 */
	public boolean isHiddenVolumeOpened()
	{
		return _isHiddenVolumeOpened;
	}

	public ContainerFormatInfo getContainerFormat()
	{
		return _containerFormat;
	}

	public void setContainerFormat(ContainerFormatInfo containerFormat)
	{
		_containerFormat = containerFormat;
	}

	public void setEncryptionEngineHint(FileEncryptionEngine eng)
	{
		_encryptionEngine = eng;
	}

	public void setHashFuncHint(MessageDigest hf)
	{
		_messageDigest = hf;
	}

	public void setNumKDFIterations(int num)
	{
		_numKDFIterations = num;
	}

	public void setProgressReporter(ContainerOpeningProgressReporter r)
	{
		_progressReporter = r;
	}

	public RandomAccessIO getEncryptedFile(boolean isReadOnly) throws IOException
	{
		if(_encryptedFile == null)
			_encryptedFile = initEncryptedFile(isReadOnly);
		return  _encryptedFile;
	}

	protected FileSystem _fileSystem;
	protected RandomAccessIO _encryptedFile;
	protected int _numKDFIterations;
	protected VolumeLayout _layout;
	protected ContainerFormatInfo _containerFormat;
	protected final Path _pathToContainer;
	protected ContainerOpeningProgressReporter _progressReporter;
	protected FileEncryptionEngine _encryptionEngine;

	protected MessageDigest _messageDigest;
	private boolean _isHiddenVolumeOpened;

	protected abstract List<ContainerFormatInfo> getFormats();

	protected RandomAccessIO openFile() throws IOException
	{
		return _pathToContainer.getFile().getRandomAccessIO(AccessMode.Read);
	}

	protected boolean tryLayout(RandomAccessIO containerFile, byte[] password, boolean isHidden) throws IOException, ApplicationException
	{
		List<ContainerFormatInfo> cfs = getFormats();
		if(cfs.size()>1)
			Collections.sort(cfs, new Comparator<ContainerFormatInfo>()
			{
				@Override
				public int compare(ContainerFormatInfo lhs, ContainerFormatInfo rhs)
				{
					return Integer.valueOf(lhs.getOpeningPriority()).compareTo(rhs.getOpeningPriority());
				}

			});
		
		for(ContainerFormatInfo cf: cfs)
		{
			//Don't try too slow container formats
			if(cf.getOpeningPriority() < 0)			
				continue;
			if(tryLayout(cf, containerFile, password, isHidden))
				return true;
		}
		return false;
	}
	
	protected boolean tryLayout(ContainerFormatInfo cf, RandomAccessIO containerFile, byte[] password, boolean isHidden) throws IOException, ApplicationException
	{
		if(isHidden && !cf.hasHiddenContainerSupport())
			return false;
		Logger.debug(String.format("Trying %s container format%s", cf.getFormatName(), isHidden ? " (hidden)" : ""));
		_isHiddenVolumeOpened = isHidden;
		if(_progressReporter!=null)
		{
			_progressReporter.setContainerFormatName(cf.getFormatName());
			_progressReporter.setIsHidden(isHidden);
		}
		VolumeLayout vl = isHidden ? cf.getHiddenVolumeLayout() : cf.getVolumeLayout();
		vl.setOpeningProgressReporter(_progressReporter);
		if(_encryptionEngine!=null)
			vl.setEngine(_encryptionEngine);
		if(_messageDigest!=null)
			vl.setHashFunc(_messageDigest);
		
		// From here on the layout holds a copy of the passphrase, so the only exit that may
		// skip vl.close() is the one that hands the layout to _layout. readHeader THROWS on
		// a wrong password for LUKS (luks/VolumeLayout rejects every wrong password with
		// WrongPasswordException rather than returning false), so an unguarded throw here
		// left one passphrase copy resident per format tried, per attempt.
		boolean adopted = false;
		try
		{
			vl.setPassword(cutPassword(password, cf.getMaxPasswordLength()));
			if(cf.hasCustomKDFIterationsSupport() && _numKDFIterations > 0)
				vl.setNumKDFIterations(_numKDFIterations);
			if(vl.readHeader(containerFile))
			{
				_containerFormat = cf;
				_layout = vl;
				adopted = true;
				return true;
			}
			else if(isHidden && (_encryptionEngine!=null || _messageDigest!=null))
			{
				vl.setEngine(null);
				vl.setHashFunc(null);
				if(vl.readHeader(containerFile))
				{
					_containerFormat = cf;
					_layout = vl;
					adopted = true;
					return true;
				}
			}
			return false;
		}
		finally
		{
			if(!adopted)
				vl.close();
		}
	}
	
	protected Iterable<VolumeLayout> getLayouts(boolean isHidden)
	{
		List<VolumeLayout> vll = new ArrayList<>();
		for(ContainerFormatInfo cf: getFormats())
		{
			VolumeLayout vl = isHidden ? cf.getHiddenVolumeLayout() : cf.getVolumeLayout();
			if(vl!=null)
				vll.add(vl);
		}
		return vll;
	}
	
	protected boolean allowLocalXTS()
	{
		return _pathToContainer instanceof StdFsPath
				&& _layout.getEngine() instanceof XTS 
				&& _pathToContainer.getFileSystem() instanceof StdFs
				&& ((StdFs)_pathToContainer.getFileSystem()).getRootDir().isEmpty();
	}

}



