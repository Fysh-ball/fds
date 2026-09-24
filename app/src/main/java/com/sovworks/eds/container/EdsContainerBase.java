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
import com.sovworks.eds.truecrypt.KeyfilePool;

import java.io.Closeable;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
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
		_protectedStart = _protectedEnd = -1;
		RandomAccessIO t = openFile();
		try
		{
			if(!tryOpenAnyLayout(t, password))
				throw new WrongFileFormatException();
			// Deliberately inside the try, while t is still open. Reading the hidden header
			// needs the raw container file, and the finally below closes it; doing this after
			// open() returned would mean opening the file a second time.
			initHiddenVolumeProtection(t);
		}
		finally
		{
			t.close();
		}
	}

	private boolean tryOpenAnyLayout(RandomAccessIO t, byte[] password) throws IOException, ApplicationException
	{
		if(_containerFormat == null)
			return tryLayout(t, password, false) || tryLayout(t, password, true);
		return tryLayout(_containerFormat, t, password, false)
				|| tryLayout(_containerFormat, t, password, true);
	}

	/**
	 * Outer-volume protection, which is VeraCrypt's name for it.
	 *
	 * Give this the HIDDEN volume's passphrase before open(). The outer volume then mounts
	 * read-write as normal; the hidden header is decrypted exactly once, purely to learn which
	 * bytes the hidden volume occupies, and its key is zeroed immediately afterwards. Writes
	 * that would land on those bytes are refused. The hidden volume is never mounted and its
	 * contents are never read.
	 *
	 * Without this, opening the outer volume of a container that has a hidden one and copying
	 * a single file into it destroys the hidden volume. The outer filesystem cannot see the
	 * hidden volume by construction, so it allocates straight through it.
	 *
	 * The array is not copied and not zeroed here. The caller owns it; open() consumes it and
	 * drops the reference as soon as the extent is known.
	 */
	public void setHiddenVolumeProtectionPassword(byte[] password)
	{
		_hiddenProtectionPassword = password;
	}

	/**
	 * Keyfiles for the next open, already folded into pools.
	 *
	 * Mixed into the passphrase per format, after that format's length cut, because the pool
	 * size depends on the cut length (see KeyfilePool). A format with no keyfile support is
	 * skipped outright while keyfiles are set: the keyfile is part of the credential, so a
	 * format that would ignore it cannot be the one the user means, and trying it anyway would
	 * cost a full LUKS KDF on every attempt for nothing.
	 *
	 * Not applied to the protection passphrase. VeraCrypt takes separate keyfiles for the
	 * hidden volume there (--protection-keyfiles), and a hidden volume that has keyfiles of its
	 * own therefore cannot be protected yet: readHiddenLayout finds nothing and the mount is
	 * refused, which is the safe failure.
	 *
	 * Not copied and not closed here. The caller owns it.
	 */
	public void setKeyfiles(KeyfilePool pool)
	{
		_keyfilePool = pool;
	}

	/** True only after open() actually established the protected range. */
	public boolean isHiddenVolumeProtectionEnabled()
	{
		return _protectedStart >= 0 && _protectedEnd > _protectedStart;
	}

	/**
	 * Every exit that is not "protection is now in force" throws. A protection passphrase that
	 * opens no hidden volume is the dangerous case: carrying on would mount the outer volume
	 * read-write with protection silently off, which looks identical to a protected mount right
	 * up until the hidden volume is gone.
	 */
	protected void initHiddenVolumeProtection(RandomAccessIO containerFile) throws IOException, ApplicationException
	{
		byte[] pass = _hiddenProtectionPassword;
		_hiddenProtectionPassword = null;
		if(pass == null)
			return;
		if(_isHiddenVolumeOpened)
			throw new HiddenVolumeProtectionFailedException(
					"the first passphrase opened the hidden volume, not the outer one, so "
					+ "there is no outer volume here to protect it from");
		if(_containerFormat == null || !_containerFormat.hasHiddenContainerSupport())
			throw new HiddenVolumeProtectionFailedException(
					"the container format " + (_containerFormat == null ? "(unknown)" : _containerFormat.getFormatName())
					+ " has no hidden volumes, so protection cannot be established");

		VolumeLayout hidden = readHiddenLayout(containerFile, pass);
		if(hidden == null)
			throw new HiddenVolumeProtectionFailedException(
					"no hidden volume opened with the protection passphrase. Either the "
					+ "passphrase is wrong or this container has no hidden volume: those two "
					+ "are indistinguishable by design and neither one is safe to write to.");
		try
		{
			long fileSize = containerFile.length();
			long outerStart = _layout.getEncryptedDataOffset();
			long outerSize = _layout.getEncryptedDataSize(fileSize);
			long hiddenStart = hidden.getEncryptedDataOffset();
			long hiddenSize = hidden.getEncryptedDataSize(fileSize);
			// A hidden volume that does not sit inside the outer data area means the two
			// headers disagree about the geometry of the same file. Refuse rather than clamp:
			// a clamped range protects the wrong bytes and still reports success.
			if(hiddenSize <= 0 || hiddenStart < outerStart
					|| hiddenStart - outerStart + hiddenSize > outerSize)
				throw new HiddenVolumeProtectionFailedException(
						"the hidden volume at [" + hiddenStart + ", " + (hiddenStart + hiddenSize)
						+ ") does not lie inside the outer data area [" + outerStart + ", "
						+ (outerStart + outerSize) + "), so the two headers disagree about this file");
			_protectedStart = hiddenStart - outerStart;
			_protectedEnd = _protectedStart + hiddenSize;
			Logger.debug("Hidden volume protection active over outer bytes ["
					+ _protectedStart + ", " + _protectedEnd + ")");
		}
		finally
		{
			// The extent was the only thing wanted. Closing zeroes the hidden master key and
			// the layout's copy of the hidden passphrase, so neither is resident for the life
			// of the mount.
			hidden.close();
		}
	}

	/**
	 * Reads the hidden header without touching _layout, _containerFormat or
	 * _isHiddenVolumeOpened, which is why this is not tryLayout(). Returns null when no hidden
	 * volume opens, and an absent hidden volume is not distinguishable from a wrong passphrase
	 * here any more than it is anywhere else.
	 *
	 * No engine or hash hint is applied. Those hints describe the OUTER volume, and a hidden
	 * volume is free to use a different cipher and a different hash: pinning them would make a
	 * legitimately different hidden volume look absent, which this code turns into a refused
	 * mount.
	 */
	protected VolumeLayout readHiddenLayout(RandomAccessIO containerFile, byte[] password) throws IOException, ApplicationException
	{
		VolumeLayout vl = _containerFormat.getHiddenVolumeLayout();
		if(vl == null)
			return null;
		boolean adopted = false;
		try
		{
			vl.setOpeningProgressReporter(_progressReporter);
			vl.setPassword(cutPassword(password, _containerFormat.getMaxPasswordLength()));
			if(_containerFormat.hasCustomKDFIterationsSupport() && _numKDFIterations > 0)
				vl.setNumKDFIterations(_numKDFIterations);
			if(vl.readHeader(containerFile))
			{
				adopted = true;
				return vl;
			}
			return null;
		}
		finally
		{
			if(!adopted)
				vl.close();
		}
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
		RandomAccessIO io = allowLocalXTS() ?
				new LocalEncryptedFileXTS(_pathToContainer.getPathString(), isReadOnly, _layout.getEncryptedDataOffset(), (XTS)enc)
				:
				new EncryptedFileWithCache(_pathToContainer,isReadOnly ? AccessMode.Read : AccessMode.ReadWrite,_layout);
		// The wrap goes here, around the DECRYPTED view, because this is the only object the
		// filesystem ever writes through. Both branches present offset 0 as the first byte of
		// the outer data area, which is the frame the protected range is expressed in.
		return isHiddenVolumeProtectionEnabled()
				? new HiddenVolumeProtectingIO(io, _protectedStart, _protectedEnd)
				: io;
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
	private byte[] _hiddenProtectionPassword;
	private KeyfilePool _keyfilePool;
	private long _protectedStart = -1;
	private long _protectedEnd = -1;

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
		if(_keyfilePool != null && !cf.hasKeyfilesSupport())
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
			vl.setPassword(formatPassword(cf, password));
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
	
	/**
	 * The passphrase as this format will see it: cut to the format's limit, then with the
	 * keyfiles mixed in. That order is the format's own. VeraCrypt applies keyfiles to the
	 * passphrase it accepted, never to bytes past its limit, and the pool size it picks is a
	 * function of that accepted length.
	 *
	 * Returns an array the layout takes ownership of and zeroes on close.
	 */
	private byte[] formatPassword(ContainerFormatInfo cf, byte[] password)
	{
		byte[] cut = cutPassword(password, cf.getMaxPasswordLength());
		if(_keyfilePool == null)
			return cut;
		try
		{
			return _keyfilePool.applyTo(cut);
		}
		finally
		{
			if(cut != null)
				Arrays.fill(cut, (byte) 0);
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



