package com.sovworks.eds.android.locations;

import android.content.Context;
import android.net.Uri;

import com.sovworks.eds.android.Logger;
import com.sovworks.eds.android.errors.UserException;
import com.sovworks.eds.android.errors.WrongPasswordOrBadContainerException;
import com.sovworks.eds.android.helpers.ContainerOpeningProgressReporter;
import com.sovworks.eds.android.settings.UserSettings;
import com.sovworks.eds.container.ContainerFormatInfo;
import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.container.VolumeLayout;
import com.sovworks.eds.container.VolumeLayoutBase;
import com.sovworks.eds.crypto.FileEncryptionEngine;
import com.sovworks.eds.crypto.SecureBuffer;
import com.sovworks.eds.crypto.SimpleCrypto;
import com.sovworks.eds.exceptions.WrongFileFormatException;
import com.sovworks.eds.fs.FileSystem;
import com.sovworks.eds.locations.ContainerLocation;
import com.sovworks.eds.locations.Location;
import com.sovworks.eds.locations.LocationsManagerBase;
import com.sovworks.eds.settings.Settings;
import com.sovworks.eds.settings.SettingsCommon;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class ContainerBasedLocation extends EDSLocationBase implements ContainerLocation
{
	public static final String URI_SCHEME = "eds-container";

	public static String getLocationId(LocationsManagerBase lm, Uri locationUri) throws Exception
	{
		Location containerLocation = getContainerLocationFromUri(locationUri, lm);
		return getLocationId(containerLocation);
	}

	public static String getLocationId(Location containerLocation)
	{
		return SimpleCrypto.calcStringMD5(containerLocation.getLocationUri().toString());
	}

    public static class ExternalSettings extends EDSLocationBase.ExternalSettings implements ContainerLocation.ExternalSettings
    {
        public ExternalSettings()
        {

        }

		@Override
        public void setContainerFormatName(String containerFormatName)
        {
            _containerFormatName = containerFormatName;
        }

		@Override
        public void setEncEngineName(String encEngineName)
        {
            _encEngineName = encEngineName;
        }

		@Override
        public void setHashFuncName(String hashFuncName)
        {
            _hashFuncName = hashFuncName;
        }

		@Override
        public String getContainerFormatName()
        {
            return _containerFormatName;
        }

		@Override
        public String getEncEngineName()
        {
            return _encEngineName;
        }

		@Override
        public String getHashFuncName()
        {
            return _hashFuncName;
        }

		/**
		 * The format, cipher and hash that a previous successful open actually used.
		 *
		 * Deliberately three fields of their own rather than a reuse of the three above,
		 * even though they hold the same kind of value. The three above are an ASSERTION
		 * by the user, made in the container's settings screen; these are an INFERENCE
		 * made by the app. They need different handling on failure: an inference that
		 * stops matching the container is stale and gets thrown away and retried without
		 * (see open()), whereas silently discarding what the user typed would be the app
		 * overruling them. Folding both into one field would leave no way to tell which
		 * of the two a given value is, and the wrong recovery is available for each.
		 */
		public String getLearnedFormatName() { return _learnedFormatName; }
		public String getLearnedEncEngineName() { return _learnedEncEngineName; }
		public String getLearnedHashFuncName() { return _learnedHashFuncName; }

		public void setLearnedHints(String formatName, String encEngineName, String hashFuncName)
		{
			_learnedFormatName = formatName;
			_learnedEncEngineName = encEngineName;
			_learnedHashFuncName = hashFuncName;
		}

		public boolean hasLearnedHints()
		{
			return !isEmpty(_learnedFormatName) || !isEmpty(_learnedEncEngineName)
					|| !isEmpty(_learnedHashFuncName);
		}

		static boolean isEmpty(String s)
		{
			return s == null || s.isEmpty();
		}

		@Override
        public void saveToJSONObject(JSONObject jo) throws JSONException
        {
            super.saveToJSONObject(jo);
            jo.put(SETTINGS_CONTAINER_FORMAT, _containerFormatName);
            jo.put(SETTINGS_ENC_ENGINE, _encEngineName);
            jo.put(SETTINGS_HASH_FUNC, _hashFuncName);
            jo.put(SETTINGS_LEARNED_CONTAINER_FORMAT, _learnedFormatName);
            jo.put(SETTINGS_LEARNED_ENC_ENGINE, _learnedEncEngineName);
            jo.put(SETTINGS_LEARNED_HASH_FUNC, _learnedHashFuncName);
        }

        @Override
        public void loadFromJSONOjbect(JSONObject jo) throws JSONException
        {
            super.loadFromJSONOjbect(jo);
            _containerFormatName = jo.optString(SETTINGS_CONTAINER_FORMAT, null);
            _encEngineName = jo.optString(SETTINGS_ENC_ENGINE, null);
            _hashFuncName = jo.optString(SETTINGS_HASH_FUNC, null);
            _learnedFormatName = jo.optString(SETTINGS_LEARNED_CONTAINER_FORMAT, null);
            _learnedEncEngineName = jo.optString(SETTINGS_LEARNED_ENC_ENGINE, null);
            _learnedHashFuncName = jo.optString(SETTINGS_LEARNED_HASH_FUNC, null);
        }

        private static final String SETTINGS_CONTAINER_FORMAT = "container_format";
        private static final String SETTINGS_ENC_ENGINE = "encryption_engine";
        private static final String SETTINGS_HASH_FUNC = "hash_func";
        private static final String SETTINGS_LEARNED_CONTAINER_FORMAT = "learned_container_format";
        private static final String SETTINGS_LEARNED_ENC_ENGINE = "learned_encryption_engine";
        private static final String SETTINGS_LEARNED_HASH_FUNC = "learned_hash_func";

        private String _containerFormatName, _hashFuncName, _encEngineName;
        private String _learnedFormatName, _learnedHashFuncName, _learnedEncEngineName;
    }

    public ContainerBasedLocation(Uri uri, LocationsManagerBase lm, Context context, Settings settings) throws Exception
    {
        this(getContainerLocationFromUri(uri, lm), null, context, settings);
		loadFromUri(uri);
    }

	public ContainerBasedLocation(ContainerBasedLocation sibling)
	{
		super(sibling);
	}
	
	public ContainerBasedLocation(Location containerLocation, Context context) throws IOException
	{
		this(containerLocation, null, context, UserSettings.getSettings(context));
	}
	
	public ContainerBasedLocation(Location containerLocation, EdsContainer cont, Context context, Settings settings)
	{
		super(settings, new SharedData(
				getLocationId(containerLocation),
				createInternalSettings(),
				containerLocation,
				context
		));
		getSharedData().container = cont;
	}

	@Override
	public void loadFromUri(Uri uri)
	{
		super.loadFromUri(uri);
		_currentPathString = uri.getPath();
	}

	@Override
	public void open() throws Exception
	{
		if(isOpenOrMounted())
			return;
		boolean opened = false;
		try
		{
			attemptOpen();
			opened = true;
		}
		catch(WrongFileFormatException e)
		{
			// A hint the app inferred for itself must never be able to lock the user out of
			// their own container. It can go stale in one ordinary way: the file at this path
			// is replaced by a different container. The learned hash then makes readHeader
			// fail on the first try and nothing retries it, because the hint path in
			// EdsContainerBase.tryLayout falls back only for the hidden pass. So an inference
			// that stopped matching is discarded and the full search is run once, at the cost
			// of one slow open on the day the container changes.
			//
			// Only for inferred hints. A hint the USER set is left in force and the open is
			// allowed to fail, because the alternative is the app quietly deciding it knows
			// the container better than the person who typed the answer in.
			if(!getExternalSettings().hasLearnedHints())
			{
				getSharedData().container = null;
				throw new WrongPasswordOrBadContainerException(getContext());
			}
			Logger.debug("Learned format/hash hints did not open the container. Discarding them "
					+ "and retrying with the full search.");
			getExternalSettings().setLearnedHints(null, null, null);
			saveExternalSettings();
			try
			{
				// getContainerFormatInfo() is polymorphic (VeraCryptLocation and friends pin a
				// format) and the learned values were just cleared, so this second attempt
				// honours the subclass and the user and nothing else.
				attemptOpen();
			}
			catch(WrongFileFormatException e2)
			{
				getSharedData().container = null;
				throw new WrongPasswordOrBadContainerException(getContext());
			}
			opened = true;
		}
		finally
		{
			// close() erases the passphrase, and close() only runs on a container that
			// OPENED. A wrong passphrase therefore stayed in the location's SecureBuffer for
			// as long as the process lived, which is the one case where the app is holding a
			// secret it has already been told is useless. The caller re-prompts and calls
			// setPassword again, so nothing downstream needs it.
			// setPassword(null) is the accessor that closes the old buffer and drops it; the
			// field itself is package private to com.sovworks.eds.locations.
			if(!opened && getPassword() != null)
				setPassword(null);
		}
	}

	private void attemptOpen() throws Exception
	{
		EdsContainer cnt = getEdsContainer();
		cnt.setContainerFormat(null);
		cnt.setEncryptionEngineHint(null);
		cnt.setHashFuncHint(null);
		cnt.setNumKDFIterations(0);
		if(_openingProgressReporter!=null)
			cnt.setProgressReporter((ContainerOpeningProgressReporter) _openingProgressReporter);
		ContainerFormatInfo cfi = getContainerFormatInfo();
		if(cfi != null)
		{
			cnt.setContainerFormat(cfi);
			VolumeLayout vl = cfi.getVolumeLayout();
			String name = getExternalSettings().getEncEngineName();
			if(ExternalSettings.isEmpty(name))
				name = getExternalSettings().getLearnedEncEngineName();
			if(name != null && !name.isEmpty())
				cnt.setEncryptionEngineHint((FileEncryptionEngine) VolumeLayoutBase.findEncEngineByName(vl.getSupportedEncryptionEngines(), name));

			name = getExternalSettings().getHashFuncName();
			if(ExternalSettings.isEmpty(name))
				name = getExternalSettings().getLearnedHashFuncName();
			if(name != null && !name.isEmpty())
				cnt.setHashFuncHint(VolumeLayoutBase.findHashFunc(vl.getSupportedHashFuncs(), name));
		}

		int numKDFIterations = getSelectedKDFIterations();
		if(numKDFIterations > 0)
			cnt.setNumKDFIterations(numKDFIterations);

		byte[] pass = getFinalPassword();
		try
		{
			cnt.open(pass);
		}
		catch(Exception e)
		{
			getSharedData().container = null;
			throw e;
		}
		finally
		{
			if(pass!=null)
				Arrays.fill(pass, (byte) 0);
		}
		// Deliberately outside the try. The container IS open at this point, and a defect in
		// the bookkeeping below must not run the catch above and discard it.
		learnHintsFrom(cnt);
	}

	/**
	 * Write down which format, cipher and hash actually opened this container, so the next
	 * open and every rejected passphrase stop paying for the search. Measured on the x86_64
	 * emulator, a wrong passphrase against an unhinted VeraCrypt container costs about
	 * fifteen minutes: four hashes at 500000 iterations each against the normal header and
	 * the same again against the hidden one. With the hash known it is one derivation.
	 *
	 * NOT recorded when the volume that opened was the hidden one, and that is the whole
	 * reason this reads a flag out of the container instead of just reading the layout.
	 * Someone handed the outer passphrase under duress can mount the outer volume and read
	 * its real hash from its own header; if the stored hint named a different hash, the
	 * difference is proof that a second volume exists. A hidden open therefore leaves no
	 * trace and pays the full search next time, which is the correct trade.
	 */
	private void learnHintsFrom(EdsContainer cnt)
	{
		if(cnt.isHiddenVolumeOpened())
			return;
		ExternalSettings es = getExternalSettings();
		ContainerFormatInfo cfi = cnt.getContainerFormat();
		VolumeLayout vl = cnt.getVolumeLayout();
		if(cfi == null || vl == null)
			return;
		String format = cfi.getFormatName();
		String engine = vl.getEngine() == null ? null : VolumeLayoutBase.getEncEngineName(vl.getEngine());
		String hash = vl.getHashFunc() == null ? null : vl.getHashFunc().getAlgorithm();
		// Nothing worth writing down, and a hint set of all-empty would fail hasLearnedHints()
		// afterwards anyway, so the retry path would never fire for it.
		if(ExternalSettings.isEmpty(format) && ExternalSettings.isEmpty(engine)
				&& ExternalSettings.isEmpty(hash))
			return;
		// Only touch storage when the answer changed. open() is on the hot path of every
		// unlock and this would otherwise rewrite the settings file on every single one.
		if(equalOrBothEmpty(format, es.getLearnedFormatName())
				&& equalOrBothEmpty(engine, es.getLearnedEncEngineName())
				&& equalOrBothEmpty(hash, es.getLearnedHashFuncName()))
			return;
		es.setLearnedHints(format, engine, hash);
		try
		{
			saveExternalSettings();
		}
		catch(Throwable e)
		{
			// Not fatal: the container is open, and the only loss is that the next open pays
			// the search again. Swallowing the message would make that indistinguishable from
			// the hint never having been computed.
			Logger.log(e);
		}
	}

	private static boolean equalOrBothEmpty(String a, String b)
	{
		return ExternalSettings.isEmpty(a) ? ExternalSettings.isEmpty(b) : a.equals(b);
	}

	@Override
	public Uri getLocationUri()
	{
		return makeUri(URI_SCHEME).build();
	}

    @Override
    public ExternalSettings getExternalSettings()
    {
        return (ExternalSettings)super.getExternalSettings();
    }

	@Override
	public boolean hasCustomKDFIterations()
	{
		ContainerFormatInfo cfi = getContainerFormatInfo();
		return cfi == null || cfi.hasCustomKDFIterationsSupport();
	}

	@Override
	public void close(boolean force) throws IOException
	{
		com.sovworks.eds.android.Logger.debug("Closing container at " + getLocation().getLocationUri());
		super.close(force);
		if(isOpen())
		{
			try
			{
				getSharedData().container.close();
			}
			catch(Throwable e)
			{
				if(!force)
					throw new IOException(e);
				else
					Logger.log(e);
			}
			getSharedData().container = null;
		}
		com.sovworks.eds.android.Logger.debug("Container has been closed");
	}

	@Override
	public boolean isOpen()
	{
		return getSharedData().container!=null && getSharedData().container.getVolumeLayout()!=null;
	}

	@Override
	public ContainerBasedLocation copy()
	{
		return new ContainerBasedLocation(this);
	}

	@Override
	public synchronized EdsContainer getEdsContainer() throws IOException
	{
		EdsContainer cnt = getSharedData().container;
		if(cnt == null)
		{
			cnt = initEdsContainer();
			getSharedData().container = cnt;
		}
		return cnt;
	}

	@Override
	public List<ContainerFormatInfo> getSupportedFormats()
	{
		return EdsContainer.getSupportedFormats();
	}

	protected static class SharedData extends EDSLocationBase.SharedData
	{
		public SharedData(String id, EDSLocationBase.InternalSettings settings, Location location, Context context)
		{
			super(id, settings, location, context);
		}

		public EdsContainer container;
	}

	public static final int MAX_PASSWORD_LENGTH = 64;

	@Override
	protected SharedData getSharedData()
	{
		return (SharedData)super.getSharedData();
	}

	protected EdsContainer initEdsContainer() throws IOException
	{
		return new EdsContainer(getLocation().getCurrentPath());
	}

	protected ContainerFormatInfo getContainerFormatInfo()
	{
		ContainerFormatInfo cfi = getUserContainerFormatInfo();
		if(cfi != null)
			return cfi;
		String name = getExternalSettings().getLearnedFormatName();
		return ExternalSettings.isEmpty(name) ? null : EdsContainer.findFormatByName(name);
	}

	/**
	 * The format the user chose, ignoring anything the app inferred. Separate from
	 * getContainerFormatInfo() because subclasses override THAT to pin a single format
	 * and must keep doing so.
	 */
	private ContainerFormatInfo getUserContainerFormatInfo()
	{
		String name = getExternalSettings().getContainerFormatName();
		return ExternalSettings.isEmpty(name) ? null : EdsContainer.findFormatByName(name);
	}

	@Override
	protected byte[] getSelectedPassword()
	{
		byte[] pass = super.getSelectedPassword();
		if(pass!=null && pass.length>MAX_PASSWORD_LENGTH)
		{
			byte[] tmp = pass;
			pass = new byte[MAX_PASSWORD_LENGTH];
			System.arraycopy(tmp, 0, pass, 0, MAX_PASSWORD_LENGTH);
			SecureBuffer.eraseData(tmp);
		}
		return pass;
	}

    @Override
    protected ExternalSettings loadExternalSettings()
    {
        ExternalSettings res = new ExternalSettings();
		res.setProtectionKeyProvider(new ProtectionKeyProvider()
		{
			@Override
			public SecureBuffer getProtectionKey()
			{
				try
				{
					return UserSettings.getSettings(getContext()).getSettingsProtectionKey();
				}
				catch (SettingsCommon.InvalidSettingsPassword invalidSettingsPassword)
				{
					return null;
				}
			}
		});
        res.load(_globalSettings,getId());
        return res;
    }

	@Override
	protected FileSystem createBaseFS(boolean readOnly) throws IOException, UserException
	{
		return getSharedData().container.getEncryptedFS(readOnly);
	}
}
