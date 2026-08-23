package com.sovworks.eds.locations;

import com.sovworks.eds.android.helpers.ProgressReporter;
import com.sovworks.eds.crypto.SecureBuffer;

import java.io.IOException;

public interface Openable extends Location
{
	String PARAM_PASSWORD = "com.sovworks.eds.android.PASSWORD";
	String PARAM_KDF_ITERATIONS = "com.sovworks.eds.android.KDF_ITERATIONS";
	/**
	 * The HIDDEN volume's passphrase, supplied at mount time to switch on outer-volume
	 * protection for this mount only.
	 *
	 * Deliberately never persisted anywhere. A stored "this container has a hidden volume"
	 * flag is itself the proof that a hidden volume exists, readable by anyone who gets the
	 * app's settings, which is the same person the feature exists to defend against. It is
	 * asked for every time for that reason, and an empty answer means no protection.
	 */
	String PARAM_PROTECTION_PASSWORD = "com.sovworks.eds.android.PROTECTION_PASSWORD";

	void setPassword(SecureBuffer pass);
	boolean hasPassword();
	boolean requirePassword();
	boolean hasCustomKDFIterations();
	boolean requireCustomKDFIterations();
	void setNumKDFIterations(int num);
	void setOpenReadOnly(boolean readOnly);
	boolean isOpen();
	void open() throws Exception;	
	void close(boolean force) throws IOException;
	void setOpeningProgressReporter(ProgressReporter pr);
}
