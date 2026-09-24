package com.sovworks.eds.locations;

import android.net.Uri;

import com.sovworks.eds.container.ContainerFormatInfo;
import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.crypto.SecureBuffer;

import java.io.IOException;
import java.util.List;

public interface ContainerLocation extends EDSLocation
{
    interface ExternalSettings extends EDSLocation.ExternalSettings
    {
        void setContainerFormatName(String containerFormatName);
        void setEncEngineName(String encEngineName);
        void setHashFuncName(String hashFuncName);
        String getContainerFormatName();
        String getEncEngineName();
        String getHashFuncName();
    }
    @Override
    ExternalSettings getExternalSettings();

    /**
     * Switch on outer-volume protection for the next open, using the hidden volume's
     * passphrase. Null or empty means no protection.
     *
     * Only containers have this, so it is here and not on Openable: the second passphrase is
     * meaningless for a location that cannot contain a second volume.
     */
    void setHiddenVolumeProtectionPassword(SecureBuffer pass);

    /**
     * Keyfiles for the next open, as content URIs the user picked. Null or empty means none.
     *
     * Held for the open and forgotten on close, never saved with the location. Which file is
     * a container's keyfile is half of its credential, and writing that down would hand it to
     * whoever reads the app's settings.
     */
    void setKeyfiles(List<Uri> keyfiles);
    EdsContainer getEdsContainer() throws IOException;
    List<ContainerFormatInfo> getSupportedFormats();
}
