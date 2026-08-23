package com.sovworks.eds.locations;

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
    EdsContainer getEdsContainer() throws IOException;
    List<ContainerFormatInfo> getSupportedFormats();
}
