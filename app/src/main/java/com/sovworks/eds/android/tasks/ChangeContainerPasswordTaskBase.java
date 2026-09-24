package com.sovworks.eds.android.tasks;

import android.os.Bundle;

import com.sovworks.eds.android.helpers.Util;
import com.sovworks.eds.container.ContainerFormatInfo;
import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.container.EdsContainerBase;
import com.sovworks.eds.container.VolumeLayout;
import com.sovworks.eds.crypto.SecureBuffer;
import com.sovworks.eds.exceptions.ApplicationException;
import com.sovworks.eds.fs.File;
import com.sovworks.eds.fs.RandomAccessIO;
import com.sovworks.eds.locations.ContainerLocation;
import com.sovworks.eds.locations.LocationsManager;
import com.sovworks.eds.locations.Openable;

import java.io.IOException;

public abstract class ChangeContainerPasswordTaskBase extends ChangeEDSLocationPasswordTask
{
    public static final String TAG = "com.sovworks.eds.android.tasks.ChangeContainerPasswordTask";
    //public static final String ARG_FIN_ACTIVITY = "fin_activity";

	@Override
	protected void changeLocationPassword() throws IOException, ApplicationException
    {
        ContainerLocation cont = (ContainerLocation)_location;
        setContainerPassword(cont);
        RandomAccessIO io = cont.getLocation().getCurrentPath().getFile().getRandomAccessIO(File.AccessMode.ReadWrite);
        try
        {
            VolumeLayout vl = cont.getEdsContainer().getVolumeLayout();
            vl.writeHeader(io);
        }
        finally
        {
            io.close();
        }
	}

	protected void setContainerPassword(ContainerLocation container) throws IOException
    {
        EdsContainer cnt = container.getEdsContainer();
        VolumeLayout vl = cnt.getVolumeLayout();
        Bundle args  = getArguments();
        SecureBuffer sb = Util.getPassword(args, LocationsManager.getLocationsManager(_context));
        byte[] pass = sb.getDataArray();
        sb.close();
        // Cut to the format's limit, as creation and every open already do. Written uncut, a
        // new TrueCrypt passphrase over 64 bytes (or a VeraCrypt one over 128) produced a
        // header keyed with bytes the open path never supplies, and the container stopped
        // opening the moment the change was saved.
        ContainerFormatInfo cfi = cnt.getContainerFormat();
        try
        {
            // cutPassword always returns a copy (or null for null), and a limit of 0 means none.
            vl.setPassword(EdsContainerBase.cutPassword(pass,
                    cfi == null ? 0 : cfi.getMaxPasswordLength()));
        }
        finally
        {
            SecureBuffer.eraseData(pass);
        }
        if(args.containsKey(Openable.PARAM_KDF_ITERATIONS))
            vl.setNumKDFIterations(args.getInt(Openable.PARAM_KDF_ITERATIONS));
    }
}
