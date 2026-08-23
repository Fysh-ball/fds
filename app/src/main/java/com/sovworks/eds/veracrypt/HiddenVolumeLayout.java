package com.sovworks.eds.veracrypt;

import com.sovworks.eds.truecrypt.StdLayout;

/**
 * The hidden volume of a VeraCrypt container: {@link VolumeLayout} pointed at the second
 * header slot.
 *
 * The same two overrides as truecrypt.HiddenLayout, duplicated rather than shared because
 * Java has single inheritance and this class has to inherit VeraCrypt's signature, iteration
 * counts and hash list. The arithmetic is one constant either way; factoring it into a helper
 * would hide it without removing the duplication.
 *
 * See truecrypt.HiddenLayout for why an absent hidden volume must stay indistinguishable from
 * a wrong passphrase, and for what creating one would additionally require.
 */
public class HiddenVolumeLayout extends VolumeLayout
{
    @Override
    protected long getHeaderOffset()
    {
        return StdLayout.HEADER_SIZE;
    }

    @Override
    protected long getBackupHeaderOffset()
    {
        return _inputSize - StdLayout.HEADER_SIZE;
    }
}
