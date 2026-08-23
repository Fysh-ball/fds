package com.sovworks.eds.truecrypt;

/**
 * The hidden volume of a TrueCrypt container.
 *
 * A TrueCrypt or VeraCrypt file reserves four 64 KiB header slots
 * ({@link #RESERVED_HEADER_SIZE}): the outer header at 0, the hidden header at 64 KiB, and
 * the two backups at the end of the file in the same order. Nothing else differs. The header
 * carries the data area's own start offset at byte 108 and its length at byte 116, and
 * {@link StdLayout#decodeHeader} already reads both, so pointing the layout at the second
 * header slot is the entire difference between opening the outer volume and opening the
 * hidden one. The crypto path, the KDF, the CRC checks and the payload filesystem are shared.
 *
 * A wrong passphrase and an absent hidden volume are indistinguishable from here, by design:
 * the hidden header slot of a container with no hidden volume holds random bytes, which fail
 * the header CRC exactly as a wrong passphrase does. That is the property the whole feature
 * rests on, so it must not be "improved" into a distinguishable error.
 *
 * Opening only. Creating a hidden volume additionally requires knowing the outer volume's
 * free space so the hidden data area cannot overwrite outer files, and outer-volume
 * protection to keep writes to the outer volume from overwriting the hidden one. Neither is
 * implemented yet, and this class is deliberately not wired into any creation path.
 */
public class HiddenLayout extends StdLayout
{
    @Override
    protected long getHeaderOffset()
    {
        return HEADER_SIZE;
    }

    @Override
    protected long getBackupHeaderOffset()
    {
        return _inputSize - HEADER_SIZE;
    }
}
