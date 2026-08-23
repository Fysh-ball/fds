package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.sovworks.eds.container.HiddenVolumeProtectedException;
import com.sovworks.eds.container.HiddenVolumeProtectingIO;
import com.sovworks.eds.fs.RandomAccessIO;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.util.Arrays;

/**
 * The refusal logic on its own, with no container and no KDF, so it runs in milliseconds and
 * every boundary can be stated as a separate case.
 *
 * OuterVolumeProtectionTest is the end-to-end half and is where the claim "the hidden volume
 * survived" is actually measured against a real container. This class only proves the
 * arithmetic, which is the part with edges in it.
 */
@RunWith(AndroidJUnit4.class)
public class HiddenVolumeProtectionTest
{
    private static final long START = 1000;
    private static final long END = 2000;

    /**
     * An in-memory RandomAccessIO. Deliberately not a mock: the test needs to read the bytes
     * back and prove that a refused write left them alone, and a mock that records calls would
     * prove only that the wrapper called what it said it called.
     */
    private static class MemIO implements RandomAccessIO
    {
        MemIO(int size) { _buf = new byte[size]; }

        @Override public void close() { _closed = true; }
        @Override public void seek(long position) { _pos = position; }
        @Override public long getFilePointer() { return _pos; }
        @Override public long length() { return _buf.length; }
        @Override public void flush() { }

        @Override public int read()
        {
            if (_pos >= _buf.length) return -1;
            return _buf[(int) _pos++] & 0xff;
        }

        @Override public int read(byte[] b, int off, int len)
        {
            int n = (int) Math.min(len, _buf.length - _pos);
            if (n <= 0) return -1;
            System.arraycopy(_buf, (int) _pos, b, off, n);
            _pos += n;
            return n;
        }

        @Override public void write(int b) { _buf[(int) _pos++] = (byte) b; }

        @Override public void write(byte[] b, int off, int len)
        {
            System.arraycopy(b, off, _buf, (int) _pos, len);
            _pos += len;
        }

        @Override public void setLength(long newLength) { _buf = Arrays.copyOf(_buf, (int) newLength); }

        byte[] _buf;
        long _pos;
        boolean _closed;
    }

    private static HiddenVolumeProtectingIO wrap(MemIO m)
    {
        return new HiddenVolumeProtectingIO(m, START, END);
    }

    private static byte[] filled(int n, int v)
    {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) v);
        return b;
    }

    /** Every way a write can touch the hidden volume, each as its own case. */
    @Test
    public void everyWriteThatTouchesTheHiddenVolumeIsRefused() throws Exception
    {
        // {position, length, what it is}
        long[][] cases = {
                {START, 1, 0},          // first protected byte
                {END - 1, 1, 0},        // last protected byte
                {START + 10, 100, 0},   // wholly inside
                {START - 10, 100, 0},   // starts before, runs in: the outer FAT's normal case
                {END - 10, 100, 0},     // starts inside, runs out
                {0, 3000, 0},           // spans the whole thing
        };
        String[] names = {
                "the first protected byte", "the last protected byte", "wholly inside",
                "starting before and running in", "starting inside and running out",
                "spanning the entire hidden volume",
        };
        for (int i = 0; i < cases.length; i++)
        {
            MemIO m = new MemIO(3000);
            HiddenVolumeProtectingIO io = wrap(m);
            byte[] before = m._buf.clone();
            io.seek(cases[i][0]);
            try
            {
                io.write(filled((int) cases[i][1], 0xAB), 0, (int) cases[i][1]);
                fail("a write " + names[i] + " was allowed at " + cases[i][0]
                        + " for " + cases[i][1] + " bytes");
            }
            catch (HiddenVolumeProtectedException expected)
            {
                // correct
            }
            assertArrayEquals("a refused write (" + names[i] + ") still changed the volume",
                    before, m._buf);
            assertTrue("the refusal did not latch after " + names[i], io.isTripped());
        }
    }

    /**
     * The other half, and the one that would be missing if this were written only to make the
     * refusals pass. A wrapper that refuses EVERY write also passes the test above and makes
     * the outer volume useless.
     */
    @Test
    public void writesThatMissTheHiddenVolumeGoThrough() throws Exception
    {
        long[][] cases = {
                {0, 10},                // well before
                {START - 100, 100},     // ends exactly at the first protected byte
                {END, 100},             // starts exactly at the first byte past it
                {2500, 500},            // well after
        };
        for (long[] c : cases)
        {
            MemIO m = new MemIO(3000);
            HiddenVolumeProtectingIO io = wrap(m);
            io.seek(c[0]);
            io.write(filled((int) c[1], 0xCD), 0, (int) c[1]);
            assertFalse("a write at " + c[0] + " for " + c[1]
                    + " bytes tripped protection but does not touch [" + START + ", " + END + ")",
                    io.isTripped());
            for (long p = c[0]; p < c[0] + c[1]; p++)
                assertEquals("byte " + p + " was not written", (byte) 0xCD, m._buf[(int) p]);
        }
    }

    /** The single-byte write path is a separate method on the interface and a separate bug. */
    @Test
    public void theSingleByteWritePathIsGuardedToo() throws Exception
    {
        MemIO m = new MemIO(3000);
        HiddenVolumeProtectingIO io = wrap(m);
        io.seek(START);
        try
        {
            io.write(0xAB);
            fail("write(int) reached the hidden volume");
        }
        catch (HiddenVolumeProtectedException expected)
        {
            // correct
        }
        assertEquals("a refused single-byte write still landed", 0, m._buf[(int) START]);
    }

    /**
     * Latching is not decoration. Once a write has been refused mid-operation the filesystem's
     * metadata no longer agrees with its data, and letting the following writes through
     * produces a corrupt outer volume in addition to the refusal.
     */
    @Test
    public void theRefusalLatchesEvenForWritesThatWouldHaveBeenFine() throws Exception
    {
        MemIO m = new MemIO(3000);
        HiddenVolumeProtectingIO io = wrap(m);
        io.seek(START);
        try { io.write(filled(10, 0xAB), 0, 10); fail("not refused"); }
        catch (HiddenVolumeProtectedException expected) { }

        io.seek(0);
        try
        {
            io.write(filled(10, 0xCD), 0, 10);
            fail("a write at offset 0 was allowed after protection had already tripped");
        }
        catch (HiddenVolumeProtectedException expected)
        {
            // correct
        }
        assertEquals("the post-trip write landed anyway", 0, m._buf[0]);
    }

    /**
     * Truncation does not overwrite the hidden volume, it hands its blocks back to the
     * filesystem holding the container. The hidden volume is equally gone.
     */
    @Test
    public void truncatingBelowTheHiddenVolumeIsRefused() throws Exception
    {
        MemIO m = new MemIO(3000);
        HiddenVolumeProtectingIO io = wrap(m);
        try
        {
            io.setLength(END - 1);
            fail("the outer volume was truncated to " + (END - 1)
                    + ", releasing the hidden volume that ends at " + END);
        }
        catch (HiddenVolumeProtectedException expected)
        {
            // correct
        }
        assertEquals("the refused truncation still resized the volume", 3000, m._buf.length);

        // and the truncation that is safe still works
        io = wrap(m);
        io.setLength(END);
        assertEquals("a truncation to exactly the end of the hidden volume was refused",
                (int) END, m._buf.length);
    }

    /**
     * A range that protects nothing must not be constructible. Silently accepting one produces
     * an object that reports protection, refuses no write, and is indistinguishable from a
     * working one until the hidden volume is gone.
     */
    @Test
    public void aRangeThatProtectsNothingIsRejected()
    {
        long[][] bad = { {0, 0}, {500, 500}, {600, 500}, {-1, 100} };
        for (long[] b : bad)
        {
            try
            {
                new HiddenVolumeProtectingIO(new MemIO(3000), b[0], b[1]);
                fail("constructed a protector over the empty range [" + b[0] + ", " + b[1] + ")");
            }
            catch (IllegalArgumentException expected)
            {
                // correct
            }
        }
    }

    /** Reads are never refused, deliberately: refusing them would be a distinguisher. */
    @Test
    public void readsInsideTheHiddenVolumeAreNotRefused() throws Exception
    {
        MemIO m = new MemIO(3000);
        Arrays.fill(m._buf, (int) START, (int) END, (byte) 0x5A);
        HiddenVolumeProtectingIO io = wrap(m);
        io.seek(START);
        byte[] got = new byte[100];
        assertEquals("a read inside the hidden volume returned short", 100, io.read(got, 0, 100));
        assertArrayEquals("a read inside the hidden volume returned the wrong bytes",
                filled(100, 0x5A), got);
        assertFalse("a read tripped protection", io.isTripped());
    }
}
