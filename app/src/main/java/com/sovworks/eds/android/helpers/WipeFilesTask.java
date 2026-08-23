package com.sovworks.eds.android.helpers;

import java.io.IOException;
import java.security.SecureRandom;

import com.sovworks.eds.fs.File;
import com.sovworks.eds.fs.RandomAccessIO;
import com.sovworks.eds.fs.Path;
import com.sovworks.eds.fs.util.SrcDstCollection;
import com.sovworks.eds.fs.util.SrcDstCollection.SrcDst;

public class WipeFilesTask
{
	public interface ITask
	{
		boolean cancel();
		void progress(int sizeInc);
	}
	
	static public void wipeFileRnd(File file) throws IOException
    {
		wipeFileRnd(file, null);
    }
	
	/**
	 * Two defects fixed here, and neither was visible from the call site.
	 *
	 * java.util.Random seeded from the clock produced the "random" bytes that overwrote
	 * plaintext temp files. Its output is reconstructible from the seed, so the overwrite
	 * was a pattern, not noise. SecureRandom costs nothing measurable at 4 KiB a block.
	 *
	 * Worse, getOutputStream() TRUNCATES the file to zero and then writes the replacement
	 * bytes. On a filesystem free to place the new extent anywhere, the blocks holding the
	 * plaintext are released unwritten and the wipe overwrites somewhere else entirely.
	 * Opening ReadWrite instead keeps the file at its original length and writes over the
	 * bytes that are actually there.
	 *
	 * This is still best effort and is not a guarantee on flash: wear levelling can retire
	 * the original block rather than rewriting it, and no userspace overwrite can reach it.
	 * The real defence is that these files should never hold plaintext for long, not that
	 * this loop erases them.
	 */
	public static void wipeFileRnd(File file,ITask task) throws IOException
    {
    	try
    	{
    		overwriteFileRnd(file, task);
    	}
	    finally
	    {
	    	file.delete();
	    }
    }

	/**
	 * The overwrite half, without the delete. Split out because it is the half that can be
	 * checked: wipeFileRnd destroys its own evidence by design, so a test of it can only
	 * observe that the file is gone, which is equally true of a wipe that wrote nothing.
	 */
	public static void overwriteFileRnd(File file, ITask task) throws IOException
	{
		SecureRandom rg = new SecureRandom();
		byte[] buf = new byte[4*1024];
		long l = file.getSize();
		RandomAccessIO s = file.getRandomAccessIO(File.AccessMode.ReadWrite);
		try
		{
			for(long i=0;i<l;i+=buf.length)
			{
				if(task!=null && task.cancel())
					return;
				rg.nextBytes(buf);
				// Never write past the original length: a partial final block would
				// otherwise GROW the file and leave its tail untouched.
				int n = (int) Math.min(buf.length, l - i);
				s.write(buf, 0, n);
				updStatus(task, n);
			}
			s.flush();
		}
		finally
		{
			s.close();
		}
	}
	
	public static void wipeFilesRnd(ITask task, Object syncer,boolean wipe,SrcDstCollection... records) throws IOException
	{
		for (SrcDstCollection col: records)
		{
			if(col!=null)
			{
				for(SrcDst rec: col)
				{
					if(task!=null && task.cancel())
						return;		
					Path p = rec.getSrcLocation().getCurrentPath();
					if(p.isFile())
					{
						if(syncer!=null)
						{
							synchronized (syncer)
							{
								wipeFile(p.getFile(),wipe,task);								
							}							
						}
						else
							wipeFile(p.getFile(),wipe,task);							
					}
					else if(p.isDirectory())
						p.getDirectory().delete();
				}
			}
		}
	}
	
	public static void wipeFile(File file,boolean wipe,ITask task) throws IOException
    {
		if(wipe)
			wipeFileRnd(file,task);
		else
		{
			file.delete();
			updStatus(task, 0);
		}
	}
	
	public WipeFilesTask(boolean wipe)
	{
		_wipe = wipe;		
	}	
	
	
	
	protected static void updStatus(ITask task, long sizeInc)
	{
		if(task == null)
			return;
		task.progress((int)sizeInc);	
	}
	
	protected Object _syncer;
	protected final boolean _wipe;
	
	protected ITask getITask()
	{
		return new ITask()
		{			
			@Override
			public boolean cancel()
			{
				return false;
			}

			@Override
			public void progress(int sizeInc)
			{			
				
			}
		};
	}
	
	protected void doWork(SrcDstCollection... records) throws Exception
	{
		wipeFilesRnd(getITask(), _syncer, _wipe, records);
	}	
}
