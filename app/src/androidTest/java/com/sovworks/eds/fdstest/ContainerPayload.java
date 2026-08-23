package com.sovworks.eds.fdstest;

import com.sovworks.eds.container.EdsContainer;
import com.sovworks.eds.fs.Directory;
import com.sovworks.eds.fs.FileSystem;
import com.sovworks.eds.fs.Path;
import com.sovworks.eds.fs.std.StdFs;

import java.io.File;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Opens a container read-only and returns every file in it as relative path -> sha256.
 *
 * The whole engine reduced to one call: EdsContainer.open tries each registered format, then
 * each of its layouts, normal before hidden, and the first header whose CRC validates wins.
 * Nothing above this needs to know which of those succeeded, which is exactly what makes a
 * hidden volume indistinguishable from a normal one to everything downstream.
 */
final class ContainerPayload
{
    static Map<String, String> read(File container, byte[] password) throws Exception
    {
        EdsContainer c = new EdsContainer(StdFs.makePath(container.getAbsolutePath()));
        try
        {
            c.open(password);
            FileSystem fs = c.getEncryptedFS(true);
            Map<String, String> out = new LinkedHashMap<>();
            walk(fs.getRootPath(), out, 0);
            return out;
        }
        finally
        {
            closeQuietly(c);
        }
    }

    private static void walk(Path dir, Map<String, String> out, int depth) throws Exception
    {
        if (depth > 8)
            throw new IllegalStateException("directory nesting deeper than 8 at "
                    + dir.getPathString() + ": refusing to recurse further");
        try (Directory.Contents contents = dir.getDirectory().list())
        {
            for (Path child : contents)
            {
                String rel = child.getPathString();
                while (rel.startsWith("/"))
                    rel = rel.substring(1);
                String leaf = rel.contains("/") ? rel.substring(rel.lastIndexOf('/') + 1) : rel;
                if (".".equals(leaf) || "..".equals(leaf) || leaf.isEmpty())
                    continue;
                if (child.isDirectory())
                    walk(child, out, depth + 1);
                else
                {
                    try (InputStream in = child.getFile().getInputStream())
                    {
                        out.put(rel, FixtureSet.sha256(in));
                    }
                }
            }
        }
    }

    static void closeQuietly(EdsContainer c)
    {
        try
        {
            c.close();
        }
        catch (Throwable ignored)
        {
            // the container may never have opened; a close failure here must not mask the
            // assertion that brought us to the finally block
        }
    }

    private ContainerPayload() { }
}
