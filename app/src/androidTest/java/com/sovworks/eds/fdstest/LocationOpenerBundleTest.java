package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.net.Uri;
import android.os.Bundle;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.sovworks.eds.android.dialogs.PasswordDialog;
import com.sovworks.eds.android.locations.opener.fragments.LocationOpenerFragmentCommon;
import com.sovworks.eds.crypto.SecureBuffer;
import com.sovworks.eds.locations.Openable;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The two Bundle hops between the unlock dialog and the location.
 *
 * The protection passphrase makes five journeys: the user types it, the dialog reads it out,
 * the opener puts it in a result Bundle, the opener copies it onto the open request, and the
 * location hands it to the container. Every one of those is now measured except the middle
 * two, and they are the two where a dropped value produces no error at all: the open simply
 * proceeds with no protection, mounts read-write, and destroys the hidden volume on the first
 * write. Nothing distinguishes that from a successful open until the damage is done.
 *
 * No views, no activity, no container and no KDF. Both methods under test are pure Bundle
 * work, which is precisely why they are cheap to check and easy to get silently wrong.
 */
@RunWith(AndroidJUnit4.class)
public class LocationOpenerBundleTest
{
    /**
     * Exposes the two protected methods. Neither touches the activity, the view tree or the
     * fragment manager, so a detached instance runs the production code unchanged.
     */
    static class ProbeOpener extends LocationOpenerFragmentCommon
    {
        Bundle resultBundleFor(PasswordDialog pd)
        {
            return getPasswordDialogResultBundle(pd);
        }

        void applyTo(Bundle args, Bundle result)
        {
            updateOpenLocationTaskParams(args, result);
        }
    }

    /**
     * The dialog with its two inputs supplied directly. getPasswordDialogResultBundle asks it
     * for three things and nothing else: the options bundle, the passphrase and the protection
     * passphrase.
     */
    static class StubDialog extends PasswordDialog
    {
        StubDialog(char[] password, char[] protection)
        {
            this(password, protection, null);
        }

        StubDialog(char[] password, char[] protection, List<Uri> keyfiles)
        {
            _password = password;
            _protection = protection;
            _keyfileList = keyfiles;
            _options = new Bundle();
        }

        @Override
        public List<Uri> getKeyfiles()
        {
            return _keyfileList;
        }

        @Override
        public char[] getPassword()
        {
            return _password;
        }

        @Override
        public char[] getProtectionPassword()
        {
            return _protection;
        }

        private final char[] _password, _protection;
        private final List<Uri> _keyfileList;
    }

    @Test
    public void aProtectionPassphraseReachesTheResultBundle()
    {
        Bundle res = new ProbeOpener().resultBundleFor(
                new StubDialog("outer".toCharArray(), "hidden".toCharArray()));
        SecureBuffer sb = res.getParcelable(Openable.PARAM_PROTECTION_PASSWORD);
        assertNotNull("the protection passphrase never reached the result bundle", sb);
        assertArrayEquals("hidden".toCharArray(), chars(sb));
    }

    /**
     * The control. A dialog that never offered the field answers null, and null must leave the
     * key out entirely rather than putting an empty buffer in: an empty one means "stop
     * protecting", which is a different instruction from "protection was never on the table".
     */
    @Test
    public void aDialogThatNeverOfferedTheFieldPutsNothingInTheBundle()
    {
        Bundle res = new ProbeOpener().resultBundleFor(
                new StubDialog("outer".toCharArray(), null));
        assertFalse("a dialog with no protection field still wrote the key",
                res.containsKey(Openable.PARAM_PROTECTION_PASSWORD));
        assertTrue("the ordinary passphrase should still be there",
                res.containsKey(Openable.PARAM_PASSWORD));
    }

    @Test
    public void theProtectionPassphraseIsCopiedOntoTheOpenRequest()
    {
        Bundle res = new ProbeOpener().resultBundleFor(
                new StubDialog("outer".toCharArray(), "hidden".toCharArray()));
        Bundle args = new Bundle();
        new ProbeOpener().applyTo(args, res);
        SecureBuffer sb = args.getParcelable(Openable.PARAM_PROTECTION_PASSWORD);
        assertNotNull("the protection passphrase was dropped on the way to the open request",
                sb);
        assertArrayEquals("hidden".toCharArray(), chars(sb));
    }

    /**
     * The hinge, and the reason the ordinary passphrase and the protection passphrase are
     * copied by DIFFERENT rules a few lines apart.
     *
     * An empty protection passphrase has to overwrite whatever is already on the request. It
     * means the user cleared a field they had filled in on a previous attempt, and the request
     * bundle is reused across attempts, so skipping the copy would leave the earlier value in
     * place: the box would be empty on screen and the outer volume would still be protected
     * with the passphrase typed the time before. The ordinary passphrase does the opposite and
     * refuses to overwrite with an empty value, because a saved password already sitting in
     * the request is the thing being defended there.
     */
    @Test
    public void anEmptyProtectionPassphraseOverwritesAStaleOne()
    {
        Bundle args = new Bundle();
        args.putParcelable(Openable.PARAM_PROTECTION_PASSWORD,
                new SecureBuffer("stale-from-last-attempt".toCharArray()));

        Bundle res = new ProbeOpener().resultBundleFor(
                new StubDialog("outer".toCharArray(), new char[0]));
        new ProbeOpener().applyTo(args, res);

        SecureBuffer sb = args.getParcelable(Openable.PARAM_PROTECTION_PASSWORD);
        assertNotNull(sb);
        assertEquals("clearing the field left the previous protection passphrase in force",
                0, sb.length());
    }

    /**
     * The other half of that asymmetry, stated as a test so it cannot drift into agreeing with
     * the protection passphrase by accident. A blank passphrase field must NOT wipe a saved
     * password already on the request.
     */
    @Test
    public void anEmptyPasswordDoesNotOverwriteASavedOne()
    {
        Bundle args = new Bundle();
        args.putParcelable(Openable.PARAM_PASSWORD, new SecureBuffer("saved".toCharArray()));

        Bundle res = new ProbeOpener().resultBundleFor(
                new StubDialog(new char[0], null));
        new ProbeOpener().applyTo(args, res);

        SecureBuffer sb = args.getParcelable(Openable.PARAM_PASSWORD);
        assertNotNull(sb);
        assertArrayEquals("a blank field wiped the saved password",
                "saved".toCharArray(), chars(sb));
    }

    // ---- keyfiles take the same two hops -------------------------------------------

    private static final List<Uri> KEYFILES = Arrays.asList(
            Uri.parse("content://fdstest/kf1"), Uri.parse("content://fdstest/kf2"));

    /**
     * Keyfiles are half of the credential, and dropping them on either hop produces the
     * worst symptom there is: the passphrase alone is tried, the container refuses it, and
     * the user is told the passphrase is wrong when it is right.
     */
    @Test
    public void keyfilesReachTheOpenRequest()
    {
        Bundle res = new ProbeOpener().resultBundleFor(
                new StubDialog("pw".toCharArray(), null, KEYFILES));
        assertEquals("keyfiles never reached the result bundle",
                KEYFILES, res.getParcelableArrayList(Openable.PARAM_KEYFILES));
        Bundle args = new Bundle();
        new ProbeOpener().applyTo(args, res);
        assertEquals("keyfiles were dropped on the way to the open request",
                KEYFILES, args.getParcelableArrayList(Openable.PARAM_KEYFILES));
    }

    /** A dialog that never offered keyfiles (LUKS, or creating a container) writes nothing. */
    @Test
    public void aDialogThatNeverOfferedKeyfilesPutsNothingInTheBundle()
    {
        Bundle res = new ProbeOpener().resultBundleFor(
                new StubDialog("pw".toCharArray(), null, null));
        assertFalse(res.containsKey(Openable.PARAM_KEYFILES));
    }

    /**
     * The protection passphrase's rule, not the password's: an empty list is the user
     * removing keyfiles picked on an earlier attempt and must overwrite them.
     */
    @Test
    public void anEmptyKeyfileListOverwritesAStaleOne()
    {
        Bundle args = new Bundle();
        args.putParcelableArrayList(Openable.PARAM_KEYFILES, new ArrayList<>(KEYFILES));
        Bundle res = new ProbeOpener().resultBundleFor(
                new StubDialog("pw".toCharArray(), null, new ArrayList<Uri>()));
        new ProbeOpener().applyTo(args, res);
        List<Uri> kf = args.getParcelableArrayList(Openable.PARAM_KEYFILES);
        assertNotNull(kf);
        assertTrue("removing the keyfiles left the previous ones in force", kf.isEmpty());
    }

    /**
     * SecureBuffer is a CharSequence, not a char[] holder with an accessor, and reading it
     * through toString would put the value in a String that nothing can wipe. charAt keeps it
     * in the array the assertion already owns.
     */
    private static char[] chars(SecureBuffer sb)
    {
        char[] res = new char[sb.length()];
        for(int i = 0; i < res.length; i++)
            res[i] = sb.charAt(i);
        return res;
    }
}
