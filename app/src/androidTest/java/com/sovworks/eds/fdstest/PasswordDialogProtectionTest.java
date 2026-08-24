package com.sovworks.eds.fdstest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.os.Bundle;
import android.view.ContextThemeWrapper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.inputmethod.EditorInfo;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.sovworks.eds.android.R;
import com.sovworks.eds.android.dialogs.PasswordDialog;
import com.sovworks.eds.android.dialogs.PasswordDialogBase;
import com.sovworks.eds.android.locations.ExternalStorageLocation;
import com.sovworks.eds.android.locations.LUKSLocation;
import com.sovworks.eds.android.locations.VeraCryptLocation;
import com.sovworks.eds.android.settings.UserSettings;
import com.sovworks.eds.android.views.EditSB;
import com.sovworks.eds.locations.Location;
import com.sovworks.eds.locations.Openable;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;

/**
 * The unlock dialog itself: does the protection field appear, for the right containers only,
 * and does what is typed into it come back out.
 *
 * This is the last link in the chain and the only one that was never measured.
 * HiddenVolumeProtectionTest covers the container, OuterVolumeProtectionTest covers it end to
 * end with a destructive control, ContainerLocationProtectionTest covers the location. All
 * three start from a protection passphrase already in hand. If the dialog never shows the
 * field, or shows it and hands back nothing, every one of them still passes and the app
 * silently mounts the outer volume unprotected: the exact failure the feature exists to
 * prevent, and one that looks identical to success from the outside.
 *
 * It is deliberately NOT an interactive UI test. Driving the real screen through the
 * accessibility tree needs the emulator to lay out, focus and accept input inside the
 * framework's own ANR windows, and on a host where system_server itself has ANR'd that
 * measures the host rather than the app. Calling onCreateView directly runs the same
 * production code that decides whether the field is shown, in process, with no dependence on
 * how loaded the machine is.
 *
 * No container file is read by any test here, and no KDF runs. hasHiddenVolumeProtection asks
 * the location for its supported FORMATS, and both VeraCryptLocation and LUKSLocation answer
 * that from a constant.
 */
@RunWith(AndroidJUnit4.class)
public class PasswordDialogProtectionTest
{
    /**
     * The real dialog, with the two things a detached fragment cannot supply for itself
     * handed to it directly.
     *
     * PasswordDialogBase.onCreate does exactly two things: it applies the dialog style, which
     * needs an Activity theme, and it recovers the location by round-tripping a URI through
     * the LocationsManager. Neither is part of the decision under test, and both are what
     * would otherwise force this class to launch an activity. onCreateView, which IS the
     * decision, is called unmodified.
     *
     * Injecting the location rather than resolving it also keeps a real fixture out of this
     * class: the URI round trip needs the container path to resolve, and nothing else here
     * touches a file.
     */
    static class ProbeDialog extends PasswordDialog
    {
        void injectLocation(Openable location)
        {
            _location = location;
        }
    }

    @BeforeClass
    public static void buildLocations() throws Exception
    {
        sCtx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        // A path, not a file. Nothing in this class opens it.
        File dir = sCtx.getCacheDir();
        Location file = new ExternalStorageLocation(
                sCtx, "fdstest", dir.getAbsolutePath(), "dialog_probe.hc");
        sVeraCrypt = new VeraCryptLocation(file, sCtx);
        sLuks = new LUKSLocation(file, null, sCtx, UserSettings.getSettings(sCtx));
        // The app's own theme, on the app's own context. The layout reads theme attributes
        // that only Theme.EDS defines, and a plain application context would resolve them to
        // nothing and inflate a view the app never inflates.
        sThemed = new ContextThemeWrapper(sCtx, R.style.Theme_EDS);
    }

    /**
     * The field has to survive resource resolution, which is not the same as existing in the
     * source tree. password_dialog.xml is provided per density bucket and nothing forces the
     * buckets to agree: a device resolving one that was missed would inflate a layout with no
     * protection field at all, and PasswordDialogBase handles that by quietly leaving the
     * buffer null. No crash, no log line, no protection.
     */
    @Test
    public void theLayoutThisDeviceResolvesCarriesTheProtectionField()
    {
        View v = inflate(sVeraCrypt, false);
        View f = v.findViewById(R.id.protection_password_et);
        assertNotNull(
                "password_dialog.xml resolved for this density has no protection_password_et",
                f);
        assertTrue(
                "protection_password_et is not an EditSB, so setSecureBuffer never ran and the "
                        + "passphrase would be held in an ordinary Editable",
                f instanceof EditSB);
    }

    @Test
    public void aVeraCryptContainerOffersProtection()
    {
        View v = inflate(sVeraCrypt, false);
        assertEquals("the ordinary passphrase field should be shown too",
                View.VISIBLE, v.findViewById(R.id.password_et).getVisibility());
        assertEquals(View.VISIBLE, v.findViewById(R.id.protection_password_et).getVisibility());
    }

    /**
     * The control that proves the test above is reading the FORMAT rather than always saying
     * yes. LUKS has no hidden volumes: FormatInfoBase.hasHiddenContainerSupport returns false,
     * so the loop in hasHiddenVolumeProtection finds nothing. Both locations are built over
     * the same underlying file, so the container format is the only thing that differs.
     */
    @Test
    public void aLuksContainerDoesNotOfferProtection()
    {
        View v = inflate(sLuks, false);
        assertEquals("LUKS has no hidden volumes, so the field must not be offered",
                View.GONE, v.findViewById(R.id.protection_password_et).getVisibility());
    }

    /**
     * The other control: creating a container is the one path where a second passphrase is
     * meaningless, because there is nothing hidden inside a container that does not exist yet.
     * Same location, same format, verification flag flipped.
     */
    @Test
    public void creatingAContainerDoesNotOfferProtection()
    {
        View v = inflate(sVeraCrypt, true);
        assertEquals(View.GONE, v.findViewById(R.id.protection_password_et).getVisibility());
    }

    @Test
    public void whatIsTypedIntoTheFieldIsWhatComesBackOut()
    {
        View v = inflate(sVeraCrypt, false);
        onUi(() -> ((EditSB) v.findViewById(R.id.protection_password_et)).setText("hidden-pass-1"));
        assertArrayEquals("hidden-pass-1".toCharArray(), sDialog.getProtectionPassword());
    }

    /**
     * Empty and absent are different answers, and the opener depends on the difference.
     * LocationOpenerFragmentCommon.updateOpenLocationTaskParams copies an EMPTY protection
     * passphrase onto the open request precisely so a value left over from a previous attempt
     * is cleared. If the dialog collapsed "shown but blank" to null, the key would vanish from
     * the bundle and the stale passphrase would still be in force: the user would have cleared
     * the box and still be protecting with the old one.
     */
    @Test
    public void aBlankFieldIsAnEmptyPassphraseNotAMissingOne()
    {
        inflate(sVeraCrypt, false);
        char[] prot = sDialog.getProtectionPassword();
        assertNotNull("a shown but blank field must not read as absent", prot);
        assertEquals(0, prot.length);
    }

    /**
     * And the converse: when the field was never offered the answer is null, not an empty
     * array, so nothing goes in the bundle and no location is told to stop protecting
     * something it was never protecting.
     */
    @Test
    public void aFieldThatWasNeverOfferedReadsAsAbsent()
    {
        inflate(sLuks, false);
        assertNull(sDialog.getProtectionPassword());
    }

    /**
     * The reveal button has to reveal BOTH passphrases.
     *
     * It did not when the field was first added, and the gap is not cosmetic. The reason to
     * reveal a passphrase is to check a long one for a typo, and a typo in the protection
     * passphrase does not announce itself: it refuses the mount with the same message a
     * container holding no hidden volume gives. That message is identical on purpose, which
     * is precisely why the user cannot distinguish a typo from an absent hidden volume by
     * trying again, and why the only way to check is to look at what was typed.
     *
     * Driven through performClick on the real button rather than by calling
     * toggleShowPassword, so the listener wired up in onCreateView is part of what is tested.
     */
    @Test
    public void revealingThePassphraseRevealsTheProtectionPassphraseToo()
    {
        View v = inflate(sVeraCrypt, false);
        View toggle = v.findViewById(R.id.toggle_show_pass);
        assertNotNull("no reveal button in the layout this device resolved", toggle);

        assertTrue(isMasked(v, R.id.password_et));
        assertTrue(isMasked(v, R.id.protection_password_et));

        onUi(toggle::performClick);
        assertFalse(isMasked(v, R.id.password_et));
        assertFalse("the reveal button left the protection passphrase masked",
                isMasked(v, R.id.protection_password_et));

        onUi(toggle::performClick);
        assertTrue("clicking again did not mask the protection passphrase",
                isMasked(v, R.id.protection_password_et));
        assertTrue(isMasked(v, R.id.password_et));
    }

    /**
     * Revealing a passphrase must not destroy it.
     *
     * setInputType is not an innocent call on these fields. They are backed by an
     * EditableSecureBuffer installed by setSecureBuffer, and EditSB.setText clears that buffer
     * before writing: any path inside TextView that reaches setText while changing the input
     * type would silently empty the box. The symptom would be a user pressing reveal to check
     * a long passphrase, seeing it vanish, and having no idea whether the app or their finger
     * did it. Reasoning about which TextView internals call setText is not evidence, so this
     * types into both fields, toggles twice, and reads them back.
     */
    @Test
    public void revealingThePassphraseDoesNotWipeIt()
    {
        View v = inflate(sVeraCrypt, false);
        onUi(() -> {
            ((EditSB) v.findViewById(R.id.password_et)).setText("outer-pass-1");
            ((EditSB) v.findViewById(R.id.protection_password_et)).setText("hidden-pass-1");
        });

        onUi(() -> v.findViewById(R.id.toggle_show_pass).performClick());
        assertArrayEquals("revealing wiped the passphrase",
                "outer-pass-1".toCharArray(), sDialog.getPassword());
        assertArrayEquals("revealing wiped the protection passphrase",
                "hidden-pass-1".toCharArray(), sDialog.getProtectionPassword());

        onUi(() -> v.findViewById(R.id.toggle_show_pass).performClick());
        assertArrayEquals("masking again wiped the passphrase",
                "outer-pass-1".toCharArray(), sDialog.getPassword());
        assertArrayEquals("masking again wiped the protection passphrase",
                "hidden-pass-1".toCharArray(), sDialog.getProtectionPassword());
    }

    private static boolean isMasked(View root, int id)
    {
        int t = ((EditSB) root.findViewById(id)).getInputType();
        return (t & EditorInfo.TYPE_MASK_VARIATION) != EditorInfo.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD;
    }

    private static Context sCtx;
    private static ContextThemeWrapper sThemed;
    private static Openable sVeraCrypt, sLuks;
    private static ProbeDialog sDialog;

    private View inflate(Openable location, boolean verifyPassword)
    {
        Bundle args = new Bundle();
        // ARG_HAS_PASSWORD is deliberately left unset, exactly as getAskPasswordArgs leaves
        // it, so hasPassword falls through to the location's own answer. Setting it here
        // would make the test agree with itself rather than with the app.
        args.putBoolean(PasswordDialogBase.ARG_VERIFY_PASSWORD, verifyPassword);
        sDialog = new ProbeDialog();
        sDialog.setArguments(args);
        sDialog.injectLocation(location);
        View[] holder = new View[1];
        onUi(() -> holder[0] = sDialog.onCreateView(
                LayoutInflater.from(sThemed), null, null));
        assertNotNull("onCreateView returned no view", holder[0]);
        return holder[0];
    }

    /**
     * Views are not thread safe and the instrumentation thread is not the main thread.
     * Inflating and typing off the main thread is the kind of race that passes a hundred times
     * and fails on a loaded machine, which is exactly the machine this runs on.
     */
    private void onUi(Runnable r)
    {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(r);
    }
}
