package com.sovworks.eds.android.dialogs;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import com.sovworks.eds.android.R;
import com.sovworks.eds.android.helpers.Util;
import com.sovworks.eds.android.locations.ContainerBasedLocation;
import com.sovworks.eds.android.settings.activities.OpeningOptionsActivity;
import com.sovworks.eds.android.views.EditSB;
import com.sovworks.eds.container.ContainerFormatInfo;
import com.sovworks.eds.crypto.SecureBuffer;
import com.sovworks.eds.locations.ContainerLocation;
import com.sovworks.eds.locations.LocationsManager;
import com.sovworks.eds.locations.Openable;
import com.trello.rxlifecycle3.components.RxDialogFragment;

import java.util.ArrayList;
import java.util.List;

import static android.view.ViewGroup.LayoutParams.WRAP_CONTENT;

public abstract class PasswordDialogBase extends RxDialogFragment
{
    public static final String TAG = "com.sovworks.eds.android.dialogs.PasswordDialog";

    public static final String ARG_LABEL = "com.sovworks.eds.android.LABEL";
    public static final String ARG_VERIFY_PASSWORD = "com.sovworks.eds.android.VERIFY_PASSWORD";
    public static final String ARG_HAS_PASSWORD = "com.sovworks.eds.android.HAS_PASSWORD";
    public static final String ARG_RECEIVER_FRAGMENT_TAG = "com.sovworks.eds.android.RECEIVER_FRAGMENT_TAG";

    public interface PasswordReceiver
    {
        void onPasswordEntered(PasswordDialog dlg);
        void onPasswordNotEntered(PasswordDialog dlg);
    }

    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        Util.setDialogStyle(this);
        _location = (Openable) LocationsManager.
                getLocationsManager(getActivity()).
                getFromBundle(getArguments(), null);
        _options = savedInstanceState == null ? getArguments() : savedInstanceState;
        if(savedInstanceState != null)
        {
            ArrayList<Uri> kf = savedInstanceState.getParcelableArrayList(STATE_KEYFILES);
            if(kf != null)
                _keyfiles.addAll(kf);
            // Out of _options, which is handed on as the open request's options and has no
            // business carrying the dialog's own state.
            _options.remove(STATE_KEYFILES);
        }
    }

    @Override
    public View onCreateView (LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
    {
        View v = inflater.inflate(R.layout.password_dialog, container);
        _labelTextView = v.findViewById(R.id.label);
        if (_labelTextView != null)
        {
            String label = loadLabel();
            if (label != null)
            {
                _labelTextView.setText(label);
                _labelTextView.setVisibility(View.VISIBLE);
            } else
                _labelTextView.setVisibility(View.GONE);
        }
        _passwordEditText = v.findViewById(R.id.password_et);
        _repeatPasswordEditText = v.findViewById(R.id.repeat_password_et);

        if(_passwordEditText != null)
        {
            if (hasPassword())
            {
                _passwordResult = SecureBuffer.reserveChars(50);
                _passwordEditText.setVisibility(View.VISIBLE);
                _passwordEditText.setSecureBuffer(_passwordResult);
            }
            else
            {
                _passwordResult = null;
                _passwordEditText.setVisibility(View.GONE);
            }
        }
        else
            _passwordResult = null;

        if (_repeatPasswordEditText != null)
        {
            if(hasPassword() && isPasswordVerificationRequired())
            {
                _repeatPasswordSB = SecureBuffer.reserveChars(50);
                _repeatPasswordEditText.setVisibility(View.VISIBLE);
                _repeatPasswordEditText.setSecureBuffer(_repeatPasswordSB);
            }
            else
            {
                _repeatPasswordSB = null;
                _repeatPasswordEditText.setVisibility(View.GONE);
            }
        }
        else
            _repeatPasswordSB = null;

        _protectionPasswordEditText = v.findViewById(R.id.protection_password_et);
        if(_protectionPasswordEditText != null && hasHiddenVolumeProtection())
        {
            _protectionPasswordSB = SecureBuffer.reserveChars(50);
            _protectionPasswordEditText.setVisibility(View.VISIBLE);
            _protectionPasswordEditText.setSecureBuffer(_protectionPasswordSB);
        }
        else
        {
            _protectionPasswordSB = null;
            if(_protectionPasswordEditText != null)
                _protectionPasswordEditText.setVisibility(View.GONE);
        }

        _keyfilesButton = v.findViewById(R.id.keyfiles_button);
        _keyfilesClearButton = v.findViewById(R.id.keyfiles_clear);
        _keyfilesTextView = v.findViewById(R.id.keyfiles_list);
        View keyfilesLayout = v.findViewById(R.id.keyfiles_layout);
        if(keyfilesLayout != null)
            keyfilesLayout.setVisibility(hasKeyfiles() ? View.VISIBLE : View.GONE);
        if(_keyfilesButton != null)
            _keyfilesButton.setOnClickListener(view -> pickKeyfiles());
        if(_keyfilesClearButton != null)
            _keyfilesClearButton.setOnClickListener(view -> {
                _keyfiles.clear();
                updateKeyfilesView();
            });
        updateKeyfilesView();

        View passwordLayout = v.findViewById(R.id.password_layout);
        if(passwordLayout!=null)
        {
            if(hasPassword())
            {
                passwordLayout.setVisibility(View.VISIBLE);
                _passwordEditText.requestFocus();
                /*lifecycle().
                        filter(event -> event == FragmentEvent.RESUME).
                        subscribe(event -> {
                            final InputMethodManager imm = (InputMethodManager) _passwordEditText.getContext().getSystemService(Context.INPUT_METHOD_SERVICE);
                            if(imm != null)
                                imm.showSoftInput(_passwordEditText, InputMethodManager.SHOW_FORCED);
                            //_passwordEditText.requestFocus();
                        });*/
            }
            else
                passwordLayout.setVisibility(hasPassword() ? View.VISIBLE : View.GONE);
        }

        Button b = v.findViewById(android.R.id.button1);
        if(b!=null)
            b.setOnClickListener(view -> confirm());

        ImageButton ib = v.findViewById(R.id.toggle_show_pass);
        if(ib!=null)
        {
            ib.setOnClickListener(v12 -> toggleShowPassword((ImageButton) v12));
        }

        ib = v.findViewById(R.id.settings);
        if(ib!=null)
        {
            if(_location == null)
                ib.setVisibility(View.GONE);
            ib.setOnClickListener(v1 -> openOptions());
        }
        return v;
    }



    @Override
    public void onDestroyView()
    {
        super.onDestroyView();
        if(_passwordResult != null)
        {
            _passwordResult.close();
            _passwordResult = null;
        }
        if(_repeatPasswordSB != null)
        {
            _repeatPasswordSB.close();
            _repeatPasswordSB = null;
        }
        if(_protectionPasswordSB != null)
        {
            _protectionPasswordSB.close();
            _protectionPasswordSB = null;
        }
    }

    @Override
    public void onResume()
    {
        super.onResume();
        setWidthHeight();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data)
    {
        switch(requestCode)
        {
            case REQUEST_OPTIONS:
                if (resultCode == Activity.RESULT_OK)
                    _options = data.getExtras();
                break;
            case REQUEST_KEYFILES:
                if (resultCode == Activity.RESULT_OK && data != null)
                    addKeyfiles(data);
                break;
            default:
                super.onActivityResult(requestCode, resultCode, data);
        }
    }

    public char[] getPassword()
    {
        if(hasPassword() && _passwordEditText!=null)
        {
            Editable pwd = _passwordEditText.getText();
            char[] res = new char[pwd.length()];
            pwd.getChars(0, res.length, res, 0);
            return res;
        }
        return null;
    }

    /**
     * The hidden volume's passphrase, or null if the field is not shown. An EMPTY array is
     * returned when the field is shown and left blank, and that is not the same thing: null
     * means "this dialog never offered protection", empty means "the user declined it this
     * time", and the second has to reach the location so a value from a previous attempt is
     * cleared rather than reused.
     */
    public char[] getProtectionPassword()
    {
        if(!hasHiddenVolumeProtection() || _protectionPasswordEditText == null)
            return null;
        Editable pwd = _protectionPasswordEditText.getText();
        char[] res = new char[pwd.length()];
        pwd.getChars(0, res.length, res, 0);
        return res;
    }

    /**
     * Offered only when opening an existing container.
     *
     * Not while creating one: isPasswordVerificationRequired() is the create path, and there
     * is nothing hidden inside a container that does not exist yet. Not for anything that is
     * not a container either, because nothing else can hold a second volume.
     */
    protected boolean hasHiddenVolumeProtection()
    {
        if(!hasPassword() || isPasswordVerificationRequired()
                || !(_location instanceof ContainerLocation))
            return false;
        // Hidden volumes are a property of the container FORMAT, and LUKS has none. Asking
        // for a second passphrase that cannot mean anything invites the user to type one and
        // then refuses the mount, which reads as the app being broken. This is not a secret
        // being leaked by the UI: which formats support hidden volumes is public.
        for(ContainerFormatInfo cfi: ((ContainerLocation) _location).getSupportedFormats())
            if(cfi != null && cfi.hasHiddenContainerSupport())
                return true;
        return false;
    }

    /**
     * The keyfiles picked in this dialog, or null if the dialog does not offer them. An EMPTY
     * list is not the same as null, for the same reason as getProtectionPassword(): it tells
     * the location to drop keyfiles left over from a previous attempt.
     */
    public List<Uri> getKeyfiles()
    {
        if(!hasKeyfiles())
            return null;
        return new ArrayList<>(_keyfiles);
    }

    /**
     * Offered only when opening an existing container of a format that has keyfiles.
     *
     * Not while creating one: this app cannot yet create a container with keyfiles, and a
     * picker on the create dialog would make one that silently ignored them. Not for LUKS,
     * whose keyfiles are a different mechanism this app does not implement.
     */
    protected boolean hasKeyfiles()
    {
        if(!hasPassword() || isPasswordVerificationRequired()
                || !(_location instanceof ContainerLocation))
            return false;
        for(ContainerFormatInfo cfi: ((ContainerLocation) _location).getSupportedFormats())
            if(cfi != null && cfi.hasKeyfilesSupport())
                return true;
        return false;
    }

    /**
     * The system picker rather than the app's own file browser. It needs no storage
     * permission, it reaches every provider (cloud, USB, another app's files), and it is the
     * access model scoped storage will require anyway.
     */
    protected void pickKeyfiles()
    {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        try
        {
            startActivityForResult(i, REQUEST_KEYFILES);
        }
        catch(ActivityNotFoundException e)
        {
            Toast.makeText(getActivity(), R.string.keyfiles_no_picker, Toast.LENGTH_LONG).show();
        }
    }

    /**
     * Adds to the list rather than replacing it, as VeraCrypt's own dialog does, so keyfiles
     * that live in different places can be collected in more than one trip to the picker.
     * Picking the same file twice keeps one copy: the format would count it twice, which is
     * never what anyone meant by selecting it again.
     */
    protected void addKeyfiles(Intent data)
    {
        ClipData clip = data.getClipData();
        if(clip != null)
        {
            for(int i = 0; i < clip.getItemCount(); i++)
                addKeyfile(clip.getItemAt(i).getUri());
        }
        else
            addKeyfile(data.getData());
        updateKeyfilesView();
    }

    private void addKeyfile(Uri uri)
    {
        if(uri != null && !_keyfiles.contains(uri))
            _keyfiles.add(uri);
    }

    protected void updateKeyfilesView()
    {
        boolean any = !_keyfiles.isEmpty();
        if(_keyfilesClearButton != null)
            _keyfilesClearButton.setVisibility(any ? View.VISIBLE : View.GONE);
        if(_keyfilesTextView != null)
        {
            if(any)
            {
                StringBuilder sb = new StringBuilder();
                for(Uri u: _keyfiles)
                {
                    if(sb.length() > 0)
                        sb.append('\n');
                    sb.append(ContainerBasedLocation.getKeyfileDisplayName(
                            _keyfilesTextView.getContext(), u));
                }
                _keyfilesTextView.setText(sb);
                _keyfilesTextView.setVisibility(View.VISIBLE);
            }
            else
            {
                _keyfilesTextView.setText(null);
                _keyfilesTextView.setVisibility(View.GONE);
            }
        }
    }

    @Override
    public void onSaveInstanceState(Bundle outState)
    {
        super.onSaveInstanceState(outState);
        if(_options!=null)
            outState.putAll(_options);
        // Only the URIs, which the picker's grant already covers. Kept across rotation so that
        // turning the phone does not silently drop half of the credential.
        outState.putParcelableArrayList(STATE_KEYFILES, new ArrayList<>(_keyfiles));
    }

    public boolean hasPassword()
    {
        Bundle args = getArguments();
        return args!=null && args.getBoolean(ARG_HAS_PASSWORD, _location!=null && _location.hasPassword());
    }

    public Bundle getOptions()
    {
        return _options;
    }

    protected static final int REQUEST_OPTIONS = 1;
    protected static final int REQUEST_KEYFILES = 2;
    private static final String STATE_KEYFILES = "com.sovworks.eds.android.dialogs.PasswordDialog.KEYFILES";
    protected TextView _labelTextView;
    protected EditSB _passwordEditText,_repeatPasswordEditText,_protectionPasswordEditText;
    protected Openable _location;
    protected Bundle _options;

    protected SecureBuffer _passwordResult, _repeatPasswordSB, _protectionPasswordSB;
    protected Button _keyfilesButton;
    protected ImageButton _keyfilesClearButton;
    protected TextView _keyfilesTextView;
    protected final ArrayList<Uri> _keyfiles = new ArrayList<>();

    protected void setWidthHeight()
    {
        Window w = getDialog().getWindow();
        if(w!=null)
            w.setLayout(calcWidth(), calcHeight());
    }

    protected int calcWidth()
    {
        return getResources().getDimensionPixelSize(R.dimen.password_dialog_width);
    }

    protected int calcHeight()
    {
        return WRAP_CONTENT;
        /*int height = getResources().getDimensionPixelSize(R.dimen.password_dialog_height);
        if(isPasswordVerificationRequired())
            height += 80;
        return height;*/
    }

    protected String loadLabel()
    {
        Bundle args = getArguments();
        return args != null ? args.getString(ARG_LABEL) : null;
    }

    protected boolean isPasswordVerificationRequired()
    {
        Bundle args = getArguments();
        return args!=null && args.getBoolean(ARG_VERIFY_PASSWORD, false);
    }

    /**
     * The protection field is toggled with the other two.
     *
     * It was left out when the field was added, and the result was a button that reveals one
     * passphrase and not the other, on a dialog where the two are typed one under the other.
     * That is not a cosmetic inconsistency: the reason to reveal a passphrase at all is to
     * check a long one for a typo, and a typo in the protection passphrase does not report
     * itself as a typo. It refuses the mount with the same message a container holding no
     * hidden volume gives, which is deliberate and is exactly why the user cannot tell the
     * two apart by trying again.
     */
    protected void toggleShowPassword(ImageButton b)
    {
        int inputType = _passwordEditText.getInputType();
        if ((inputType & EditorInfo.TYPE_MASK_VARIATION) == EditorInfo.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
        {
            setInputTypeOnAll(EditorInfo.TYPE_CLASS_TEXT | EditorInfo.TYPE_TEXT_VARIATION_PASSWORD);
            b.setImageResource(R.drawable.ic_show_pass);
        } else
        {
            setInputTypeOnAll(EditorInfo.TYPE_CLASS_TEXT | EditorInfo.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
            b.setImageResource(R.drawable.ic_hide_pass);
        }
    }

    private void setInputTypeOnAll(int inputType)
    {
        _passwordEditText.setInputType(inputType);
        if (_repeatPasswordEditText != null)
            _repeatPasswordEditText.setInputType(inputType);
        if (_protectionPasswordEditText != null)
            _protectionPasswordEditText.setInputType(inputType);
    }

    protected void openOptions()
    {
        Intent i = new Intent(getActivity(), OpeningOptionsActivity.class);
        if(_location!=null)
            LocationsManager.storePathsInIntent(i, _location, null);
        i.putExtras(_options);
        startActivityForResult(i, REQUEST_OPTIONS);
    }

    protected PasswordReceiver getResultReceiver()
    {
        Bundle args = getArguments();
        String recTag = args!=null ? args.getString(ARG_RECEIVER_FRAGMENT_TAG) : null;
        return recTag != null ? (PasswordReceiver) getFragmentManager().findFragmentByTag(recTag) : null;
    }

    protected boolean checkInput()
    {
        if(hasPassword() && isPasswordVerificationRequired())
        {
            if(!checkPasswordsMatch())
            {
                Toast.makeText(getActivity(), R.string.password_does_not_match, Toast.LENGTH_LONG).show();
                return false;
            }
        }
        return true;
    }

    protected void confirm()
    {
        if(!checkInput())
            return;

        onPasswordEntered();
        dismiss();
    }

    protected boolean checkPasswordsMatch()
    {
        return _passwordEditText.getText().equals(_repeatPasswordEditText.getText());
    }

    protected void onPasswordEntered()
    {
        PasswordReceiver r = getResultReceiver();
        if(r!=null)
            r.onPasswordEntered((PasswordDialog) this);
        else
        {
            Activity act = getActivity();
            if(act instanceof PasswordReceiver)
                ((PasswordReceiver)act).onPasswordEntered((PasswordDialog) this);
        }
    }

    @Override
    public void onCancel(DialogInterface dialog)
    {
        onPasswordNotEntered();
    }

    protected void onPasswordNotEntered()
    {
        PasswordReceiver r = getResultReceiver();
        if(r!=null)
            r.onPasswordNotEntered((PasswordDialog) this);
        else
        {
            Activity act = getActivity();
            if(act instanceof PasswordReceiver)
                ((PasswordReceiver)act).onPasswordNotEntered((PasswordDialog) this);
        }
    }
}
