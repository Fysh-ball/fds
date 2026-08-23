package com.sovworks.eds.android.dialogs;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import com.sovworks.eds.android.Logger;
import com.sovworks.eds.android.R;
import com.sovworks.eds.settings.GlobalConfig;

/**
 * Two buttons were removed here rather than repointed: "Make a donation" went to
 * sovworks.com and "Check the full version" to the paid EDS on Google Play. Upstream has
 * been dead since 2020-04-21 and this fork exists because those features were paywalled,
 * so both buttons sent the user somewhere that either takes their money for an
 * unmaintained app or takes it for nothing at all.
 */
public class AboutDialog extends AboutDialogBase
{
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
    {
        View v = super.onCreateView(inflater, container, savedInstanceState);
        if(v == null)
            return null;

        v.findViewById(R.id.check_source_code_button).setOnClickListener(new View.OnClickListener()
        {
            @Override
            public void onClick(View view)
            {
                openSourceCodePage();
            }
        });

        return v;
    }

    private void openSourceCodePage()
    {
        try
        {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(GlobalConfig.SOURCE_CODE_URL)));
        }
        catch (Exception e)
        {
            Logger.showAndLog(getActivity(), e);
        }
    }

}
