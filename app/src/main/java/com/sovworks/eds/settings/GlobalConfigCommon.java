package com.sovworks.eds.settings;


import com.sovworks.eds.android.BuildConfig;

class GlobalConfigCommon
{
	public static boolean isDebug()
	{
		return BuildConfig.DEBUG;
	}

    public static final int FB_PREVIEW_WIDTH = 40;
    public static final int FB_PREVIEW_HEIGHT = 40;
    public static final int CLEAR_MASTER_PASS_INACTIVITY_TIMEOUT = 20*60*1000;
    // eds@sovworks.com until now, which is upstream's address for an app they stopped
    // shipping in 2020. A support button that mails a dead vendor is worse than no button.
    public static final String SUPPORT_EMAIL = "Admin@fysh.site";
    public static final String HELP_URL = "https://sovworks.com/eds/managing-containers.php";
    public static final String EXFAT_MODULE_URL = "https://github.com/sovworks/edsexfat";
}
