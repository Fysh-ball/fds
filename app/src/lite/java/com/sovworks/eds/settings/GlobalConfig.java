package com.sovworks.eds.settings;


public final class GlobalConfig extends GlobalConfigCommon
{
    public static boolean isTest()
    {
        return false;
    }
    // DONATIONS_URL and FULL_VERSION_URL are gone with the buttons that used them: both
    // pointed at sovworks, whose last release was 2020-04-21 and whose paid version is
    // the reason this fork exists. UPSTREAM_SOURCE_URL stays because GPL attribution
    // needs somewhere to point, and it is shown as provenance, not as this app's home.
    public static final String SOURCE_CODE_URL = "https://github.com/Fysh-ball/fds";
    public static final String UPSTREAM_SOURCE_URL = "https://github.com/sovworks/edslite";
}
