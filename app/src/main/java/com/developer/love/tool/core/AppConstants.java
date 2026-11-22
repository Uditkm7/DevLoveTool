package com.developer.love.tool.core;

public final class AppConstants {
    private AppConstants() {}

    public static final String TAG = "DevLoveTool";
    
    // Intents
    public static final String EXTRA_PACKAGE_NAME = "extra_package_name";
    public static final String EXTRA_KEYSTORE_PATH = "extra_keystore_path";
    public static final String EXTRA_APK_PATH = "extra_apk_path";

    // Formats
    public static final String FORMAT_PKCS12 = "PKCS12";
    public static final String FORMAT_JKS = "JKS";

    // Filter & Sort
    public static final int FILTER_USER_ONLY = 0;
    public static final int FILTER_ALL = 1;

    public static final int SORT_ALPHA_ASC = 0;
    public static final int SORT_ALPHA_DESC = 1;
    public static final int SORT_SIZE_DESC = 2;
    public static final int SORT_RECENT_INSTALLED = 3;
}
