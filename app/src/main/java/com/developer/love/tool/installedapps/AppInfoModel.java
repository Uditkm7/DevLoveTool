package com.developer.love.tool.installedapps;

import android.graphics.drawable.Drawable;

public class AppInfoModel {
    private String appName;
    private String packageName;
    private String versionName;
    private long versionCode;
    private long appSize;
    private boolean isSystemApp;
    private Drawable icon;
    private long firstInstallTime;
    private long lastUpdateTime;
    private String installerPackage;
    private String sourceDir;
    private int minSdk;
    private int targetSdk;
    private Integer compileSdk;

    public AppInfoModel() {}

    public String getAppName() {
        return appName != null ? appName : packageName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getVersionName() {
        return versionName != null ? versionName : "N/A";
    }

    public void setVersionName(String versionName) {
        this.versionName = versionName;
    }

    public long getVersionCode() {
        return versionCode;
    }

    public void setVersionCode(long versionCode) {
        this.versionCode = versionCode;
    }

    public long getAppSize() {
        return appSize;
    }

    public void setAppSize(long appSize) {
        this.appSize = appSize;
    }

    public boolean isSystemApp() {
        return isSystemApp;
    }

    public void setSystemApp(boolean systemApp) {
        isSystemApp = systemApp;
    }

    public Drawable getIcon() {
        return icon;
    }

    public void setIcon(Drawable icon) {
        this.icon = icon;
    }

    public long getFirstInstallTime() {
        return firstInstallTime;
    }

    public void setFirstInstallTime(long firstInstallTime) {
        this.firstInstallTime = firstInstallTime;
    }

    public long getLastUpdateTime() {
        return lastUpdateTime;
    }

    public void setLastUpdateTime(long lastUpdateTime) {
        this.lastUpdateTime = lastUpdateTime;
    }

    public String getInstallerPackage() {
        return installerPackage != null ? installerPackage : "Direct Install / Unknown";
    }

    public void setInstallerPackage(String installerPackage) {
        this.installerPackage = installerPackage;
    }

    public String getSourceDir() {
        return sourceDir != null ? sourceDir : "";
    }

    public void setSourceDir(String sourceDir) {
        this.sourceDir = sourceDir;
    }

    public int getMinSdk() {
        return minSdk;
    }

    public void setMinSdk(int minSdk) {
        this.minSdk = minSdk;
    }

    public int getTargetSdk() {
        return targetSdk;
    }

    public void setTargetSdk(int targetSdk) {
        this.targetSdk = targetSdk;
    }

    public Integer getCompileSdk() {
        return compileSdk;
    }

    public void setCompileSdk(Integer compileSdk) {
        this.compileSdk = compileSdk;
    }
}
