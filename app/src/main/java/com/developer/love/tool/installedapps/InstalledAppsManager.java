package com.developer.love.tool.installedapps;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.LruCache;

import com.developer.love.tool.core.AppConstants;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class InstalledAppsManager {

    public interface OnAppsLoadedListener {
        void onAppsLoaded(List<AppInfoModel> apps);
        void onError(String message);
    }

    private static final String PREF_CACHE = "devlovetool_apps_cache";
    private static final String KEY_CACHED_JSON = "cached_apps_v1";

    private static volatile List<AppInfoModel> sMemoryCache = null;
    private static volatile boolean sHasScannedThisSession = false;
    private static final LruCache<String, Drawable> sIconCache = new LruCache<>(180);

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    public static boolean hasScannedThisSession() {
        return sHasScannedThisSession;
    }

    public static Drawable getCachedIcon(String packageName) {
        if (packageName == null) return null;
        return sIconCache.get(packageName);
    }

    public static void putCachedIcon(String packageName, Drawable icon) {
        if (packageName != null && icon != null) {
            sIconCache.put(packageName, icon);
        }
    }

    /**
     * Returns immediately from RAM cache or lightweight SharedPreferences snapshot
     * so the Installed Apps screen and APK Picker never start empty with a spinner.
     */
    public static List<AppInfoModel> getCachedApps(Context context) {
        if (sMemoryCache != null && !sMemoryCache.isEmpty()) {
            return new ArrayList<>(sMemoryCache);
        }
        if (context == null) return new ArrayList<>();

        List<AppInfoModel> diskList = loadSnapshotFromPrefs(context.getApplicationContext());
        if (!diskList.isEmpty()) {
            sMemoryCache = diskList;
        }
        return new ArrayList<>(diskList);
    }

    public void loadAppsAsync(Context context, OnAppsLoadedListener listener) {
        final Context appContext = context.getApplicationContext();
        executor.execute(() -> {
            try {
                PackageManager pm = appContext.getPackageManager();
                List<PackageInfo> installedPackages = pm.getInstalledPackages(0);
                List<AppInfoModel> models = new ArrayList<>(installedPackages.size());

                for (PackageInfo pi : installedPackages) {
                    try {
                        ApplicationInfo ai = pi.applicationInfo;
                        if (ai == null) continue;

                        AppInfoModel model = new AppInfoModel();
                        model.setPackageName(pi.packageName);
                        CharSequence label = pm.getApplicationLabel(ai);
                        model.setAppName(label != null ? label.toString() : pi.packageName);
                        model.setVersionName(pi.versionName != null ? pi.versionName : "N/A");

                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            model.setVersionCode(pi.getLongVersionCode());
                        } else {
                            @SuppressWarnings("deprecation")
                            long vCode = pi.versionCode;
                            model.setVersionCode(vCode);
                        }

                        model.setSystemApp((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
                        // Reuse already-cached icon if present; otherwise adapter lazy-loads visible icons on demand
                        Drawable existingIcon = sIconCache.get(pi.packageName);
                        if (existingIcon != null) {
                            model.setIcon(existingIcon);
                        }
                        model.setFirstInstallTime(pi.firstInstallTime);
                        model.setLastUpdateTime(pi.lastUpdateTime);
                        model.setSourceDir(ai.sourceDir);

                        if (ai.sourceDir != null) {
                            File apkFile = new File(ai.sourceDir);
                            if (apkFile.exists()) {
                                model.setAppSize(apkFile.length());
                            }
                        }

                        model.setTargetSdk(ai.targetSdkVersion);
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                            model.setMinSdk(ai.minSdkVersion);
                        } else {
                            model.setMinSdk(23);
                        }

                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                            model.setCompileSdk(ai.compileSdkVersion);
                        }

                        models.add(model);
                    } catch (Exception ignored) {}
                }

                sMemoryCache = new ArrayList<>(models);
                sHasScannedThisSession = true;
                saveSnapshotToPrefs(appContext, models);

                if (listener != null) {
                    listener.onAppsLoaded(models);
                }
            } catch (Exception e) {
                if (listener != null) {
                    listener.onError(e.getMessage());
                }
            }
        });
    }

    private static void saveSnapshotToPrefs(Context context, List<AppInfoModel> models) {
        try {
            JSONArray array = new JSONArray();
            for (AppInfoModel m : models) {
                JSONObject obj = new JSONObject();
                obj.put("n", m.getAppName());
                obj.put("p", m.getPackageName());
                obj.put("vn", m.getVersionName());
                obj.put("vc", m.getVersionCode());
                obj.put("s", m.getAppSize());
                obj.put("sys", m.isSystemApp());
                obj.put("fi", m.getFirstInstallTime());
                obj.put("lu", m.getLastUpdateTime());
                if (m.getSourceDir() != null) {
                    obj.put("sd", m.getSourceDir());
                }
                array.put(obj);
            }
            SharedPreferences sp = context.getSharedPreferences(PREF_CACHE, Context.MODE_PRIVATE);
            sp.edit().putString(KEY_CACHED_JSON, array.toString()).apply();
        } catch (Exception ignored) {}
    }

    private static List<AppInfoModel> loadSnapshotFromPrefs(Context context) {
        List<AppInfoModel> list = new ArrayList<>();
        try {
            SharedPreferences sp = context.getSharedPreferences(PREF_CACHE, Context.MODE_PRIVATE);
            String json = sp.getString(KEY_CACHED_JSON, null);
            if (json == null || json.isEmpty()) return list;

            JSONArray array = new JSONArray(json);
            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                AppInfoModel m = new AppInfoModel();
                m.setAppName(obj.optString("n", ""));
                m.setPackageName(obj.optString("p", ""));
                m.setVersionName(obj.optString("vn", "N/A"));
                m.setVersionCode(obj.optLong("vc", 0));
                m.setAppSize(obj.optLong("s", 0));
                m.setSystemApp(obj.optBoolean("sys", false));
                m.setFirstInstallTime(obj.optLong("fi", 0));
                m.setLastUpdateTime(obj.optLong("lu", 0));
                m.setSourceDir(obj.optString("sd", null));
                Drawable cachedIcon = sIconCache.get(m.getPackageName());
                if (cachedIcon != null) {
                    m.setIcon(cachedIcon);
                }
                list.add(m);
            }
        } catch (Exception ignored) {}
        return list;
    }

    public static List<AppInfoModel> filterAndSort(List<AppInfoModel> fullList,
                                                   String searchQuery,
                                                   int filterMode,
                                                   int sortMode) {
        if (fullList == null) return new ArrayList<>();
        List<AppInfoModel> result = new ArrayList<>();
        String query = searchQuery != null ? searchQuery.trim().toLowerCase() : "";

        for (AppInfoModel app : fullList) {
            // Filter user vs system
            if (filterMode == AppConstants.FILTER_USER_ONLY && app.isSystemApp()) {
                continue;
            }

            // Search query
            if (!query.isEmpty()) {
                boolean matchesName = app.getAppName().toLowerCase().contains(query);
                boolean matchesPkg = app.getPackageName().toLowerCase().contains(query);
                if (!matchesName && !matchesPkg) {
                    continue;
                }
            }

            result.add(app);
        }

        // Sorting
        Collections.sort(result, (a, b) -> {
            if (sortMode == AppConstants.SORT_RECENT_INSTALLED) {
                long timeA = Math.max(a.getLastUpdateTime(), a.getFirstInstallTime());
                long timeB = Math.max(b.getLastUpdateTime(), b.getFirstInstallTime());
                int cmp = Long.compare(timeB, timeA);
                if (cmp != 0) return cmp;
                return a.getAppName().compareToIgnoreCase(b.getAppName());
            } else if (sortMode == AppConstants.SORT_ALPHA_DESC) {
                return b.getAppName().compareToIgnoreCase(a.getAppName());
            } else if (sortMode == AppConstants.SORT_SIZE_DESC) {
                return Long.compare(b.getAppSize(), a.getAppSize());
            } else {
                // SORT_ALPHA_ASC
                return a.getAppName().compareToIgnoreCase(b.getAppName());
            }
        });

        return result;
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
