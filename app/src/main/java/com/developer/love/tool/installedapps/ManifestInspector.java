package com.developer.love.tool.installedapps;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.os.Build;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ManifestInspector {

    public static class PermissionItem {
        public String name;
        public boolean isGranted;
        public String description;

        public PermissionItem(String name, boolean isGranted, String description) {
            this.name = name;
            this.isGranted = isGranted;
            this.description = description;
        }
    }

    public static class ComponentItem {
        public String name;
        public boolean isExported;

        public ComponentItem(String name, boolean isExported) {
            this.name = name;
            this.isExported = isExported;
        }
    }

    public static class ManifestDetails {
        public List<PermissionItem> permissions = new ArrayList<>();
        public List<ComponentItem> activities = new ArrayList<>();
        public List<ComponentItem> services = new ArrayList<>();
        public List<ComponentItem> receivers = new ArrayList<>();
        public List<ComponentItem> providers = new ArrayList<>();
        public String errorMessage;
    }

    public static ManifestDetails inspect(Context context, String packageName) {
        ManifestDetails details = new ManifestDetails();
        PackageManager pm = context.getPackageManager();

        try {
            int flags = PackageManager.GET_PERMISSIONS |
                    PackageManager.GET_ACTIVITIES |
                    PackageManager.GET_SERVICES |
                    PackageManager.GET_RECEIVERS |
                    PackageManager.GET_PROVIDERS;

            PackageInfo pi = pm.getPackageInfo(packageName, flags);

            // Permissions
            if (pi.requestedPermissions != null) {
                int[] reqFlags = pi.requestedPermissionsFlags;
                for (int i = 0; i < pi.requestedPermissions.length; i++) {
                    String permName = pi.requestedPermissions[i];
                    boolean granted = false;
                    if (reqFlags != null && i < reqFlags.length) {
                        granted = (reqFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0;
                    }

                    String desc = "";
                    try {
                        PermissionInfo pInfo = pm.getPermissionInfo(permName, 0);
                        CharSequence loadDesc = pInfo.loadDescription(pm);
                        if (loadDesc != null) {
                            desc = loadDesc.toString();
                        }
                    } catch (Exception ignored) {}

                    details.permissions.add(new PermissionItem(permName, granted, desc));
                }
            }

            // Activities
            if (pi.activities != null) {
                for (ActivityInfo a : pi.activities) {
                    details.activities.add(new ComponentItem(a.name, a.exported));
                }
            }

            // Services
            if (pi.services != null) {
                for (ServiceInfo s : pi.services) {
                    details.services.add(new ComponentItem(s.name, s.exported));
                }
            }

            // Receivers
            if (pi.receivers != null) {
                for (ActivityInfo r : pi.receivers) {
                    details.receivers.add(new ComponentItem(r.name, r.exported));
                }
            }

            // Providers
            if (pi.providers != null) {
                for (ProviderInfo p : pi.providers) {
                    details.providers.add(new ComponentItem(p.name, p.exported));
                }
            }

        } catch (Exception e) {
            details.errorMessage = "Manifest parsing error: " + e.getMessage();
        }

        return details;
    }
}
