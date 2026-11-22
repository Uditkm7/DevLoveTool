package com.developer.love.tool.storage;

import android.content.Context;
import android.os.Environment;
import android.os.StatFs;

import java.io.File;

public final class StorageHelper {
    private StorageHelper() {}

    public static boolean hasEnoughStorage(File targetDir, long requiredBytes) {
        try {
            StatFs stat = new StatFs(targetDir.getPath());
            long availableBytes = stat.getAvailableBytes();
            return availableBytes > (requiredBytes + 10 * 1024 * 1024); // buffer 10MB
        } catch (Exception e) {
            return true; // Assume enough if stat fails
        }
    }

    public static long getAvailableStorage(File targetDir) {
        try {
            StatFs stat = new StatFs(targetDir.getPath());
            return stat.getAvailableBytes();
        } catch (Exception e) {
            return 0;
        }
    }
}
