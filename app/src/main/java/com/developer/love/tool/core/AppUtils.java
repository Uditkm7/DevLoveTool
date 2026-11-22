package com.developer.love.tool.core;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.widget.Toast;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public final class AppUtils {
    private AppUtils() {}

    public static String formatFileSize(long bytes) {
        if (bytes <= 0) return "0 B";
        final String[] units = new String[]{"B", "KB", "MB", "GB", "TB"};
        int digitGroups = (int) (Math.log10(bytes) / Math.log10(1024));
        if (digitGroups >= units.length) digitGroups = units.length - 1;
        return String.format(Locale.US, "%.2f %s", bytes / Math.pow(1024, digitGroups), units[digitGroups]);
    }

    public static String formatDate(long timestamp) {
        if (timestamp <= 0) return "Unknown";
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
        return sdf.format(new Date(timestamp));
    }

    public static String bytesToHexFormatted(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String getFingerprint(byte[] certBytes, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(certBytes);
            return bytesToHexFormatted(digest);
        } catch (NoSuchAlgorithmException e) {
            return "Unavailable (" + algorithm + ")";
        }
    }

    public static String toBase64(byte[] data) {
        if (data == null) return "";
        char[] tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
        StringBuilder sb = new StringBuilder(((data.length + 2) / 3) * 4);
        int i = 0;
        while (i < data.length) {
            int b0 = data[i++] & 0xFF;
            int b1 = i < data.length ? data[i++] & 0xFF : -1;
            int b2 = i < data.length ? data[i++] & 0xFF : -1;

            sb.append(tbl[b0 >> 2]);
            if (b1 != -1) {
                sb.append(tbl[((b0 & 0x03) << 4) | (b1 >> 4)]);
                if (b2 != -1) {
                    sb.append(tbl[((b1 & 0x0F) << 2) | (b2 >> 6)]);
                    sb.append(tbl[b2 & 0x3F]);
                } else {
                    sb.append(tbl[(b1 & 0x0F) << 2]);
                    sb.append('=');
                }
            } else {
                sb.append(tbl[(b0 & 0x03) << 4]);
                sb.append("==");
            }
        }
        return sb.toString();
    }

    public static void copyToClipboard(Context context, String label, String text) {
        ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            ClipData clip = ClipData.newPlainText(label, text);
            clipboard.setPrimaryClip(clip);
            Toast.makeText(context, label + " copied to clipboard", Toast.LENGTH_SHORT).show();
        }
    }
}
