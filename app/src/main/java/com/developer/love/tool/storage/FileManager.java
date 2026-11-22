package com.developer.love.tool.storage;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import androidx.core.content.FileProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public final class FileManager {
    private FileManager() {}

    public static File getKeystoresDir(Context context) {
        File dir = context.getExternalFilesDir("keystores");
        if (dir == null) {
            dir = new File(context.getFilesDir(), "keystores");
        }
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getExportsDir(Context context) {
        File dir = context.getExternalFilesDir("exports");
        if (dir == null) {
            dir = new File(context.getFilesDir(), "exports");
        }
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getTempDir(Context context) {
        File dir = new File(context.getCacheDir(), "devtool_temp");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static void clearTempDir(Context context) {
        File dir = new File(context.getCacheDir(), "devtool_temp");
        if (dir.exists() && dir.isDirectory()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File f : files) {
                    f.delete();
                }
            }
        }
    }

    public static String getFileName(Context context, Uri uri) {
        String result = null;
        if (uri.getScheme() != null && uri.getScheme().equals("content")) {
            try (Cursor cursor = context.getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (nameIndex != -1) {
                        result = cursor.getString(nameIndex);
                    }
                }
            } catch (Exception ignored) {}
        }
        if (result == null) {
            result = uri.getPath();
            if (result != null) {
                int cut = result.lastIndexOf('/');
                if (cut != -1) {
                    result = result.substring(cut + 1);
                }
            }
        }
        return (result != null && !result.isEmpty()) ? result : "file.bin";
    }

    public static File copyUriToFile(Context context, Uri uri, File destinationFile) throws IOException {
        try (InputStream in = context.getContentResolver().openInputStream(uri);
             OutputStream out = new FileOutputStream(destinationFile)) {
            if (in == null) {
                throw new IOException("Unable to open input stream for " + uri);
            }
            byte[] buffer = new byte[16384];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            out.flush();
        }
        return destinationFile;
    }

    public static void copyFileToUri(Context context, File sourceFile, Uri destinationUri) throws IOException {
        if (sourceFile == null || !sourceFile.exists()) {
            throw new IOException("Source file does not exist.");
        }
        try (InputStream in = new FileInputStream(sourceFile);
             OutputStream out = context.getContentResolver().openOutputStream(destinationUri)) {
            if (out == null) {
                throw new IOException("Unable to open output stream for selected folder.");
            }
            byte[] buffer = new byte[16384];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            out.flush();
        }
    }

    public static void copyFile(File source, File destination) throws IOException {
        try (InputStream in = new FileInputStream(source);
             OutputStream out = new FileOutputStream(destination)) {
            byte[] buffer = new byte[16384];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            out.flush();
        }
    }

    public static void shareFile(Context context, File file, String mimeType) {
        if (file == null || !file.exists()) return;
        Uri uri = FileProvider.getUriForFile(context, context.getPackageName() + ".fileprovider", file);
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType(mimeType);
        intent.putExtra(Intent.EXTRA_STREAM, uri);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        context.startActivity(Intent.createChooser(intent, "Share " + file.getName()));
    }

    public static List<File> listKeystoreFiles(Context context) {
        List<File> list = new ArrayList<>();
        File dir = getKeystoresDir(context);
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                String name = f.getName().toLowerCase();
                if (f.isFile() && (name.endsWith(".jks") || name.endsWith(".p12") || name.endsWith(".keystore") || name.endsWith(".bks"))) {
                    list.add(f);
                }
            }
        }
        return list;
    }
}
